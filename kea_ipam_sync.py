
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# kea_ipam_sync.py — Patch 4
# - Valida a estrutura da tabela `hosts` (SHOW COLUMNS) antes de alterar dados
# - De-duplica por MAC antes de gravar (último prevalece no ciclo)
# - Upsert 3 etapas: UPDATE por MAC -> UPDATE por (subnet_id+IP) trocando MAC -> INSERT ... ON DUPLICATE KEY UPDATE
# - Remove automaticamente do KEA o que não está mais no phpIPAM (flag --skip-delete para preservar)
# - Ignora endereços marcados como dinâmicos no phpIPAM (type=0/dhcp)
# - Reload opcional do Kea Control Agent (apenas se RELOAD_AFTER_DB=true e KEA_URL setado)
# - Logs claros: OK / WARN / ERRO / DEBUG
# - Compatível com phpIPAM API (endereços por sub-rede), tolerante a variações de campos custom
# - Sem dependências não padrão além de requests e PyMySQL

import os
import sys
import json
import time
import argparse
import ipaddress
from typing import Any, Dict, List, Optional, Tuple, Set

try:
    import requests
except Exception as e:
    print("[ERRO] Dependência 'requests' não instalada. Instale com: pip install requests", file=sys.stderr)
    raise

try:
    import pymysql
except Exception as e:
    print("[ERRO] Dependência 'PyMySQL' não instalada. Instale com: pip install PyMySQL", file=sys.stderr)
    raise


# ---------------------------
# Logging helpers
# ---------------------------
def _debug(msg: str) -> None:
    if os.getenv("DEBUG", "false").lower() in ("1", "true", "yes", "on"):
        print(f"[DEBUG] {msg}")

def _info(msg: str) -> None:
    print(f"OK   {msg}")

def _warn(msg: str) -> None:
    print(f"[WARN] {msg}")

def _err(msg: str) -> None:
    print(f"ERRO {msg}")


# ---------------------------
# .env loader (leve, sem python-dotenv)
# ---------------------------
def load_env(path: str) -> None:
    if not os.path.isfile(path):
        _warn(f".env não encontrado em {path} (seguindo com variáveis de ambiente já carregadas)")
        return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            # remove aspas
            v = v.strip().strip("'").strip('"')
            os.environ.setdefault(k.strip(), v)


# ---------------------------
# Utilidades
# ---------------------------
def mac_to_bin(mac: str) -> bytes:
    # Remove separadores e converte para bytes
    s = mac.replace(":", "").replace("-", "").lower()
    return bytes.fromhex(s)

def ip_to_str(v: Any) -> Optional[str]:
    """Aceita '10.0.0.1', inteiro decimal ou dict, devolve string IPv4"""
    if v is None:
        return None
    if isinstance(v, str):
        if v.count(".") == 3:
            return v
        # às vezes phpIPAM manda 'ip' como string decimal
        try:
            dec = int(v)
            return str(ipaddress.IPv4Address(dec))
        except Exception:
            return None
    if isinstance(v, int):
        try:
            return str(ipaddress.IPv4Address(v))
        except Exception:
            return None
    if isinstance(v, dict):
        # tolerância a outros formatos
        for k in ("ip", "address", "addr"):
            if k in v:
                return ip_to_str(v[k])
    return None

def extract_bool(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    return s in ("1", "true", "yes", "y", "sim")

def pick_first(d: Dict[str, Any], keys: List[str]) -> Optional[Any]:
    for k in keys:
        if k in d and d[k] not in (None, "", []):
            return d[k]
    return None


# ---------------------------
# phpIPAM API
# ---------------------------
def ipam_get_addresses(base: str, token: str, subnet_id: str) -> Tuple[int, Optional[List[Dict[str, Any]]]]:
    """GET /subnets/{id}/addresses/"""
    url = f"{base.rstrip('/')}/subnets/{subnet_id}/addresses/"
    headers = {"token": token}
    try:
        resp = requests.get(url, headers=headers, timeout=30, verify=False)
        if resp.status_code == 404:
            _warn(f"API retornou 404 para /subnets/{subnet_id}/addresses/ — ignorando e seguindo.")
            return (0, None)
        resp.raise_for_status()
        data = resp.json()
        # phpIPAM costuma devolver {'code': 200, 'success': True, 'data': [...]}
        if isinstance(data, dict) and "data" in data:
            return (0, data.get("data") or [])
        if isinstance(data, list):
            return (0, data)
        # fallback
        return (0, [])
    except requests.RequestException as e:
        _err(f"Falha na chamada IPAM: {e}")
        return (-1, None)


def build_items_from_ipam(raw_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normaliza os itens vindos do IPAM para um formato interno simples."""
    items: List[Dict[str, Any]] = []
    for row in raw_list or []:
        # Sinalizador custom para reservar no Kea
        reserve = False
        for key in ("custom_kea_reserve", "kea_reserve", "custom_reserva_kea", "reserve_kea"):
            if key in row and extract_bool(row[key]):
                reserve = True
                break
        if not reserve:
            continue

        # IP
        ip = pick_first(row, ["ip", "ip_addr", "address", "addr"])
        ip_s = ip_to_str(ip)
        if not ip_s:
            _warn(f"Item sem IP válido: {row}")
            continue

        # Tipo do endereço: ignora registros claramente dinâmicos
        tipo_val = pick_first(row, ["type", "address_type", "state"])
        if tipo_val is not None:
            tipo_str = str(tipo_val).strip().lower()
            if tipo_str in {"0", "dynamic", "dhcp"}:
                _debug(f"Ignorado {ip_s}: tipo '{tipo_str}' não é estático")
                continue

        # MAC
        mac = pick_first(row, ["mac", "mac_address", "mac_addr", "hwaddr", "hw_address"])
        if not mac:
            _warn(f"Pulado: {ip_s} sem MAC")
            continue

        # Hostname
        hostname = pick_first(row, ["hostname", "hostname_fqdn", "dns_name", "name", "description"])

        items.append({"ip": ip_s, "mac": str(mac).lower(), "hostname": hostname})
    return items


# ---------------------------
# Banco de dados KEA (hosts)
# ---------------------------
def db_connect():
    host = os.getenv("DB_HOST", "localhost")
    port = int(os.getenv("DB_PORT", "3306"))
    user = os.getenv("DB_USER", "kea")
    pwd  = os.getenv("DB_PASSWORD", "")
    name = os.getenv("DB_NAME", "kea")
    conn = pymysql.connect(
        host=host, port=port, user=user, password=pwd, database=name,
        autocommit=True, charset="utf8mb4", cursorclass=pymysql.cursors.Cursor
    )
    return conn


REQUIRED_HOST_COLUMNS: Dict[str, Tuple[str, ...]] = {
    "dhcp_identifier": ("varbinary",),
    "dhcp_identifier_type": ("tinyint",),
    "dhcp4_subnet_id": ("int",),
    "ipv4_address": ("int",),
    "hostname": ("varchar", "text"),
}

OPTIONAL_HOST_COLUMNS: Dict[str, Tuple[str, ...]] = {
    "host_id": ("int",),
    "dhcp6_subnet_id": ("int",),
    "dhcp4_client_classes": ("varchar", "text"),
    "dhcp6_client_classes": ("varchar", "text"),
    "dhcp4_next_server": ("int",),
    "dhcp4_server_hostname": ("varchar",),
    "dhcp4_boot_file_name": ("varchar",),
    "user_context": ("text",),
    "auth_key": ("varchar",),
}


def db_validate_hosts_schema(conn) -> bool:
    """Valida se a tabela `hosts` possui as colunas usadas pelo sincronizador."""
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cur:
            cur.execute("SHOW COLUMNS FROM hosts")
            rows = cur.fetchall()
    except Exception as exc:
        _err(f"Falha ao inspecionar a tabela hosts: {exc}")
        return False

    columns = {row["Field"]: row for row in rows}

    missing_required = [col for col in REQUIRED_HOST_COLUMNS if col not in columns]
    if missing_required:
        _err(
            "Tabela hosts não possui as colunas obrigatórias: "
            + ", ".join(sorted(missing_required))
        )
        return False

    for col, expected_prefixes in REQUIRED_HOST_COLUMNS.items():
        detected_type = str(columns[col]["Type"]).lower()
        if not any(detected_type.startswith(prefix) for prefix in expected_prefixes):
            _warn(
                f"Coluna '{col}' com tipo '{detected_type}' — esperado prefixo "
                f"{', '.join(expected_prefixes)}"
            )

    for col, expected_prefixes in OPTIONAL_HOST_COLUMNS.items():
        if col not in columns:
            _debug(f"Coluna opcional '{col}' não encontrada na tabela hosts")
            continue
        detected_type = str(columns[col]["Type"]).lower()
        if not any(detected_type.startswith(prefix) for prefix in expected_prefixes):
            _debug(
                f"Coluna opcional '{col}' com tipo '{detected_type}' (esperado iniciar com "
                f"{', '.join(expected_prefixes)})"
            )

    _debug(
        "Colunas detectadas na tabela hosts: "
        + ", ".join(f"{row['Field']}:{row['Type']}" for row in rows)
    )
    return True


def db_upsert_host(conn, mac: str, ip: str, subnet_id: int, hostname: Optional[str], dry_run: bool=False) -> Tuple[int, str]:
    mac_bin = mac_to_bin(mac)

    sql_upd_by_mac = """
        UPDATE hosts
           SET ipv4_address = INET_ATON(%s),
               hostname = %s,
               dhcp4_subnet_id = %s
         WHERE dhcp_identifier = %s
           AND dhcp_identifier_type = 0
    """

    # Toma posse de uma linha existente pelo IP (mesma sub-rede), trocando o MAC
    sql_upd_by_ip = """
        UPDATE hosts
           SET dhcp_identifier = %s,
               hostname = %s
         WHERE dhcp_identifier_type = 0
           AND dhcp4_subnet_id = %s
           AND ipv4_address = INET_ATON(%s)
    """

    # Insere, mas se bater numa unique (ex.: key_dhcp4_identifier_subnet_id), atualiza
    sql_ins_ondup = """
        INSERT INTO hosts
            (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname)
        VALUES
            (%s, 0, %s, INET_ATON(%s), %s)
        ON DUPLICATE KEY UPDATE
            ipv4_address = VALUES(ipv4_address),
            hostname     = VALUES(hostname),
            dhcp4_subnet_id = VALUES(dhcp4_subnet_id)
    """

    if dry_run:
        _debug(f"DRY-RUN DB upsert: mac={mac}, ip={ip}, host={hostname}, subnet_id={subnet_id}")
        return (0, "dry-run")

    try:
        with conn.cursor() as cur:
            # 1) UPDATE por MAC
            cur.execute(sql_upd_by_mac, (ip, hostname, subnet_id, mac_bin))
            if cur.rowcount > 0:
                return (0, "upsert ok")

            # 2) UPDATE por (subnet_id + IP) trocando o MAC
            cur.execute(sql_upd_by_ip, (mac_bin, hostname, subnet_id, ip))
            if cur.rowcount > 0:
                return (0, "upsert ok")

            # 3) INSERT ... ON DUPLICATE KEY UPDATE
            cur.execute(sql_ins_ondup, (mac_bin, subnet_id, ip, hostname))
            return (0, "upsert ok")
    except Exception as e:
        return (-1, f"erro DB: {e}")


def db_delete_host(conn, subnet_id: int, ip: str, dry_run: bool=False) -> Tuple[int, str]:
    sql = """
        DELETE FROM hosts
         WHERE dhcp4_subnet_id = %s
           AND ipv4_address = INET_ATON(%s)
           AND dhcp_identifier_type = 0
    """
    if dry_run:
        _debug(f"DRY-RUN DB delete: subnet_id={subnet_id}, ip={ip}")
        return (0, "dry-run")
    try:
        with conn.cursor() as cur:
            cur.execute(sql, (subnet_id, ip))
            return (0, f"deleted {cur.rowcount}")
    except Exception as e:
        return (-1, f"erro DB: {e}")


def db_list_hosts_by_subnets(conn, managed_subnet_ids: List[int]) -> Dict[Tuple[int, str], Dict[str, Any]]:
    """Retorna dict {(subnet_id, ip_str): {...row...}} dos hosts do KEA nas sub-redes gerenciadas."""
    if not managed_subnet_ids:
        return {}
    placeholders = ",".join(["%s"] * len(managed_subnet_ids))
    sql = f"""
        SELECT host_id,
               HEX(dhcp_identifier) AS mac_hex,
               dhcp_identifier_type,
               dhcp4_subnet_id,
               INET_NTOA(ipv4_address) AS ip,
               hostname
          FROM hosts
         WHERE dhcp_identifier_type = 0
           AND dhcp4_subnet_id IN ({placeholders})
    """
    rows = {}
    with conn.cursor(pymysql.cursors.DictCursor) as cur:
        cur.execute(sql, managed_subnet_ids)
        for r in cur.fetchall():
            key = (int(r["dhcp4_subnet_id"]), str(r["ip"]))
            rows[key] = r
    return rows


# ---------------------------
# KEA Control Agent - reload opcional
# ---------------------------
def kea_reload_if_enabled() -> None:
    if os.getenv("RELOAD_AFTER_DB", "false").lower() not in ("1", "true", "yes", "on"):
        _debug("PULANDO reload: RELOAD_AFTER_DB=false")
        return
    base = os.getenv("KEA_URL", "").strip()
    if not base:
        _debug("PULANDO reload: KEA_URL vazio")
        return
    user = os.getenv("KEA_USER", "").strip()
    pwd  = os.getenv("KEA_PASSWORD", "").strip()

    url = f"{base.rstrip('/')}/v1/ctrl-agent/command"  # tolerante: alguns usam raiz "/"
    payload = {"command": "config-reload", "service": ["dhcp4"]}
    try:
        _debug(f"Enviando reload para {url}")
        auth = (user, pwd) if user and pwd else None
        r = requests.post(url, json=payload, auth=auth, timeout=10, verify=False)
        if r.status_code >= 400:
            _warn(f"Reload respondeu HTTP {r.status_code}: {r.text[:200]}")
        else:
            _info("reload solicitado ao Control Agent")
    except requests.RequestException as e:
        _warn(f"reload falhou (best-effort): {e}")


# ---------------------------
# CORE
# ---------------------------
def parse_mapping_env(var_name: str) -> Dict[str, int]:
    """
    Lê mapa "IPAM_SUBNETID -> KEA dhcp4_subnet_id".
    Formatos aceitos:
      - JSON: {"39":188,"40":189}
      - CSV pares: "39:188,40:189"
    """
    raw = os.getenv(var_name, "").strip()
    if not raw:
        return {}
    try:
        # Tenta JSON
        parsed = json.loads(raw)
        return {str(k): int(v) for k, v in parsed.items()}
    except Exception:
        pass
    # Tenta CSV
    mapping = {}
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            k, v = part.split(":", 1)
            mapping[str(k.strip())] = int(v.strip())
    return mapping


def sync(dry_run: bool=False, delete_missing: bool=True) -> Tuple[int, int, int]:
    base = os.getenv("IPAM_BASE", "").strip() or os.getenv("BASE", "").strip()
    token = os.getenv("IPAM_TOKEN", "").strip() or os.getenv("TOKEN", "").strip()
    if not base or not token:
        _err("Configure IPAM_BASE e IPAM_TOKEN no .env")
        return (0, 0, 1)

    # Mapa obrigatório IPAM_SUBNETID -> KEA dhcp4_subnet_id
    ipam_to_kea = parse_mapping_env("IPAM_SUBNETID_TO_ID")
    if not ipam_to_kea:
        _err("Configure IPAM_SUBNETID_TO_ID no .env (ex: {\"39\":188,\"40\":189} ou 39:188,40:189)")
        return (0, 0, 1)

    conn = db_connect()

    if not db_validate_hosts_schema(conn):
        try:
            conn.close()
        except Exception:
            pass
        return (0, 0, 1)

    _info("Estrutura da tabela 'hosts' validada.")

    updated = 0
    removed = 0
    errors = 0

    desired: Dict[Tuple[int, str], Dict[str, Optional[str]]] = {}
    processed_subnets: Set[int] = set()

    for ipam_subnet, kea_subnet_id in ipam_to_kea.items():
        rc, data = ipam_get_addresses(base, token, ipam_subnet)
        if rc != 0 or data is None:
            continue
        subnet_int = int(kea_subnet_id)
        processed_subnets.add(subnet_int)
        items = build_items_from_ipam(data)

        if not items:
            _warn(f"Sub-rede {ipam_subnet} sem IPs elegíveis (estáticos com MAC)")
            continue

        # De-duplicar por MAC: o último item prevalece
        uniq_by_mac = {}
        for it in items:
            mac = it.get("mac")
            if mac:
                uniq_by_mac[mac] = it
        items = list(uniq_by_mac.values())

        for it in items:
            ip = it["ip"]
            mac = it["mac"]
            hostname = it.get("hostname")
            # Mantém o "estado desejado" para possível GC
            desired[(subnet_int, ip)] = {"mac": mac, "hostname": hostname}

            rc, msg = db_upsert_host(conn, mac, ip, subnet_int, hostname, dry_run=dry_run)
            if rc == 0:
                updated += 1
                action = "DRY-RUN" if dry_run else ""
                prefix = f"{action} " if action else ""
                _info(f"{prefix}DB upsert {ip} ({mac}) subnet-id={kea_subnet_id} :: {msg}")
            else:
                errors += 1
                _err(f"DB {ip}: {msg}")

    # Remove do KEA o que não está mais presente no IPAM (somente para sub-redes processadas com sucesso)
    if delete_missing and processed_subnets:
        managed_ids = sorted(processed_subnets)
        current = db_list_hosts_by_subnets(conn, managed_ids)
        for key, row in current.items():
            if key not in desired:
                subnet_id, ip = key
                if dry_run:
                    removed += 1
                    _info(f"DRY-RUN remover {ip} subnet-id={subnet_id}")
                    continue
                rc, msg = db_delete_host(conn, subnet_id, ip, dry_run=False)
                if rc == 0:
                    removed += 1
                    _info(f"Removido {ip} subnet-id={subnet_id} :: {msg}")
                else:
                    errors += 1
                    _warn(f"Erro ao remover {ip} subnet-id={subnet_id} :: {msg}")
    elif delete_missing and not processed_subnets:
        _warn("Nenhuma sub-rede foi processada com sucesso; remoções não realizadas.")

    try:
        conn.close()
    except Exception:
        pass

    # Reload opcional (best-effort)
    if not dry_run and (updated > 0 or removed > 0):
        kea_reload_if_enabled()
    elif not dry_run:
        _debug("PULANDO reload: nada mudou")

    return (updated, removed, errors)


def main():
    parser = argparse.ArgumentParser(description="Sincroniza reservas do phpIPAM -> KEA MySQL (Patch 4)")
    parser.add_argument("--dry-run", action="store_true", help="Não grava no banco; apenas loga operações")
    parser.add_argument(
        "--skip-delete",
        dest="skip_delete",
        action="store_true",
        help="Não remove entradas do KEA que não estão mais no IPAM",
    )
    parser.add_argument(
        "--no-delete",
        dest="skip_delete",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--gc", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--env", default=".env", help="Caminho do arquivo .env (padrão: .env)")
    args = parser.parse_args()

    if getattr(args, "gc", False):
        _warn("Flag --gc mantida por compatibilidade: a remoção agora é padrão.")

    load_env(args.env)

    start = time.time()
    updated, removed, errors = sync(
        dry_run=args.dry_run,
        delete_missing=not getattr(args, "skip_delete", False),
    )
    elapsed = time.time() - start

    print()
    print(f"Resumo: atualizados={updated}, removidos={removed}, erros={errors}  ({elapsed:.2f}s)")


if __name__ == "__main__":
    sys.exit(main())
