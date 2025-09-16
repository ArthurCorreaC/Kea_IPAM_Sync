
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
DEFAULT_TRUE_VALUES: Set[str] = {"1", "true", "yes", "y", "sim", "on"}
DEFAULT_FALSE_VALUES: Set[str] = {"0", "false", "no", "n", "nao", "off"}
DEFAULT_CUSTOM_FIELDS: Tuple[str, ...] = (
    "custom_kea_reserve",
    "kea_reserve",
    "custom_reserva_kea",
    "reserve_kea",
)


def env_first(*names: str, default: Optional[str] = None) -> Optional[str]:
    for name in names:
        if not name:
            continue
        value = os.getenv(name)
        if value is None:
            continue
        if isinstance(value, str):
            value = value.strip()
            if not value:
                continue
        return str(value)
    return default


def parse_bool(
    value: Any,
    default: bool = False,
    true_values: Optional[Set[str]] = None,
    false_values: Optional[Set[str]] = None,
) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    if not s:
        return default
    tv = true_values or DEFAULT_TRUE_VALUES
    fv = false_values or DEFAULT_FALSE_VALUES
    if s in tv:
        return True
    if s in fv:
        return False
    return default


def csv_to_list(value: str) -> List[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def get_custom_field_names() -> List[str]:
    names: List[str] = []
    raw = os.getenv("CUSTOM_FIELD_NAME", "")
    for part in csv_to_list(raw):
        if part not in names:
            names.append(part)
    for fallback in DEFAULT_CUSTOM_FIELDS:
        if fallback not in names:
            names.append(fallback)
    return names


def get_custom_true_values() -> Set[str]:
    raw = os.getenv("CUSTOM_FIELD_TRUE_VALUES")
    if raw:
        values = {item.lower() for item in csv_to_list(raw)}
        if values:
            return values
    return set(DEFAULT_TRUE_VALUES)


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


def extract_bool(value: Any, true_values: Optional[Set[str]] = None) -> bool:
    return parse_bool(value, default=False, true_values=true_values)


def pick_first(d: Dict[str, Any], keys: List[str]) -> Optional[Any]:
    for k in keys:
        if k in d and d[k] not in (None, "", []):
            return d[k]
    return None


# ---------------------------
# phpIPAM API
# ---------------------------
def build_ipam_base_url() -> str:
    base = env_first("PHPIPAM_BASE_URL", "IPAM_BASE", "BASE", default="")
    if not base:
        return ""

    base = base.rstrip("/")
    app_id = env_first("PHPIPAM_APP_ID", "IPAM_APP_ID", "IPAM_APP")
    if app_id:
        app_id = app_id.strip("/")
        if app_id and not base.endswith(f"/{app_id}"):
            if base.endswith("/api"):
                base = f"{base}/{app_id}"
            elif "/api/" in base:
                base = f"{base}/{app_id}"
            else:
                base = f"{base}/api/{app_id}"
    return base


def ipam_login_for_token(base: str, username: str, password: str, verify_tls: bool) -> Optional[str]:
    url = f"{base.rstrip('/')}/user/"
    payload = {"username": username, "password": password}
    headers = {"Accept": "application/json"}
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=15, verify=verify_tls)
        resp.raise_for_status()
    except requests.RequestException as exc:
        _err(f"Falha ao autenticar no phpIPAM: {exc}")
        return None

    try:
        data = resp.json()
    except ValueError:
        _err("Resposta inválida ao autenticar no phpIPAM (JSON esperado).")
        return None

    if isinstance(data, dict) and data.get("success") is False:
        msg = data.get("message") or data.get("data")
        _err(f"Login no phpIPAM recusado: {msg}")
        return None

    token: Optional[str] = None
    if isinstance(data, dict):
        if isinstance(data.get("data"), dict) and data["data"].get("token"):
            token = str(data["data"]["token"])
        elif data.get("token"):
            token = str(data["token"])

    if token:
        _info("Token obtido via login no phpIPAM.")
        return token

    _err("Login no phpIPAM não retornou token válido.")
    _debug(f"Resposta completa do login: {data}")
    return None


def ipam_get_addresses(
    base: str,
    token: str,
    subnet_id: str,
    verify_tls: bool,
    extra_headers: Optional[Dict[str, str]] = None,
) -> Tuple[int, Optional[List[Dict[str, Any]]]]:
    """GET /subnets/{id}/addresses/"""
    url = f"{base.rstrip('/')}/subnets/{subnet_id}/addresses/"
    headers = {"token": token, "Accept": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    try:
        resp = requests.get(url, headers=headers, timeout=30, verify=verify_tls)
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
    reserve_fields = get_custom_field_names()
    true_values = get_custom_true_values()

    for row in raw_list or []:
        # Sinalizador custom para reservar no Kea
        reserve = False
        for key in reserve_fields:
            if key in row and extract_bool(row[key], true_values=true_values):
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
    host = env_first("KEA_DB_HOST", "DB_HOST", "MYSQL_HOST", default="localhost")
    port = int(env_first("KEA_DB_PORT", "DB_PORT", default="3306"))
    user = env_first("KEA_DB_USER", "DB_USER", "KEA_DB_USERNAME", "DB_USERNAME", default="kea")
    pwd = env_first("KEA_DB_PASS", "KEA_DB_PASSWORD", "DB_PASSWORD", "DB_PASS", default="")
    name = env_first("KEA_DB_NAME", "DB_NAME", default="kea")
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
def parse_mapping_env(*var_names: str) -> Dict[str, int]:
    """
    Lê mapa "IPAM_SUBNETID -> KEA dhcp4_subnet_id" de diferentes variáveis.
    Formatos aceitos:
      - JSON: {"39":188,"40":189}
      - CSV pares: "39:188,40:189"
    """
    for var_name in var_names:
        if not var_name:
            continue
        raw = os.getenv(var_name, "")
        if not raw:
            continue
        raw = raw.strip()
        if not raw:
            continue
        try:
            parsed = json.loads(raw)
            mapping = {str(k): int(v) for k, v in parsed.items()}
            if mapping:
                return mapping
        except Exception:
            pass
        mapping: Dict[str, int] = {}
        for part in raw.split(","):
            part = part.strip()
            if not part or ":" not in part:
                continue
            k, v = part.split(":", 1)
            try:
                mapping[str(k.strip())] = int(v.strip())
            except ValueError:
                continue
        if mapping:
            return mapping
    return {}


def sync(dry_run: bool=False, delete_missing: bool=True) -> Tuple[int, int, int]:
    base = build_ipam_base_url()
    if not base:
        _err("Configure PHPIPAM_BASE_URL (e PHPIPAM_APP_ID) no .env — veja o .env.example.")
        return (0, 0, 1)

    verify_tls = parse_bool(env_first("PHPIPAM_VERIFY_TLS", "IPAM_VERIFY_TLS"), default=False)
    if not verify_tls:
        try:
            import urllib3  # type: ignore
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # type: ignore[attr-defined]
        except Exception:
            pass

    token = env_first("PHPIPAM_TOKEN", "IPAM_TOKEN", "TOKEN")
    username = env_first("PHPIPAM_USERNAME", "IPAM_USERNAME", "PHPIPAM_USER")
    password = env_first("PHPIPAM_PASSWORD", "IPAM_PASSWORD", "PHPIPAM_PASS")

    if not token:
        if username and password:
            token = ipam_login_for_token(base, username, password, verify_tls)
            if not token:
                return (0, 0, 1)
        else:
            _err("Configure PHPIPAM_TOKEN ou PHPIPAM_USERNAME/PHPIPAM_PASSWORD no .env.")
            return (0, 0, 1)

    # Mapa obrigatório IPAM_SUBNETID -> KEA dhcp4_subnet_id
    ipam_to_kea = parse_mapping_env(
        "SUBNET_ID_MAP_JSON",
        "SUBNET_ID_MAP",
        "IPAM_SUBNETID_TO_ID",
    )
    if not ipam_to_kea:
        _err(
            "Configure SUBNET_ID_MAP_JSON (ou SUBNET_ID_MAP/IPAM_SUBNETID_TO_ID) no .env. "
            "Exemplo: {\"39\":188,\"40\":189} ou 39:188,40:189"
        )
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
        rc, data = ipam_get_addresses(base, token, str(ipam_subnet), verify_tls)
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
