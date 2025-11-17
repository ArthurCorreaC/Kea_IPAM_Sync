#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sincroniza reservas do phpIPAM diretamente com o $config do pfSense."""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import shlex
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import json_kea_ipam_sync as jk


def _encode_b64_json(data: Any) -> str:
    dumped = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    return base64.b64encode(dumped.encode("utf-8")).decode("ascii")


def _encode_b64_text(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def _compact_php(code: str) -> str:
    lines = [line.strip() for line in code.strip().splitlines() if line.strip()]
    return " ".join(lines)


def _php_reader_code(path_b64: str) -> str:
    return _compact_php(
        f"""
        @ini_set('display_errors','0');
        require_once('/etc/inc/config.inc');
        @require_once('/etc/inc/services.inc');
        $segments = json_decode(base64_decode('{path_b64}'), true);
        if (!is_array($segments)) {{
            $segments = array();
        }}
        $value = $config;
        foreach ($segments as $segment) {{
            $segment = (string)$segment;
            $is_index = ctype_digit($segment);
            if (!is_array($value)) {{
                $value = null;
                break;
            }}
            if ($is_index) {{
                $idx = intval($segment);
                if (!array_key_exists($idx, $value)) {{
                    $value = null;
                    break;
                }}
                $value = $value[$idx];
            }} else {{
                if (!array_key_exists($segment, $value)) {{
                    $value = null;
                    break;
                }}
                $value = $value[$segment];
            }}
        }}
        $payload = json_encode($value);
        if ($payload === false) {{
            $payload = 'null';
        }}
        echo base64_encode($payload);
        """
    )


def _php_writer_code(path_b64: str, payload_b64: str, note_b64: str) -> str:
    return _compact_php(
        f"""
        @ini_set('display_errors','0');
        require_once('/etc/inc/config.inc');
        @require_once('/etc/inc/services.inc');
        $segments = json_decode(base64_decode('{path_b64}'), true);
        if (!is_array($segments) || empty($segments)) {{
            echo base64_encode(json_encode(['ok'=>false,'error'=>'config path vazio']));
            exit(1);
        }}
        $data_raw = base64_decode('{payload_b64}');
        $data = json_decode($data_raw, true);
        if ($data === null && json_last_error() !== JSON_ERROR_NONE) {{
            echo base64_encode(json_encode(['ok'=>false,'error'=>'payload inválido']));
            exit(1);
        }}
        $value = $config;
        foreach ($segments as $segment) {{
            $segment = (string)$segment;
            $is_index = ctype_digit($segment);
            if (!is_array($value)) {{
                $value = null;
                break;
            }}
            if ($is_index) {{
                $idx = intval($segment);
                if (!array_key_exists($idx, $value)) {{
                    $value = null;
                    break;
                }}
                $value = $value[$idx];
            }} else {{
                if (!array_key_exists($segment, $value)) {{
                    $value = null;
                    break;
                }}
                $value = $value[$segment];
            }}
        }}
        $current_serial = serialize($value);
        $new_serial = serialize($data);
        if ($current_serial === $new_serial) {{
            echo base64_encode(json_encode(['ok'=>true,'changed'=>false]));
            exit(0);
        }}
        $ref =& $config;
        $lastIndex = count($segments) - 1;
        foreach ($segments as $idx => $segment) {{
            $segment = (string)$segment;
            $is_last = ($idx === $lastIndex);
            $is_index = ctype_digit($segment);
            if ($is_last) {{
                if (!is_array($ref)) {{
                    $ref = array();
                }}
                if ($is_index) {{
                    $ref[intval($segment)] = $data;
                }} else {{
                    $ref[$segment] = $data;
                }}
                break;
            }}
            if (!is_array($ref)) {{
                $ref = array();
            }}
            if ($is_index) {{
                $index = intval($segment);
                if (!array_key_exists($index, $ref) || !is_array($ref[$index])) {{
                    $ref[$index] = array();
                }}
                $ref =& $ref[$index];
            }} else {{
                if (!array_key_exists($segment, $ref) || !is_array($ref[$segment])) {{
                    $ref[$segment] = array();
                }}
                $ref =& $ref[$segment];
            }}
        }}
        $note = base64_decode('{note_b64}');
        if ($note === false) {{
            $note = 'Atualizado via pfsense_kea_ipam_sync.py';
        }}
        write_config($note);

        // Reload do Kea/DHCP no estilo da "Opção A"
        if (function_exists('services_kea_dhcp4_configure')) {{
            services_kea_dhcp4_configure();
        }} elseif (function_exists('services_kea_configure')) {{
            services_kea_configure();
        }} elseif (function_exists('kea_configure')) {{
            kea_configure();
        }} elseif (file_exists('/usr/local/sbin/rc.kea_dhcp4_configure')) {{
            mwexec('/usr/local/sbin/rc.kea_dhcp4_configure');
        }}

        echo base64_encode(json_encode(['ok'=>true,'changed'=>true]));
        """
    )


def _run_php(code: str, ssh_settings: Optional[Dict[str, Any]]) -> Tuple[int, str, str]:
    if ssh_settings:
        command = f"php -r {shlex.quote(code)}"
        return jk._run_ssh_command(ssh_settings, command)
    try:
        proc = subprocess.run(
            ["php", "-r", code],
            capture_output=True,
            text=True,
            check=False,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return 127, "", "php não encontrado"


def _decode_base64_json(stdout: str) -> Optional[Dict[str, Any]]:
    payload = stdout.strip()
    if not payload:
        return None
    try:
        decoded = base64.b64decode(payload)
    except Exception as exc:  # pragma: no cover - best effort
        jk._warn(f"Resposta inesperada do pfSense (base64): {exc} -> {payload[:80]}")
        return None
    try:
        data = json.loads(decoded.decode("utf-8"))
    except Exception as exc:  # pragma: no cover - best effort
        jk._warn(f"Resposta inesperada do pfSense (JSON): {exc} -> {decoded[:80]!r}")
        return None
    if isinstance(data, dict):
        return data
    return None


def fetch_pfsense_config(
    path_segments: List[str], ssh_settings: Optional[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    code = _php_reader_code(_encode_b64_json(path_segments))
    rc, stdout, stderr = _run_php(code, ssh_settings)
    if rc != 0:
        message = stderr or stdout or f"php retornou código {rc}"
        jk._warn(f"Falha ao ler configuração atual no pfSense: {message}")
        return None
    payload = stdout.strip()
    if not payload:
        return None
    try:
        decoded = base64.b64decode(payload)
        if not decoded:
            return None
        data = json.loads(decoded.decode("utf-8"))
    except Exception as exc:
        jk._warn(f"Não foi possível interpretar a configuração atual: {exc}")
        return None
    if isinstance(data, dict):
        return data
    if data is None:
        return None
    jk._warn("Configuração atual no pfSense não é um objeto JSON; usando template local.")
    return None


def push_pfsense_config(
    config: Dict[str, Any],
    path_segments: List[str],
    ssh_settings: Optional[Dict[str, Any]],
    note: str,
) -> Tuple[bool, bool]:
    payload_b64 = _encode_b64_json(config)
    path_b64 = _encode_b64_json(path_segments)
    note_b64 = _encode_b64_text(note)
    code = _php_writer_code(path_b64, payload_b64, note_b64)
    rc, stdout, stderr = _run_php(code, ssh_settings)
    if rc != 0:
        message = stderr or stdout or f"php retornou código {rc}"
        jk._err(f"Falha ao atualizar o pfSense: {message}")
        return False, False
    response = _decode_base64_json(stdout)
    if not response:
        return True, True
    if not response.get("ok", True):
        error_msg = response.get("error") or "erro desconhecido"
        jk._err(f"pfSense rejeitou atualização: {error_msg}")
        return False, False
    return True, bool(response.get("changed", False))


def get_config_path_segments() -> List[str]:
    raw = jk.env_first("PF_CONFIG_PATH", "PFSENSE_CONFIG_PATH")
    default_path = "installedpackages:kea_dhcp4:config:0:Dhcp4"
    if not raw:
        raw = default_path
    segments = [segment.strip() for segment in raw.split(":") if segment.strip()]
    if not segments:
        raise ValueError("PF_CONFIG_PATH vazio")
    return segments


def sync(dry_run: bool = False, delete_missing: bool = True) -> Tuple[int, int, int]:
    base = jk.build_ipam_base_url()
    if not base:
        jk._err("Configure PHPIPAM_BASE_URL (e PHPIPAM_APP_ID) no .env — veja o .env.example.")
        return (0, 0, 1)

    verify_tls = jk.parse_bool(jk.env_first("PHPIPAM_VERIFY_TLS", "IPAM_VERIFY_TLS"), default=False)
    if not verify_tls:
        try:  # pragma: no cover - dependência opcional
            import urllib3  # type: ignore

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # type: ignore[attr-defined]
        except Exception:
            pass

    token = jk.env_first("PHPIPAM_TOKEN", "IPAM_TOKEN", "TOKEN")
    username = jk.env_first("PHPIPAM_USERNAME", "IPAM_USERNAME", "PHPIPAM_USER")
    password = jk.env_first("PHPIPAM_PASSWORD", "IPAM_PASSWORD", "PHPIPAM_PASS")

    if not token:
        if username and password:
            token = jk.ipam_login_for_token(base, username, password, verify_tls)
            if not token:
                return (0, 0, 1)
        else:
            jk._err("Configure PHPIPAM_TOKEN ou PHPIPAM_USERNAME/PHPIPAM_PASSWORD no .env.")
            return (0, 0, 1)

    ipam_to_kea = jk.parse_mapping_env(
        "SUBNET_ID_MAP_JSON",
        "SUBNET_ID_MAP",
        "IPAM_SUBNETID_TO_ID",
    )
    if not ipam_to_kea:
        jk._err(
            "Configure SUBNET_ID_MAP_JSON (ou SUBNET_ID_MAP/IPAM_SUBNETID_TO_ID) no .env. "
            "Exemplo: {\"39\":188,\"40\":189} ou 39:188,40:189"
        )
        return (0, 0, 1)

    template_path = jk.env_first("KEA_JSON_TEMPLATE_PATH", "KEA_CONFIG_TEMPLATE_PATH")
    output_candidate = jk.env_first("KEA_JSON_OUTPUT_PATH", "KEA_CONFIG_PATH", default="")

    ssh_settings = jk._load_ssh_settings()
    path_segments = get_config_path_segments()
    remote_config = fetch_pfsense_config(path_segments, ssh_settings)
    if remote_config is not None:
        config = remote_config
    else:
        config = jk.load_base_config(template_path, output_candidate or "")

    reservations_by_subnet: Dict[int, List[Dict[str, Any]]] = {}
    processed_subnets: Set[int] = set()
    errors = 0

    for ipam_subnet, kea_subnet_id in ipam_to_kea.items():
        rc, data = jk.ipam_get_addresses(base, token, str(ipam_subnet), verify_tls)
        if rc != 0 or data is None:
            errors += 1
            continue
        subnet_int = int(kea_subnet_id)
        processed_subnets.add(subnet_int)
        items = jk.build_items_from_ipam(data)

        if not items:
            msg = f"Sub-rede {ipam_subnet} sem IPs elegíveis (estáticos com MAC/client-id)"
            if delete_missing:
                jk._warn(msg)
                reservations_by_subnet[subnet_int] = []
            else:
                jk._debug(msg + " — preservando reservas atuais")
            continue

        uniq_by_identifier: Dict[Tuple[int, str], Dict[str, Any]] = {}
        for it in items:
            identifier_hex = it.get("identifier_hex")
            identifier_type = int(it.get("identifier_type", 0))
            if identifier_hex:
                uniq_by_identifier[(identifier_type, identifier_hex)] = it
        items = list(uniq_by_identifier.values())
        try:
            items.sort(
                key=lambda it: (
                    ipaddress.IPv4Address(it["ip"]),
                    str(it.get("identifier_hex", "")),
                )
            )
        except Exception:
            items.sort(key=lambda it: it.get("ip", ""))

        reservations = [jk.reservation_from_item(it) for it in items]
        reservations_by_subnet[subnet_int] = reservations

        for it in items:
            identifier_log = it.get("log_identifier", it["identifier_hex"])
            jk._info(
                f"Reserva preparada {it['ip']} ({identifier_log}) subnet-id={kea_subnet_id}"
            )

    if not processed_subnets:
        jk._warn("Nenhuma sub-rede foi processada com sucesso; nada para escrever.")
        return (0, 0, errors if errors else 1)

    total_reservations, subnets_modified = jk.apply_reservations(
        config, reservations_by_subnet, delete_missing
    )

    if dry_run:
        jk._info(
            f"DRY-RUN: {total_reservations} reservas seriam gravadas em {subnets_modified} sub-redes"
        )
        return (total_reservations, subnets_modified, errors)

    if subnets_modified <= 0:
        jk._info("Nenhuma alteração detectada — pfSense já estava sincronizado")
        return (total_reservations, subnets_modified, errors)

    note = jk.env_first("PF_CONFIG_WRITE_NOTE", "PFSENSE_CONFIG_NOTE", default="Kea_IPAM_Sync") or "Kea_IPAM_Sync"
    success, changed = push_pfsense_config(config, path_segments, ssh_settings, note)
    if not success:
        errors += 1
        return (total_reservations, subnets_modified, errors)

    if changed:
        jk._info("Configuração do pfSense atualizada e serviço recarregado")
    else:
        jk._info("pfSense já possuía a mesma configuração — sem reload adicional")

    return (total_reservations, subnets_modified, errors)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sincroniza reservas do phpIPAM diretamente no pfSense ($config)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Apenas calcula as alterações sem atualizar o pfSense",
    )
    parser.add_argument(
        "--skip-delete",
        dest="skip_delete",
        action="store_true",
        help="Não remove reservas existentes quando o phpIPAM não retornar entradas",
    )
    parser.add_argument("--env", default=".env", help="Caminho do arquivo .env (padrão: .env)")
    args = parser.parse_args()

    jk.load_env(args.env)
    jk.setup_logging(force=True)

    start = time.time()
    total_reservations, subnets_modified, errors = sync(
        dry_run=args.dry_run,
        delete_missing=not getattr(args, "skip_delete", False),
    )
    elapsed = time.time() - start

    print()
    jk._log(
        jk.logging.INFO,
        f"Resumo: reservas={total_reservations}, sub-redes alteradas={subnets_modified}, erros={errors}  ({elapsed:.2f}s)",
    )

    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
