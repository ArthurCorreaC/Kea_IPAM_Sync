#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sincroniza reservas do phpIPAM diretamente em static-maps nativos do pfSense."""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import logging
import os
import shlex
import shutil
import subprocess
import sys
import time
import unicodedata
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

import requests
import types

try:  # pragma: no cover - dependência opcional
    import paramiko  # type: ignore
except Exception:  # pragma: no cover - fallback silencioso
    paramiko = None  # type: ignore


jk = types.SimpleNamespace()


# ---------------------------
# Logging helpers (copiados do json_kea_ipam_sync.py)
# ---------------------------
LOG_NAME = "json_kea_ipam_sync"
LOG_DIR_ENV_VAR = "KEA_IPAM_SYNC_LOG_DIR"
LOG_RETENTION_ENV_VAR = "KEA_IPAM_SYNC_LOG_RETENTION_DAYS"
DEFAULT_LOG_DIR = "logs"
DEFAULT_LOG_RETENTION_DAYS = 5

_LOGGER = logging.getLogger(LOG_NAME)
_LOGGER.setLevel(logging.DEBUG)
_LOGGER.propagate = False
_LOGGER_INITIALIZED = False
_CURRENT_LOG_DIR: Optional[str] = None
_CURRENT_RETENTION_DAYS = DEFAULT_LOG_RETENTION_DAYS
_DEBUG_ENV_NAMES = (
    "DEBUG",
    "KEA_IPAM_SYNC_DEBUG",
    "PFSENSE_IPAM_SYNC_DEBUG",
)
_DEBUG_ONE_BY_ONE_ENV_NAMES = (
    "DEBUG_ONE_A_ONE",
    "DEBUG_ONE_BY_ONE",
    "PFSENSE_DEBUG_ONE_A_ONE",
    "PFSENSE_DEBUG_ONE_BY_ONE",
    "KEA_IPAM_SYNC_DEBUG_ONE_A_ONE",
)
_DEBUG_TRUE_VALUES = {"1", "true", "yes", "y", "sim", "on"}
_DEBUG_FALSE_VALUES = {"0", "false", "no", "n", "nao", "off"}


def _cleanup_old_logs(log_dir: str, keep_days: int) -> None:
    if keep_days <= 0 or not log_dir:
        return
    cutoff = time.time() - (keep_days * 86400)
    try:
        entries = os.listdir(log_dir)
    except OSError:
        return
    for name in entries:
        if not name.startswith("json_kea_ipam_sync_") or not name.endswith(".log"):
            continue
        path = os.path.join(log_dir, name)
        if not os.path.isfile(path):
            continue
        try:
            if os.path.getmtime(path) < cutoff:
                os.remove(path)
        except OSError:
            pass


def setup_logging(force: bool = False) -> None:
    global _LOGGER_INITIALIZED, _CURRENT_LOG_DIR, _CURRENT_RETENTION_DAYS

    log_dir = os.getenv(LOG_DIR_ENV_VAR, DEFAULT_LOG_DIR).strip() or DEFAULT_LOG_DIR
    retention_raw = os.getenv(LOG_RETENTION_ENV_VAR, "").strip()
    try:
        retention_days = int(retention_raw) if retention_raw else DEFAULT_LOG_RETENTION_DAYS
    except ValueError:
        retention_days = DEFAULT_LOG_RETENTION_DAYS
    if retention_days < 0:
        retention_days = DEFAULT_LOG_RETENTION_DAYS

    if _LOGGER_INITIALIZED and not force:
        return
    if (
        _LOGGER_INITIALIZED
        and force
        and log_dir == (_CURRENT_LOG_DIR or "")
        and retention_days == _CURRENT_RETENTION_DAYS
    ):
        return

    prepared_log_dir = log_dir
    if prepared_log_dir:
        try:
            os.makedirs(prepared_log_dir, exist_ok=True)
        except OSError as exc:
            print(
                f"[WARN] Não foi possível criar diretório de logs '{prepared_log_dir}': {exc}",
                file=sys.stderr,
            )
            prepared_log_dir = ""

    if prepared_log_dir:
        _cleanup_old_logs(prepared_log_dir, retention_days)

    for handler in list(_LOGGER.handlers):
        _LOGGER.removeHandler(handler)
        try:
            handler.close()
        except Exception:
            pass

    file_handler: Optional[logging.Handler] = None
    if prepared_log_dir:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = os.path.join(prepared_log_dir, f"json_kea_ipam_sync_{timestamp}.log")
        try:
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
        except OSError as exc:
            print(
                f"[WARN] Não foi possível criar arquivo de log '{log_file}': {exc}",
                file=sys.stderr,
            )
            file_handler = None

    if file_handler:
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S")
        )
        _LOGGER.addHandler(file_handler)

    stream_handler = logging.StreamHandler(stream=sys.stdout)
    stream_handler.setLevel(logging.DEBUG)
    stream_handler.setFormatter(logging.Formatter("%(message)s"))
    _LOGGER.addHandler(stream_handler)

    _LOGGER_INITIALIZED = True
    _CURRENT_LOG_DIR = prepared_log_dir
    _CURRENT_RETENTION_DAYS = retention_days


def _ensure_logger() -> logging.Logger:
    if not _LOGGER_INITIALIZED:
        setup_logging()
    return _LOGGER


def _is_debug_enabled() -> bool:
    for name in _DEBUG_ENV_NAMES:
        value = os.getenv(name)
        if value is None:
            continue
        s = str(value).strip().lower()
        if s in _DEBUG_TRUE_VALUES:
            return True
        if s in _DEBUG_FALSE_VALUES:
            return False
    return False


def _log(level: int, message: str) -> None:
    logger = _ensure_logger()
    logger.log(level, message)


def _debug(msg: str) -> None:
    if _is_debug_enabled():
        _log(logging.DEBUG, f"[DEBUG] {msg}")


def _warn(msg: str) -> None:
    _log(logging.WARNING, f"[WARN] {msg}")


def _err(msg: str) -> None:
    _log(logging.ERROR, f"ERRO {msg}")


def _info(msg: str) -> None:
    _log(logging.INFO, f"OK {msg}")


def is_debug_enabled() -> bool:
    return _is_debug_enabled()


def is_debug_one_by_one_enabled() -> bool:
    for name in _DEBUG_ONE_BY_ONE_ENV_NAMES:
        value = os.getenv(name)
        if value is None:
            continue
        s = str(value).strip().lower()
        if s in _DEBUG_TRUE_VALUES:
            return True
        if s in _DEBUG_FALSE_VALUES:
            return False
    return False


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
    "reserva_kea",
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


HEX_DIGITS = set("0123456789abcdef")


def _clean_hex_string(value: str) -> str:
    return "".join(ch for ch in value if ch.lower() in HEX_DIGITS)


def normalize_mac(value: Any) -> Optional[str]:
    if value is None:
        return None
    cleaned = _clean_hex_string(str(value))
    if len(cleaned) != 12:
        return None
    return cleaned.lower()


def normalize_client_id(value: Any) -> Optional[str]:
    if value is None:
        return None
    cleaned = _clean_hex_string(str(value))
    if len(cleaned) < 2 or len(cleaned) % 2 != 0:
        return None
    if len(cleaned) > 64:
        return None
    return cleaned.lower()


def _group_hex_pairs(value: str) -> str:
    return ":".join(value[i : i + 2] for i in range(0, len(value), 2))


# ---------------------------
# phpIPAM helpers
# ---------------------------
def build_ipam_base_url() -> Optional[str]:
    base = env_first("PHPIPAM_BASE_URL", "IPAM_BASE_URL")
    if not base:
        return None
    base = base.rstrip("/")
    return base


def ipam_request(
    method: str,
    url: str,
    token: Optional[str],
    verify_tls: bool,
    *,
    payload: Optional[Dict[str, Any]] = None,
) -> Tuple[int, Optional[Dict[str, Any]]]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["token"] = token
    try:
        response = requests.request(
            method,
            url,
            headers=headers,
            json=payload,
            timeout=30,
            verify=verify_tls,
        )
    except requests.RequestException as exc:  # pragma: no cover - dependência externa
        _err(f"Falha na requisição ao phpIPAM: {exc}")
        return (1, None)

    if response.status_code == 401:
        _err("phpIPAM retornou 401 (token inválido ou expirado)")
        return (1, None)

    if response.status_code >= 500:
        _err(f"phpIPAM retornou erro {response.status_code}: {response.text[:200]}")
        return (1, None)

    try:
        data = response.json()
    except ValueError as exc:
        _err(f"Resposta inválida do phpIPAM (não é JSON): {exc}")
        return (1, None)

    if isinstance(data, dict) and not data.get("success", True):
        message = data.get("message", "sem mensagem")
        _err(f"phpIPAM retornou erro lógico: {message}")
        return (1, data if isinstance(data, dict) else None)

    return (0, data if isinstance(data, dict) else None)


def ipam_login_for_token(base: str, username: str, password: str, verify_tls: bool) -> Optional[str]:
    url = f"{base}/api/{env_first('PHPIPAM_APP_ID', 'IPAM_APP_ID', default='kea')}/user/" + username
    payload = {"password": password}
    rc, data = ipam_request("POST", url, token=None, verify_tls=verify_tls, payload=payload)
    if rc != 0 or not data:
        return None
    token = data.get("data")
    if isinstance(token, dict):
        token = token.get("token")
    if not token:
        _err("phpIPAM não retornou token de autenticação")
        return None
    return str(token)


def ipam_get_addresses(
    base: str,
    token: str,
    subnet_id: str,
    verify_tls: bool,
) -> Tuple[int, Optional[List[Dict[str, Any]]]]:
    url = f"{base}/api/{env_first('PHPIPAM_APP_ID', 'IPAM_APP_ID', default='kea')}/subnets/{subnet_id}/addresses/"
    rc, data = ipam_request("GET", url, token=token, verify_tls=verify_tls)
    if rc != 0 or not data:
        return (1, None)
    rows = data.get("data")
    if rows is None:
        _warn(
            f"Sub-rede {subnet_id} não possui endereços cadastrados no phpIPAM; seguindo com lista vazia"
        )
        return (0, [])
    if not isinstance(rows, list):
        _err(f"phpIPAM retornou dados inesperados para sub-rede {subnet_id}")
        return (1, None)
    return (0, rows)


def ipam_get_subnet(
    base: str,
    token: str,
    subnet_id: str,
    verify_tls: bool,
) -> Tuple[int, Optional[Dict[str, Any]]]:
    url = f"{base}/api/{env_first('PHPIPAM_APP_ID', 'IPAM_APP_ID', default='kea')}/subnets/{subnet_id}/"
    rc, data = ipam_request("GET", url, token=token, verify_tls=verify_tls)
    if rc != 0 or not data:
        return (1, None)
    subnet = data.get("data")
    if not isinstance(subnet, dict):
        _err(f"phpIPAM retornou dados inesperados ao consultar a sub-rede {subnet_id}")
        return (1, None)
    return (0, subnet)


def pick_first(row: Dict[str, Any], keys: List[str], default: Any = None) -> Any:
    for key in keys:
        if key in row:
            value = row[key]
            if value not in (None, ""):
                return value
    return default


def build_items_from_ipam(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    truthy_values = get_custom_true_values()
    flag_fields = get_custom_field_names()

    for row in rows:
        if not isinstance(row, dict):
            continue

        ip_addr = row.get("ip")
        try:
            ip = ipaddress.ip_address(str(ip_addr))
        except Exception:
            _warn(f"Ignorado endereço IP inválido no phpIPAM: {ip_addr}")
            continue
        if ip.version != 4:
            _debug(f"Ignorado {ip_addr}: apenas IPv4 é suportado")
            continue
        ip_s = str(ip)

        flag_value = None
        for field in flag_fields:
            if field in row:
                flag_value = row[field]
                break
        if flag_value is None:
            _debug(f"Ignorado {ip_s}: campo custom não encontrado")
            continue
        if str(flag_value).strip().lower() not in truthy_values:
            _debug(f"Ignorado {ip_s}: flag custom marcada como falsa")
            continue

        tipo_val = row.get("type")
        if tipo_val is not None:
            tipo_str = str(tipo_val).strip().lower()
            if tipo_str in {"0", "dynamic", "dhcp"}:
                _debug(f"Ignorado {ip_s}: tipo '{tipo_str}' não é estático")
                continue

        identifier_type = 0
        identifier_hex: Optional[str] = None

        client_id = pick_first(
            row,
            [
                "client_id",
                "custom_client_id",
                "clientid",
                "custom_clientid",
            ],
        )

        if client_id not in (None, ""):
            normalized_client_id = normalize_client_id(client_id)
            if not normalized_client_id:
                _warn(f"Pulado: {ip_s} com client-id inválido ({client_id})")
                continue
            identifier_type = 1
            identifier_hex = normalized_client_id
        else:
            mac = pick_first(row, ["mac", "mac_address", "mac_addr", "hwaddr", "hw_address"])
            normalized_mac = normalize_mac(mac)
            if not normalized_mac:
                _warn(f"Pulado: {ip_s} sem MAC válido")
                continue
            identifier_type = 0
            identifier_hex = normalized_mac

        hostname = pick_first(row, ["hostname", "hostname_fqdn", "dns_name", "name", "description"])

        items.append(
            {
                "ip": ip_s,
                "identifier_hex": identifier_hex,
                "identifier_type": identifier_type,
                "hostname": hostname,
                "log_identifier": identifier_hex and _group_hex_pairs(identifier_hex) or "",
            }
        )
    return items


# ---------------------------
# SSH helpers
# ---------------------------
def _split_extra_args(value: str) -> List[str]:
    try:
        return shlex.split(value)
    except Exception:
        return []


def _build_ssh_base(settings: Dict[str, Any]) -> str:
    user = settings.get("user")
    host = settings.get("host")
    if user:
        return f"{user}@{host}"
    return str(host)


def _ssh_common_args(settings: Dict[str, Any], for_scp: bool) -> List[str]:
    args: List[str] = []
    if not settings.get("password"):
        args.extend(["-o", "BatchMode=yes"])
    identity = settings.get("identity")
    if identity:
        args.extend(["-i", identity])
    port = settings.get("port")
    if port:
        args.extend(["-P" if for_scp else "-p", str(port)])
    known_hosts = settings.get("known_hosts")
    strict = settings.get("strict", True)
    if known_hosts:
        args.extend(["-o", f"UserKnownHostsFile={known_hosts}"])
    elif not strict:
        args.extend(
            [
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
            ]
        )
    extra_args = settings.get("extra_args") or []
    args.extend(extra_args)
    return args


def _load_ssh_settings() -> Optional[Dict[str, Any]]:
    host = env_first("PF_SSH_HOST", "PFSENSE_HOST", "PFSENSE_SSH_HOST")
    if not host:
        return None
    host = host.strip()
    if not host:
        return None
    settings: Dict[str, Any] = {"host": host}
    transport = "ssh"
    user = env_first("PF_SSH_USER", "PFSENSE_USER", "PFSENSE_SSH_USER")
    if user:
        settings["user"] = user.strip()
    port = env_first("PF_SSH_PORT", "PFSENSE_SSH_PORT")
    if port:
        try:
            settings["port"] = int(port)
        except (TypeError, ValueError):
            _warn(f"PF_SSH_PORT inválida: {port}")
    identity = env_first("PF_SSH_KEY", "PF_SSH_IDENTITY", "PFSENSE_SSH_KEY")
    if identity:
        settings["identity"] = identity.strip()
    known_hosts = env_first("PF_SSH_KNOWN_HOSTS", "PFSENSE_KNOWN_HOSTS")
    if known_hosts:
        settings["known_hosts"] = known_hosts.strip()
    strict = env_first("PF_SSH_STRICT_HOST_KEY_CHECKING", "PFSENSE_STRICT_HOST_KEY_CHECKING")
    if strict is not None:
        settings["strict"] = parse_bool(strict, default=True)
    extra = env_first("PF_SSH_EXTRA_ARGS", "PFSENSE_SSH_EXTRA_ARGS")
    if extra:
        settings["extra_args"] = _split_extra_args(extra)
    password = env_first(
        "PF_SSH_PASSWORD",
        "PFSENSE_SSH_PASSWORD",
        "PF_SSH_PASS",
        "PFSENSE_SSH_PASS",
    )
    if password:
        settings["password"] = password
        if shutil.which("sshpass"):
            transport = "sshpass"
        elif paramiko is not None:
            transport = "paramiko"
        else:
            transport = "unsupported"
    settings["_transport"] = transport
    return settings


def _wrap_ssh_with_password(
    settings: Dict[str, Any], args: List[str]
) -> Tuple[List[str], Optional[Dict[str, str]]]:
    password = settings.get("password")
    if not password or settings.get("_transport") != "sshpass":
        return args, None
    new_args = ["sshpass", "-e", *args]
    env = os.environ.copy()
    env["SSHPASS"] = password
    return new_args, env


def _paramiko_connect(settings: Dict[str, Any]) -> Tuple[Optional[Any], Optional[str]]:
    if paramiko is None:
        return None, "biblioteca paramiko não instalada"
    client = paramiko.SSHClient()
    strict = settings.get("strict", True)
    known_hosts = settings.get("known_hosts")
    try:
        client.load_system_host_keys()
    except Exception:
        pass
    if known_hosts:
        try:
            client.load_host_keys(known_hosts)
        except Exception:
            return None, "falha ao carregar known_hosts"
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            settings["host"],
            port=settings.get("port", 22),
            username=settings.get("user"),
            password=settings.get("password"),
            key_filename=settings.get("identity"),
            look_for_keys=strict,
            allow_agent=strict,
        )
        return client, None
    except Exception as exc:
        return None, str(exc)


def _paramiko_run_command(settings: Dict[str, Any], command: str) -> Tuple[int, str, str]:
    client, error = _paramiko_connect(settings)
    if client is None:
        return 127, "", error or "falha na conexão Paramiko"
    try:
        stdin, stdout, stderr = client.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()
        stdout_data = stdout.read().decode(errors="ignore").strip()
        stderr_data = stderr.read().decode(errors="ignore").strip()
        return exit_status, stdout_data, stderr_data
    except Exception as exc:
        return 127, "", str(exc)
    finally:
        client.close()


def _run_ssh_command(settings: Dict[str, Any], command: str) -> Tuple[int, str, str]:
    transport = settings.get("_transport", "ssh")
    if transport == "unsupported":
        return 127, "", "Autenticação por senha requer 'sshpass' ou biblioteca 'paramiko'"
    if transport == "paramiko":
        return _paramiko_run_command(settings, command)
    target = _build_ssh_base(settings)
    args = ["ssh", *_ssh_common_args(settings, for_scp=False), target, command]
    args, env = _wrap_ssh_with_password(settings, args)
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        missing = args[0]
        if missing == "sshpass":
            _err("Comando 'sshpass' não encontrado no PATH")
            return (127, "", "sshpass não encontrado")
        _err("Comando 'ssh' não encontrado no PATH")
        return (127, "", "ssh não encontrado")


def parse_mapping_env(*var_names: str) -> Dict[str, int]:
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


# Expor helpers em um namespace compatível com o arquivo original
jk._warn = _warn
jk._err = _err
jk._info = _info
jk._debug = _debug
jk._log = _log
jk.setup_logging = setup_logging
jk.load_env = load_env
jk.env_first = env_first
jk.parse_bool = parse_bool
jk.parse_mapping_env = parse_mapping_env
jk._load_ssh_settings = _load_ssh_settings
jk._run_ssh_command = _run_ssh_command
jk.is_debug_enabled = is_debug_enabled
jk.is_debug_one_by_one_enabled = is_debug_one_by_one_enabled
jk.build_ipam_base_url = build_ipam_base_url
jk.ipam_get_addresses = ipam_get_addresses
jk.ipam_get_subnet = ipam_get_subnet
jk.ipam_login_for_token = ipam_login_for_token
jk.build_items_from_ipam = build_items_from_ipam
jk._group_hex_pairs = _group_hex_pairs
jk.logging = logging


def _encode_b64_json(data: Any) -> str:
    dumped = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    return base64.b64encode(dumped.encode("utf-8")).decode("ascii")


def _encode_b64_text(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def _compact_php(code: str) -> str:
    lines = [line.strip() for line in code.strip().splitlines() if line.strip()]
    return " ".join(lines)


def _sanitize_hostname(hostname: str, max_length: int = 63) -> str:
    normalized = unicodedata.normalize("NFKD", hostname)
    normalized = "".join(ch for ch in normalized if unicodedata.category(ch) != "Mn")
    cleaned = "".join(ch for ch in normalized if ch.isalnum() or ch in "-._")
    cleaned = cleaned.strip("-._")
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length]
    return cleaned


def _php_reader_code(path_b64: str) -> str:
    return _compact_php(
        f"""
        @ini_set('display_errors','0');
        require_once('/etc/inc/config.inc');
        @require_once('/etc/inc/services.inc');
        $segments = json_decode(base64_decode('{path_b64}'), true);
        if (is_array($segments) == false) {{
            $segments = array();
        }}
        $value = $config;
        foreach ($segments as $segment) {{
            $segment = (string)$segment;
            $is_index = ctype_digit($segment);
            if (is_array($value) == false) {{
                $value = null;
                break;
            }}
            if ($is_index) {{
                $idx = intval($segment);
                if (array_key_exists($idx, $value) == false) {{
                    $value = null;
                    break;
                }}
                $value = $value[$idx];
            }} else {{
                if (array_key_exists($segment, $value) == false) {{
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


def _php_apply_staticmaps_code(payload_b64: str, note_b64: str) -> str:
    return _compact_php(
        f"""
        @ini_set('display_errors','0');
        require_once('/etc/inc/config.inc');
        @require_once('/etc/inc/util.inc');
        @require_once('/etc/inc/functions.inc');
        @require_once('/etc/inc/services.inc');

        $debug_mode = filter_var(
            getenv('PFSENSE_IPAM_SYNC_DEBUG') ?: getenv('KEA_IPAM_SYNC_DEBUG') ?: getenv('DEBUG'),
            FILTER_VALIDATE_BOOLEAN
        );

        if (isset($config) == false || is_array($config) == false) {{
            echo base64_encode(json_encode(['ok'=>false,'error'=>'config.xml inválido ou não carregado']));
            exit(1);
        }}

        function ensure_array_ref(&$value) {{
            if (is_array($value) == false) {{
                $value = array();
            }}
        }}

        function ensure_array_path(&$root, $path) {{
            if (is_array($root) == false) {{
                $root = array();
            }}
            $segments = explode('/', $path);
            $ref =& $root;
            foreach ($segments as $segment) {{
                if (isset($ref[$segment]) == false || is_array($ref[$segment]) == false) {{
                    $ref[$segment] = array();
                }}
                $ref =& $ref[$segment];
            }}
            return $ref;
        }}

        function normalize_staticmap_entry($entry) {{
            if (is_array($entry) == false) {{
                return null;
            }}
            $fields = array('mac','cid','ipaddr','hostname','descr');
            $normalized = array();
            foreach ($fields as $field) {{
                if (array_key_exists($field, $entry) == false) {{
                    continue;
                }}
                $value = $entry[$field];
                if ($value === null || $value === '') {{
                    continue;
                }}
                if (is_string($value)) {{
                    $value = trim($value);
                }}
                if ($field === 'mac' || $field === 'cid') {{
                    $value = strtolower($value);
                }}
                $normalized[$field] = $value;
            }}
            if (isset($normalized['ipaddr']) == false) {{
                return null;
            }}
            if (isset($normalized['mac']) == false && isset($normalized['cid']) == false) {{
                return null;
            }}
            return $normalized;
        }}

        function normalize_staticmap_entries($entries) {{
            $result = array();
            if (is_array($entries) == false) {{
                return $result;
            }}
            foreach ($entries as $entry) {{
                $normalized = normalize_staticmap_entry($entry);
                if ($normalized === null) {{
                    continue;
                }}
                $result[] = $normalized;
            }}
            return $result;
        }}

        function staticmaps_equal($current, $next) {{
            $current_v = array_values($current);
            $next_v = array_values($next);
            return serialize($current_v) === serialize($next_v);
        }}

        $payload_raw = base64_decode('{payload_b64}');
        $payload = json_decode($payload_raw, true);
        if (
            is_array($payload) == false ||
            isset($payload['ifaces']) == false ||
            is_array($payload['ifaces']) == false
        ) {{
            echo base64_encode(json_encode(['ok'=>false,'error'=>'payload inválido']));
            exit(1);
        }}
        ensure_array_ref($config);
        ensure_array_path($config, 'dhcpd');
        $changed_ifaces = array();
        foreach ($payload['ifaces'] as $iface => $data) {{
            $iface = (string)$iface;
            if ($iface === '') {{
                continue;
            }}
            $entries = array();
            if (isset($data['reservations'])) {{
                $entries = normalize_staticmap_entries($data['reservations']);
            }}
            $delete = empty($data['delete']) == false;
            if (
                isset($config['dhcpd'][$iface]) == false ||
                is_array($config['dhcpd'][$iface]) == false
            ) {{
                $config['dhcpd'][$iface] = array();
            }}
            $current = array();
            if (isset($config['dhcpd'][$iface]['staticmap']) && is_array($config['dhcpd'][$iface]['staticmap'])) {{
                $current = array_values($config['dhcpd'][$iface]['staticmap']);
            }}
            if ($delete && empty($entries)) {{
                if (empty($current) == false) {{
                    unset($config['dhcpd'][$iface]['staticmap']);
                    $changed_ifaces[] = $iface;
                }}
                continue;
            }}
            if (empty($entries)) {{
                continue;
            }}
            if (empty($current) == false && staticmaps_equal($current, $entries)) {{
                continue;
            }}
            $config['dhcpd'][$iface]['staticmap'] = $entries;
            $changed_ifaces[] = $iface;
        }}
        if (empty($changed_ifaces)) {{
            echo base64_encode(json_encode(['ok'=>true,'changed'=>false]));
            exit(0);
        }}
        $note = base64_decode('{note_b64}');
        if ($note === false) {{
            $note = 'Atualizado via pfsense_kea_ipam_sync.py';
        }}
        ensure_array_ref($config);
        ensure_array_path($config, 'notifications');
        ensure_array_path($config, 'notifications/smtp');

        try {{
            write_config($note);
        }} catch (Throwable $e) {{
            $error = 'erro ao salvar config: '.$e->getMessage();
            if ($debug_mode) {{
                $context = array(
                    'config_type' => gettype($config),
                    'notifications_type' => isset($config['notifications']) ? gettype($config['notifications']) : 'unset',
                    'smtp_type' => isset($config['notifications']['smtp']) ? gettype($config['notifications']['smtp']) : 'unset',
                    'smtp_dump' => isset($config['notifications']['smtp']) ? json_encode($config['notifications']['smtp']) : null,
                );
                $error .= ' | contexto: '.json_encode($context);
            }}
            echo base64_encode(json_encode(['ok'=>false,'error'=>$error]));
            exit(1);
        }}
        if (function_exists('services_dhcpd_configure')) {{
            services_dhcpd_configure();
        }} elseif (function_exists('dhcpd_configure')) {{
            dhcpd_configure();
        }} elseif (file_exists('/usr/local/sbin/rc.dhcpd')) {{
            mwexec('/usr/local/sbin/rc.dhcpd restart');
        }}
        echo base64_encode(json_encode(['ok'=>true,'changed'=>true,'ifaces'=>$changed_ifaces]));
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


def push_staticmaps_to_pfsense(
    staticmaps_by_iface: Dict[str, Dict[str, Any]],
    ssh_settings: Optional[Dict[str, Any]],
    note: str,
) -> Tuple[bool, bool, List[str]]:
    if not staticmaps_by_iface:
        return True, False, []
    total_reservations = sum(len(v.get("reservations", [])) for v in staticmaps_by_iface.values())

    def _send_payload(payload_ifaces: Dict[str, Dict[str, Any]]) -> Tuple[bool, bool, List[str]]:
        payload = {"ifaces": payload_ifaces}
        payload_b64 = _encode_b64_json(payload)
        note_b64 = _encode_b64_text(note)
        code = _php_apply_staticmaps_code(payload_b64, note_b64)
        if jk.is_debug_enabled():
            jk._debug(
                f"Enviando {sum(len(v.get('reservations', [])) for v in payload_ifaces.values())} reservas em {len(payload_ifaces)} interfaces para o pfSense"
            )
        rc, stdout, stderr = _run_php(code, ssh_settings)
        if jk.is_debug_enabled():
            jk._debug(
                f"PHP retornou rc={rc}, stdout='{stdout[:200]}', stderr='{stderr[:200]}'"
            )
        if rc != 0:
            message = stderr or stdout or f"php retornou código {rc}"
            jk._err(f"Falha ao atualizar o pfSense: {message}")
            return False, False, []
        response = _decode_base64_json(stdout)
        if not response:
            return True, True, list(payload_ifaces.keys())
        if not response.get("ok", True):
            error_msg = response.get("error") or "erro desconhecido"
            jk._err(f"pfSense rejeitou atualização: {error_msg}")
            return False, False, []
        changed_ifaces_inner: List[str] = []
        if response.get("changed"):
            payload_ifaces_resp = response.get("ifaces")
            if isinstance(payload_ifaces_resp, list):
                changed_ifaces_inner = [str(iface) for iface in payload_ifaces_resp]
            else:
                changed_ifaces_inner = list(payload_ifaces.keys())
        return True, bool(response.get("changed", False)), changed_ifaces_inner

    if jk.is_debug_one_by_one_enabled():
        if jk.is_debug_enabled():
            jk._debug(
                f"Modo debug_one_a_one ativo: enviando {total_reservations} reservas em lotes unitários por interface"
            )
        overall_changed = False
        changed_ifaces: Set[str] = set()
        for iface, data in staticmaps_by_iface.items():
            reservations = list(data.get("reservations", []))
            delete_flag = bool(data.get("delete"))
            if delete_flag:
                ok, changed, updated_ifaces = _send_payload({iface: data})
                if not ok:
                    return False, False, []
                overall_changed = overall_changed or changed
                changed_ifaces.update(updated_ifaces)
                continue
            cumulative: List[Dict[str, Any]] = []
            for idx, entry in enumerate(reservations, 1):
                cumulative.append(entry)
                chunk_payload = {iface: {"reservations": list(cumulative)}}
                ok, changed, updated_ifaces = _send_payload(chunk_payload)
                if not ok:
                    return False, False, []
                overall_changed = overall_changed or changed
                changed_ifaces.update(updated_ifaces)
                if jk.is_debug_enabled():
                    jk._debug(
                        f"Reserva {idx}/{len(reservations)} aplicada na interface {iface} no modo 1-a-1"
                    )
        return True, overall_changed, sorted(changed_ifaces)

    return _send_payload(staticmaps_by_iface)


def get_config_path_segments() -> List[str]:
    default_path = "dhcpd"
    raw = jk.env_first("PF_CONFIG_PATH", "PFSENSE_CONFIG_PATH")
    if raw:
        raw = raw.strip()
    if not raw:
        return [default_path]
    segments = [segment.strip() for segment in raw.split(":") if segment.strip()]
    if not segments:
        raise ValueError("PF_CONFIG_PATH vazio")
    if segments != [default_path]:
        jk._warn(
            "PF_CONFIG_PATH diferente de 'dhcpd' foi ignorado — o modo pfSense sempre escreve em $config['dhcpd']"
        )
        return [default_path]
    return segments


def _parse_ipam_subnet_ids() -> List[str]:
    mapping = jk.parse_mapping_env(
        "SUBNET_ID_MAP_JSON",
        "SUBNET_ID_MAP",
        "IPAM_SUBNETID_TO_ID",
    )
    if mapping:
        return [str(key) for key in mapping.keys()]
    raw = jk.env_first("IPAM_SUBNET_IDS", "PHPIPAM_SUBNET_IDS")
    if not raw:
        return []
    return [part.strip() for part in raw.split(",") if part.strip()]


def _network_from_ip_and_mask(
    ipaddr: Optional[str], mask: Optional[str]
) -> Optional[ipaddress.IPv4Network]:
    if not ipaddr or not mask:
        return None
    try:
        ipaddress.IPv4Address(str(ipaddr))
    except Exception:
        return None
    mask_s = str(mask).strip()
    if not mask_s:
        return None
    try:
        prefix = int(mask_s)
        return ipaddress.IPv4Interface(f"{ipaddr}/{prefix}").network
    except Exception:
        pass
    try:
        return ipaddress.IPv4Network((str(ipaddr), mask_s), strict=False)
    except Exception:
        return None


def _build_iface_network_index(
    interfaces_config: Dict[str, Any]
) -> Dict[str, ipaddress.IPv4Network]:
    index: Dict[str, ipaddress.IPv4Network] = {}
    for iface, data in interfaces_config.items():
        if not isinstance(data, dict):
            continue
        ipaddr = data.get("ipaddr")
        mask = data.get("subnet") or data.get("subnetmask")
        network = _network_from_ip_and_mask(ipaddr, mask)
        if network is None:
            continue
        index[str(iface)] = network
        if jk.is_debug_enabled():
            jk._debug(
                f"Interface {iface}: rede detectada {network} (ipaddr={ipaddr}, mask={mask})"
            )
    return index


def _match_ip_to_iface(
    ip_s: str, iface_networks: Dict[str, ipaddress.IPv4Network]
) -> Optional[str]:
    try:
        addr = ipaddress.IPv4Address(ip_s)
    except Exception:
        return None
    for iface, network in iface_networks.items():
        if addr in network:
            return iface
    return None


def _match_network_to_iface(
    target: ipaddress.IPv4Network,
    iface_networks: Dict[str, ipaddress.IPv4Network],
) -> Optional[str]:
    for iface, network in iface_networks.items():
        if target == network or target.subnet_of(network) or network.subnet_of(target):
            return iface
    return None


def _fetch_ipam_subnet_network(
    base: str,
    token: str,
    subnet_id: str,
    verify_tls: bool,
    cache: Dict[str, Optional[ipaddress.IPv4Network]],
) -> Optional[ipaddress.IPv4Network]:
    if subnet_id in cache:
        if jk.is_debug_enabled():
            jk._debug(f"Sub-rede {subnet_id}: reutilizando rede em cache {cache[subnet_id]}")
        return cache[subnet_id]
    rc, data = jk.ipam_get_subnet(base, token, subnet_id, verify_tls)
    network: Optional[ipaddress.IPv4Network] = None
    if rc == 0 and data:
        subnet = data.get("subnet")
        mask = data.get("mask") or data.get("subnetmask")
        try:
            if subnet and mask:
                network = ipaddress.IPv4Network(f"{subnet}/{mask}", strict=False)
        except Exception as exc:
            jk._warn(
                f"Não foi possível interpretar a rede do phpIPAM para sub-rede {subnet_id}: {exc}"
            )
    else:
        jk._warn(f"phpIPAM não retornou detalhes para a sub-rede {subnet_id}")
    if jk.is_debug_enabled():
        jk._debug(f"Sub-rede {subnet_id}: rede descoberta {network}")
    cache[subnet_id] = network
    return network


def _determine_interface_for_subnet(
    subnet_id: str,
    items: List[Dict[str, Any]],
    iface_networks: Dict[str, ipaddress.IPv4Network],
    base: str,
    token: str,
    verify_tls: bool,
    network_cache: Dict[str, Optional[ipaddress.IPv4Network]],
) -> Optional[str]:
    matches: Dict[str, int] = {}
    for item in items:
        ip_s = item.get("ip")
        if not ip_s:
            continue
        iface = _match_ip_to_iface(ip_s, iface_networks)
        if iface:
            matches[iface] = matches.get(iface, 0) + 1
    if matches:
        iface, _ = max(matches.items(), key=lambda kv: kv[1])
        if len(matches) > 1:
            jk._warn(
                f"Sub-rede {subnet_id} tem IPs espalhados em múltiplas interfaces {list(matches.keys())}; usando {iface}"
            )
        elif jk.is_debug_enabled():
            jk._debug(
                f"Sub-rede {subnet_id}: interface escolhida {iface} com base em IPs {matches}"
            )
        return iface
    network = _fetch_ipam_subnet_network(base, token, subnet_id, verify_tls, network_cache)
    if network:
        iface = _match_network_to_iface(network, iface_networks)
        if iface:
            if jk.is_debug_enabled():
                jk._debug(
                    f"Sub-rede {subnet_id}: interface {iface} combinada pela rede {network}"
                )
            return iface
        jk._warn(
            f"Rede {network} da sub-rede {subnet_id} não corresponde a nenhum DHCP ativo no pfSense"
        )
    else:
        jk._warn(
            f"Não foi possível descobrir a rede da sub-rede {subnet_id}; defina IPs ou revise o phpIPAM"
        )
    return None


def _build_staticmap_entry(item: Dict[str, Any]) -> Dict[str, Any]:
    entry: Dict[str, Any] = {"ipaddr": item["ip"]}
    identifier_hex = item["identifier_hex"].lower()
    identifier_type = int(item.get("identifier_type", 0))
    if identifier_type == 0:
        entry["mac"] = jk._group_hex_pairs(identifier_hex)
    else:
        entry["cid"] = jk._group_hex_pairs(identifier_hex)
    hostname = item.get("hostname")
    if hostname:
        sanitized = _sanitize_hostname(str(hostname))
        if sanitized:
            entry["hostname"] = sanitized
            entry["descr"] = sanitized
            if jk.is_debug_enabled() and sanitized != str(hostname):
                jk._debug(
                    f"Hostname sanitizado '{hostname}' -> '{sanitized}' para IP {item['ip']}"
                )
    return entry


def _normalize_staticmap_entry(entry: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(entry, dict):
        return None
    normalized: Dict[str, Any] = {}
    for field in ("ipaddr", "mac", "cid", "hostname", "descr"):
        if field not in entry:
            continue
        value = entry[field]
        if value is None:
            continue
        if isinstance(value, str):
            value = value.strip()
        if value == "":
            continue
        if field in ("mac", "cid") and isinstance(value, str):
            value = value.lower()
        normalized[field] = value
    if "ipaddr" not in normalized:
        return None
    if "mac" not in normalized and "cid" not in normalized:
        return None
    return normalized


def _normalize_staticmap_entries(entries: Any) -> List[Dict[str, Any]]:
    if isinstance(entries, dict):
        iterable = entries.values()
    elif isinstance(entries, list):
        iterable = entries
    else:
        return []
    result: List[Dict[str, Any]] = []
    for entry in iterable:
        normalized = _normalize_staticmap_entry(entry)
        if normalized is None:
            continue
        result.append(normalized)
    return result


def _staticmap_entries_by_ip(entries: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    mapping: Dict[str, Dict[str, Any]] = {}
    for entry in entries:
        ipaddr = str(entry.get("ipaddr"))
        if not ipaddr:
            continue
        if ipaddr in mapping:
            jk._warn(f"Mais de uma reserva para o IP {ipaddr}; mantendo a última entrada")
        mapping[ipaddr] = entry
    return mapping


def _staticmap_entries_equal(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    fields = ("mac", "cid", "hostname", "descr")
    for field in fields:
        if a.get(field) != b.get(field):
            return False
    return True


def _diff_staticmaps(
    current_entries: List[Dict[str, Any]],
    desired_entries: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Tuple[Dict[str, Any], Dict[str, Any]]], List[Dict[str, Any]]]:
    current_by_ip = _staticmap_entries_by_ip(current_entries)
    desired_by_ip = _staticmap_entries_by_ip(desired_entries)

    created: List[Dict[str, Any]] = []
    updated: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    deleted: List[Dict[str, Any]] = []

    for ip, desired_entry in desired_by_ip.items():
        current_entry = current_by_ip.get(ip)
        if current_entry is None:
            created.append(desired_entry)
            continue
        if not _staticmap_entries_equal(current_entry, desired_entry):
            updated.append((current_entry, desired_entry))

    for ip, current_entry in current_by_ip.items():
        if ip not in desired_by_ip:
            deleted.append(current_entry)

    return created, updated, deleted


def _describe_staticmap_entry(entry: Dict[str, Any]) -> str:
    parts = [str(entry.get("ipaddr"))]
    identifier = entry.get("mac") or entry.get("cid")
    if identifier:
        parts.append(str(identifier))
    hostname = entry.get("hostname")
    if hostname:
        parts.append(str(hostname))
    descr = entry.get("descr")
    if descr and descr != hostname:
        parts.append(f"descr='{descr}'")
    return " ".join(parts)


def _describe_staticmap_change(old: Dict[str, Any], new: Dict[str, Any]) -> str:
    changes: List[str] = []
    for field in ("mac", "cid", "hostname", "descr"):
        old_val = old.get(field)
        new_val = new.get(field)
        if old_val == new_val:
            continue
        changes.append(
            f"{field}: '{old_val if old_val is not None else '-'}' -> '{new_val if new_val is not None else '-'}'"
        )
    if not changes:
        return "sem alterações de campo"
    return ", ".join(changes)


def _extract_current_staticmaps(
    dhcpd_config: Optional[Dict[str, Any]]
) -> Dict[str, List[Dict[str, Any]]]:
    result: Dict[str, List[Dict[str, Any]]] = {}
    if not isinstance(dhcpd_config, dict):
        return result
    for iface, data in dhcpd_config.items():
        if not isinstance(data, dict):
            continue
        entries = _normalize_staticmap_entries(data.get("staticmap"))
        result[str(iface)] = entries
    return result


def sync(dry_run: bool = False, delete_missing: bool = True) -> Tuple[int, int, int]:
    debug_enabled = jk.is_debug_enabled()
    base = jk.build_ipam_base_url()
    if not base:
        jk._err("Configure PHPIPAM_BASE_URL (e PHPIPAM_APP_ID) no .env — veja o .env.example.")
        return (0, 0, 1)

    verify_tls = jk.parse_bool(jk.env_first("PHPIPAM_VERIFY_TLS", "IPAM_VERIFY_TLS"), default=False)
    if debug_enabled:
        jk._debug(
            f"Iniciando sync (dry_run={dry_run}, delete_missing={delete_missing}, verify_tls={verify_tls})"
        )
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

    ipam_subnet_ids = _parse_ipam_subnet_ids()
    if not ipam_subnet_ids:
        jk._err(
            "Configure SUBNET_ID_MAP_JSON (ou SUBNET_ID_MAP/IPAM_SUBNETID_TO_ID) no .env para listar as sub-redes do phpIPAM a sincronizar."
        )
        return (0, 0, 1)
    if debug_enabled:
        jk._debug(f"Sub-redes configuradas para sincronizar: {ipam_subnet_ids}")

    ssh_settings = jk._load_ssh_settings()
    if debug_enabled:
        jk._debug(f"Configuração SSH carregada: {ssh_settings}")
    # Ainda validamos PF_CONFIG_PATH para alertar sobre caminhos inválidos
    get_config_path_segments()
    errors = 0
    interfaces_config = fetch_pfsense_config(["interfaces"], ssh_settings)
    if interfaces_config is None:
        jk._err("Não foi possível ler $config['interfaces'] no pfSense; necessário para localizar as redes de cada interface.")
        return (0, 0, 1)

    dhcpd_config = fetch_pfsense_config(["dhcpd"], ssh_settings)
    if dhcpd_config is None:
        jk._warn(
            "Não foi possível ler $config['dhcpd'] no pfSense; assumindo que não há reservas atuais para comparação"
        )
    current_staticmaps = _extract_current_staticmaps(dhcpd_config)
    if debug_enabled:
        jk._debug(
            f"pfSense retornou {len(current_staticmaps)} interfaces com static-maps atuais"
        )

    iface_networks = _build_iface_network_index(interfaces_config)
    if not iface_networks:
        jk._err("Nenhuma interface com IPv4 válido encontrada no pfSense; habilite DHCP nas VLANs desejadas antes de sincronizar.")
        return (0, 0, 1)

    iface_results: Dict[str, Dict[str, Any]] = {}
    processed_ifaces: Set[str] = set()
    subnet_network_cache: Dict[str, Optional[ipaddress.IPv4Network]] = {}

    for ipam_subnet in ipam_subnet_ids:
        rc, data = jk.ipam_get_addresses(base, token, str(ipam_subnet), verify_tls)
        if rc != 0 or data is None:
            errors += 1
            continue
        items = jk.build_items_from_ipam(data)

        if debug_enabled:
            jk._debug(
                f"Sub-rede {ipam_subnet}: {len(items)} endereços retornados pelo phpIPAM"
            )

        if not items:
            items = []

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

        iface = _determine_interface_for_subnet(
            str(ipam_subnet), items, iface_networks, base, token, verify_tls, subnet_network_cache
        )
        if not iface:
            base_msg = (
                f"Não foi possível associar a sub-rede {ipam_subnet} a nenhuma interface do pfSense; confira o config.xml e as VLANs."
            )
            if not items:
                jk._warn(base_msg + " — sub-rede sem IPs foi ignorada")
                continue
            jk._err(base_msg)
            errors += 1
            continue

        processed_ifaces.add(iface)
        iface_network = iface_networks.get(iface)

        if not items:
            msg = f"Sub-rede {ipam_subnet} sem IPs elegíveis (estáticos com MAC/client-id)"
            if delete_missing:
                jk._warn(msg)
                entry = iface_results.setdefault(
                    iface, {"reservations": [], "delete": False}
                )
                entry["delete"] = True
            else:
                jk._debug(msg + " — preservando reservas atuais")
            continue

        filtered_items: List[Dict[str, Any]] = []
        for it in items:
            if iface_network and it.get("ip"):
                try:
                    ip_val = ipaddress.IPv4Address(it["ip"])
                    if ip_val not in iface_network:
                        jk._warn(
                            f"Ignorado {it['ip']} da sub-rede {ipam_subnet}: fora da rede {iface_network} da interface {iface}"
                        )
                        continue
                except Exception:
                    jk._warn(f"Ignorado IP inválido {it.get('ip')} na sub-rede {ipam_subnet}")
                    continue
            filtered_items.append(it)

        if debug_enabled:
            jk._debug(
                f"Sub-rede {ipam_subnet} vinculada à interface {iface}: {len(filtered_items)} IPs após filtro"
            )

        if not filtered_items:
            msg = (
                f"Sub-rede {ipam_subnet} não possui IPs dentro da rede {iface_network} (interface {iface})"
                if iface_network
                else f"Sub-rede {ipam_subnet} não possui IPs compatíveis com a interface {iface}"
            )
            if delete_missing:
                jk._warn(msg)
                entry = iface_results.setdefault(
                    iface, {"reservations": [], "delete": False}
                )
                entry["delete"] = True
            else:
                jk._debug(msg + " — preservando reservas atuais")
            continue

        reservations = [_build_staticmap_entry(it) for it in filtered_items]
        entry = iface_results.setdefault(iface, {"reservations": [], "delete": False})
        entry["reservations"].extend(reservations)

        for it in filtered_items:
            identifier_log = it.get("log_identifier", it["identifier_hex"])
            jk._info(
                f"Reserva preparada {it['ip']} ({identifier_log}) interface={iface}"
            )

    if not processed_ifaces:
        jk._warn("Nenhuma interface foi processada com sucesso; nada para escrever.")
        return (0, 0, errors if errors else 1)

    updates_payload: Dict[str, Dict[str, Any]] = {}
    total_reservations = 0
    for iface, result in iface_results.items():
        reservations_raw = result.get("reservations") or []
        reservations = _normalize_staticmap_entries(reservations_raw)
        delete_flag = bool(result.get("delete"))
        current_entries = current_staticmaps.get(iface, [])

        if delete_flag and not reservations:
            if not current_entries:
                jk._info(
                    f"Interface {iface} já não possui static-maps — nenhuma remoção necessária"
                )
                continue
            for entry in current_entries:
                jk._info(
                    f"Reserva removida interface={iface} {_describe_staticmap_entry(entry)}"
                )
            updates_payload[iface] = {"reservations": [], "delete": True}
            continue

        if not reservations:
            continue

        created, updated, deleted = _diff_staticmaps(current_entries, reservations)
        if not created and not updated and not deleted:
            jk._debug(
                f"Interface {iface} já possui reservas idênticas — nenhuma atualização necessária"
            )
            continue

        for entry in created:
            jk._info(
                f"Reserva adicionada interface={iface} {_describe_staticmap_entry(entry)}"
            )
        for old, new in updated:
            change = _describe_staticmap_change(old, new)
            jk._info(
                f"Reserva atualizada interface={iface} {new['ipaddr']} ({change})"
            )
        for entry in deleted:
            jk._info(
                f"Reserva removida interface={iface} {_describe_staticmap_entry(entry)}"
            )

        updates_payload[iface] = {"reservations": reservations, "delete": False}
        total_reservations += len(reservations)

    if not updates_payload:
        if errors:
            return (total_reservations, 0, errors)
        jk._info("Nenhuma alteração necessária — pfSense já estava sincronizado")
        return (total_reservations, 0, errors)

    if debug_enabled:
        jk._debug(
            f"Interfaces a atualizar: {list(updates_payload.keys())}; reservas totais preparadas: {total_reservations}"
        )

    if dry_run:
        for iface, data in updates_payload.items():
            count = len(data.get("reservations") or [])
            if count:
                jk._info(
                    f"DRY-RUN: {count} reservas seriam gravadas na interface={iface}"
                )
            elif data.get("delete"):
                jk._info(
                    f"DRY-RUN: static-maps seriam removidos da interface={iface}"
                )
        return (total_reservations, len(updates_payload), errors)

    note = (
        jk.env_first("PF_CONFIG_WRITE_NOTE", "PFSENSE_CONFIG_NOTE", default="Kea_IPAM_Sync")
        or "Kea_IPAM_Sync"
    )
    success, changed, changed_ifaces = push_staticmaps_to_pfsense(
        updates_payload, ssh_settings, note
    )
    if not success:
        errors += 1
        return (total_reservations, 0, errors)

    if not changed:
        jk._info("pfSense já possuía a mesma configuração — sem reload adicional")
        return (total_reservations, 0, errors)

    for iface in changed_ifaces:
        data = updates_payload.get(iface, {})
        count = len(data.get("reservations") or [])
        if count:
            jk._info(f"Atualizadas {count} reservas para interface={iface}")
        elif data.get("delete"):
            jk._info(f"Static-maps removidos para interface={iface}")

    jk._info("Configuração do pfSense atualizada e serviço recarregado")

    return (total_reservations, len(changed_ifaces), errors)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sincroniza reservas do phpIPAM diretamente como static-maps DHCP do pfSense"
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
    if jk.is_debug_enabled():
        jk._debug(f"Modo debug ativo; arquivo .env carregado de {args.env}")

    start = time.time()
    total_reservations, interfaces_modified, errors = sync(
        dry_run=args.dry_run,
        delete_missing=not getattr(args, "skip_delete", False),
    )
    elapsed = time.time() - start

    print()
    jk._log(
        jk.logging.INFO,
        f"Resumo: reservas={total_reservations}, interfaces alteradas={interfaces_modified}, erros={errors}  ({elapsed:.2f}s)",
    )

    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
