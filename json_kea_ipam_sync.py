#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sincroniza reservas do phpIPAM com um arquivo kea-dhcp4.conf."""

import os
import sys
import json
import time
import argparse
import logging
import shlex
import shutil
import subprocess
from datetime import datetime
import ipaddress
from typing import Any, Dict, List, Optional, Tuple, Set

try:
    import requests
except Exception as e:  # pragma: no cover - dependência externa
    print("[ERRO] Dependência 'requests' não instalada. Instale com: pip install requests", file=sys.stderr)
    raise

try:  # pragma: no cover - dependência opcional
    import paramiko  # type: ignore
except Exception:
    paramiko = None  # type: ignore


# ---------------------------
# Logging helpers
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


def _log(level: int, message: str) -> None:
    logger = _ensure_logger()
    logger.log(level, message)


def _debug(msg: str) -> None:
    if os.getenv("DEBUG", "false").lower() in ("1", "true", "yes", "on"):
        _log(logging.DEBUG, f"[DEBUG] {msg}")


def _info(msg: str) -> None:
    _log(logging.INFO, f"OK   {msg}")


def _warn(msg: str) -> None:
    _log(logging.WARNING, f"[WARN] {msg}")


def _err(msg: str) -> None:
    _log(logging.ERROR, f"ERRO {msg}")


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
    "reserve_kea",
)


def _split_extra_args(raw: Optional[str]) -> List[str]:
    if not raw:
        return []
    try:
        return shlex.split(raw)
    except ValueError:
        return [part for part in raw.split() if part]


def _build_ssh_base(settings: Dict[str, Any]) -> str:
    user = settings.get("user")
    host = settings["host"]
    return f"{user}@{host}" if user else host


def _ssh_common_args(settings: Dict[str, Any], *, for_scp: bool) -> List[str]:
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
        except Exception as exc:
            client.close()
            return None, f"falha ao carregar known_hosts '{known_hosts}': {exc}"
    if strict:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_args: Dict[str, Any] = {
        "hostname": settings["host"],
        "port": settings.get("port", 22),
        "username": settings.get("user") or None,
        "timeout": 10,
        "banner_timeout": 10,
    }
    identity = settings.get("identity")
    if identity:
        connect_args["key_filename"] = identity
    password = settings.get("password")
    if password:
        connect_args["password"] = password
        connect_args["allow_agent"] = False
        connect_args["look_for_keys"] = False
    else:
        connect_args.setdefault("allow_agent", True)
        connect_args.setdefault("look_for_keys", True)

    try:
        client.connect(**connect_args)
    except Exception as exc:
        client.close()
        return None, str(exc)
    return client, None


def _paramiko_run_command(settings: Dict[str, Any], command: str) -> Tuple[int, str, str]:
    client, error = _paramiko_connect(settings)
    if client is None:
        return 255, "", error or "falha ao inicializar conexão Paramiko"
    try:
        stdin, stdout, stderr = client.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()
        out = stdout.read().decode(errors="ignore").strip()
        err = stderr.read().decode(errors="ignore").strip()
        return exit_status, out, err
    except Exception as exc:
        return 255, "", str(exc)
    finally:
        client.close()


def _paramiko_deploy(
    settings: Dict[str, Any], local_path: str, remote_path: str
) -> Tuple[bool, str]:
    client, error = _paramiko_connect(settings)
    if client is None:
        return False, error or "falha ao inicializar conexão Paramiko"
    try:
        directory = os.path.dirname(remote_path)
        if directory and directory not in (".", "/"):
            cmd = f"mkdir -p {shlex.quote(directory)}"
            stdin, stdout, stderr = client.exec_command(cmd)
            exit_status = stdout.channel.recv_exit_status()
            stdout_data = stdout.read().decode(errors="ignore").strip()
            stderr_data = stderr.read().decode(errors="ignore").strip()
            if exit_status != 0:
                message = stderr_data or stdout_data or f"mkdir -p retornou código {exit_status}"
                return False, message
        try:
            with client.open_sftp() as sftp:
                sftp.put(local_path, remote_path)
        except Exception as exc:
            return False, str(exc)
    except Exception as exc:
        return False, str(exc)
    finally:
        client.close()
    return True, ""


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


def _deploy_via_scp(
    settings: Dict[str, Any], local_path: str, remote_path: str
) -> Tuple[bool, str]:
    transport = settings.get("_transport", "ssh")
    if transport == "unsupported":
        return False, "Autenticação por senha requer 'sshpass' ou biblioteca 'paramiko'"
    if transport == "paramiko":
        return _paramiko_deploy(settings, local_path, remote_path)
    target = f"{_build_ssh_base(settings)}:{remote_path}"
    args = ["scp", *_ssh_common_args(settings, for_scp=True), local_path, target]
    args, env = _wrap_ssh_with_password(settings, args)
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
    except FileNotFoundError:
        missing = args[0]
        if missing == "sshpass":
            return False, "Comando 'sshpass' não encontrado no PATH"
        return False, "Comando 'scp' não encontrado no PATH"
    if proc.returncode != 0:
        msg = proc.stderr.strip() or proc.stdout.strip() or "falha desconhecida"
        return False, msg
    return True, ""


def _paramiko_fetch(
    settings: Dict[str, Any], remote_path: str, local_path: str
) -> Tuple[bool, str]:
    client, error = _paramiko_connect(settings)
    if client is None:
        return False, error or "falha ao inicializar conexão Paramiko"
    try:
        os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)
        try:
            with client.open_sftp() as sftp:
                sftp.get(remote_path, local_path)
        except FileNotFoundError:
            return False, "arquivo remoto não encontrado"
        except Exception as exc:
            return False, str(exc)
    except Exception as exc:
        return False, str(exc)
    finally:
        client.close()
    return True, ""


def _fetch_via_scp(
    settings: Dict[str, Any], remote_path: str, local_path: str
) -> Tuple[bool, str]:
    transport = settings.get("_transport", "ssh")
    if transport == "unsupported":
        return False, "Autenticação por senha requer 'sshpass' ou biblioteca 'paramiko'"
    if transport == "paramiko":
        return _paramiko_fetch(settings, remote_path, local_path)
    target = f"{_build_ssh_base(settings)}:{remote_path}"
    args = ["scp", *_ssh_common_args(settings, for_scp=True), target, local_path]
    args, env = _wrap_ssh_with_password(settings, args)
    os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
    except FileNotFoundError:
        missing = args[0]
        if missing == "sshpass":
            return False, "Comando 'sshpass' não encontrado no PATH"
        return False, "Comando 'scp' não encontrado no PATH"
    if proc.returncode != 0:
        msg = proc.stderr.strip() or proc.stdout.strip() or "falha desconhecida"
        return False, msg
    return True, ""


def _resolve_remote_path(default_remote_path: Optional[str] = None) -> Optional[str]:
    remote_path = env_first(
        "PF_SSH_REMOTE_PATH",
        "PFSENSE_REMOTE_CONFIG_PATH",
        "KEA_REMOTE_CONFIG_PATH",
    )
    if remote_path:
        remote_path = remote_path.strip()
        if remote_path:
            return remote_path
    if default_remote_path:
        default_remote_path = default_remote_path.strip()
        if default_remote_path and default_remote_path.startswith("/"):
            return default_remote_path
    return None


def fetch_config_from_pfsense(
    local_path: str, default_remote_path: str
) -> Tuple[bool, bool]:
    settings = _load_ssh_settings()
    if not settings:
        return (False, True)
    remote_path = _resolve_remote_path(default_remote_path)
    if not remote_path:
        _err("PF_SSH_REMOTE_PATH não configurado e caminho remoto padrão inválido")
        return (True, False)
    ok, message = _fetch_via_scp(settings, remote_path, local_path)
    if not ok:
        _err(f"Falha ao baixar arquivo do pfSense: {message}")
        return (True, False)
    _info(f"Arquivo baixado do pfSense: {remote_path}")
    return (True, True)


def _ensure_remote_directory(settings: Dict[str, Any], remote_path: str) -> bool:
    transport = settings.get("_transport", "ssh")
    if transport == "unsupported":
        _warn("Autenticação por senha requer 'sshpass' instalado ou 'pip install paramiko'")
        return False
    if transport == "paramiko":
        # O mkdir será feito durante o deploy via Paramiko
        return True
    directory = os.path.dirname(remote_path)
    if not directory or directory in (".", "/"):
        return True
    cmd = f"mkdir -p {shlex.quote(directory)}"
    rc, _, stderr = _run_ssh_command(settings, cmd)
    if rc != 0:
        msg = stderr or f"mkdir -p retornou código {rc}"
        _warn(f"Falha ao criar diretório remoto {directory}: {msg}")
        return False
    return True


def deploy_config_to_pfsense(local_path: str, default_remote_path: str) -> Tuple[bool, bool]:
    settings = _load_ssh_settings()
    if not settings:
        return (False, True)
    remote_path = _resolve_remote_path(default_remote_path)
    if not remote_path:
        _err("PF_SSH_REMOTE_PATH não configurado e caminho remoto padrão inválido")
        return (True, False)

    transport = settings.get("_transport", "ssh")
    if transport == "unsupported":
        _err(
            "Autenticação por senha requer o utilitário 'sshpass' instalado ou a biblioteca Python 'paramiko' (pip install paramiko)"
        )
        return (True, False)

    if not _ensure_remote_directory(settings, remote_path):
        return (True, False)

    ok, message = _deploy_via_scp(settings, local_path, remote_path)
    if not ok:
        _err(f"Falha ao enviar arquivo para pfSense: {message}")
        return (True, False)

    _info(f"Arquivo enviado para pfSense: {remote_path}")
    return (True, True)


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


def hex_to_bytes(value: str) -> bytes:
    return bytes.fromhex(value)


def _group_hex_pairs(value: str) -> str:
    return ":".join(value[i : i + 2] for i in range(0, len(value), 2))


def format_identifier_for_log(identifier_hex: str, identifier_type: int) -> str:
    identifier_hex = identifier_hex.lower()
    if identifier_type == 0 and len(identifier_hex) == 12:
        return _group_hex_pairs(identifier_hex)
    if identifier_type == 1:
        try:
            return _group_hex_pairs(identifier_hex)
        except Exception:
            return identifier_hex
    return identifier_hex


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
    headers = {"Accept": "application/json"}
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
    except requests.RequestException as exc:
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
                "log_identifier": format_identifier_for_log(identifier_hex, identifier_type),
            }
        )
    return items


# ---------------------------
# KEA Control Agent - reload opcional
# ---------------------------
def kea_reload_if_enabled() -> None:
    if os.getenv("RELOAD_AFTER_DB", "false").lower() not in ("1", "true", "yes", "on"):
        _debug("PULANDO reload: RELOAD_AFTER_DB=false")
        return
    ssh_settings = _load_ssh_settings()
    if ssh_settings:
        if ssh_settings.get("_transport") == "unsupported":
            _warn(
                "PULANDO reload via SSH: instale 'sshpass' ou 'pip install paramiko' para suportar autenticação por senha"
            )
        else:
            reload_cmd = env_first("PF_SSH_RELOAD_COMMAND", "PFSENSE_RELOAD_COMMAND")
            if reload_cmd:
                reload_cmd = reload_cmd.strip()
            if not reload_cmd:
                reload_cmd = "sudo keactrl reload -s dhcp4"
            if reload_cmd:
                rc, stdout, stderr = _run_ssh_command(ssh_settings, reload_cmd)
                if rc == 0:
                    message = stdout or stderr
                    if message:
                        _debug(f"SSH reload output: {message}")
                    _info("reload solicitado ao pfSense via SSH")
                    return
                else:
                    msg = stderr or stdout or f"código {rc}"
                    _warn(f"reload via SSH falhou (best-effort): {msg}")
            else:
                _debug("PULANDO reload via SSH: comando vazio")

    base = os.getenv("KEA_URL", "").strip()
    if not base:
        _debug("PULANDO reload: KEA_URL vazio")
        return
    user = os.getenv("KEA_USER", "").strip()
    pwd = os.getenv("KEA_PASSWORD", "").strip()

    url = f"{base.rstrip('/')}/v1/ctrl-agent/command"
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
# JSON helpers
# ---------------------------
def reservation_from_item(item: Dict[str, Any]) -> Dict[str, Any]:
    identifier_hex = item["identifier_hex"].lower()
    identifier_type = int(item.get("identifier_type", 0))
    reservation: Dict[str, Any] = {
        "ip-address": item["ip"],
    }
    if identifier_type == 0:
        reservation["hw-address"] = _group_hex_pairs(identifier_hex)
    else:
        reservation["client-id"] = _group_hex_pairs(identifier_hex)
    hostname = item.get("hostname")
    if hostname:
        reservation["hostname"] = hostname
    return reservation


def load_base_config(template_path: Optional[str], output_path: str) -> Dict[str, Any]:
    candidates = [template_path, output_path]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            try:
                with open(candidate, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                    if isinstance(data, dict):
                        return data
            except Exception as exc:
                _warn(f"Não foi possível ler {candidate}: {exc}")
    return {"Dhcp4": {"subnet4": []}}


def ensure_subnet_entry(config: Dict[str, Any], subnet_id: int) -> Dict[str, Any]:
    dhcp4 = config.setdefault("Dhcp4", {})
    subnet_list = dhcp4.setdefault("subnet4", [])
    for entry in subnet_list:
        try:
            if int(entry.get("id")) == subnet_id:
                return entry
        except Exception:
            continue
    _warn(
        f"Sub-rede id={subnet_id} não encontrada no arquivo. Criando entrada básica (prefixo deve existir manualmente)."
    )
    entry = {"id": subnet_id, "reservations": []}
    subnet_list.append(entry)
    return entry


def apply_reservations(
    config: Dict[str, Any],
    reservations_by_subnet: Dict[int, List[Dict[str, Any]]],
    delete_missing: bool,
) -> Tuple[int, int]:
    dhcp4 = config.setdefault("Dhcp4", {})
    subnet_list = dhcp4.setdefault("subnet4", [])
    index_by_id: Dict[int, Dict[str, Any]] = {}
    for entry in subnet_list:
        try:
            idx = int(entry.get("id"))
            index_by_id[idx] = entry
        except Exception:
            continue

    subnets_modified = 0
    reservations_total = 0

    for subnet_id, reservations in reservations_by_subnet.items():
        entry = index_by_id.get(subnet_id)
        if entry is None:
            entry = ensure_subnet_entry(config, subnet_id)
            index_by_id[subnet_id] = entry
        current_res = entry.get("reservations") or []
        if not isinstance(current_res, list):
            current_res = []
        if reservations or delete_missing:
            if current_res != reservations:
                subnets_modified += 1
                entry["reservations"] = reservations
                _info(
                    f"Atualizadas {len(reservations)} reservas para subnet-id={subnet_id}"
                )
        else:
            _debug(
                f"Sub-rede id={subnet_id} não recebeu reservas e --skip-delete está ativo; mantendo configuração atual"
            )
        reservations_total += len(reservations)

    if delete_missing:
        managed_ids = set(reservations_by_subnet.keys())
        for subnet_id, entry in list(index_by_id.items()):
            if subnet_id not in managed_ids:
                continue
            if subnet_id in reservations_by_subnet and not reservations_by_subnet[subnet_id]:
                if entry.get("reservations"):
                    entry["reservations"] = []
                    subnets_modified += 1
                    _info(f"Removidas reservas antigas da subnet-id={subnet_id}")

    return reservations_total, subnets_modified


def write_config(output_path: str, config: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    tmp_path = f"{output_path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(config, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    os.replace(tmp_path, output_path)
    _info(f"Arquivo {output_path} atualizado com sucesso")


# ---------------------------
# CORE
# ---------------------------
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


def sync(dry_run: bool = False, delete_missing: bool = True) -> Tuple[int, int, int]:
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

    output_path = env_first("KEA_JSON_OUTPUT_PATH", "KEA_CONFIG_PATH", default="kea-dhcp4.conf")
    template_path = env_first("KEA_JSON_TEMPLATE_PATH", "KEA_CONFIG_TEMPLATE_PATH")

    fetched_remote = False
    errors = 0
    fetch_attempted, fetch_ok = fetch_config_from_pfsense(output_path, output_path)
    if fetch_attempted:
        if not fetch_ok:
            errors += 1
        else:
            fetched_remote = True

    config = load_base_config(template_path, output_path)

    reservations_by_subnet: Dict[int, List[Dict[str, Any]]] = {}
    processed_subnets: Set[int] = set()

    for ipam_subnet, kea_subnet_id in ipam_to_kea.items():
        rc, data = ipam_get_addresses(base, token, str(ipam_subnet), verify_tls)
        if rc != 0 or data is None:
            errors += 1
            continue
        subnet_int = int(kea_subnet_id)
        processed_subnets.add(subnet_int)
        items = build_items_from_ipam(data)

        if not items:
            msg = f"Sub-rede {ipam_subnet} sem IPs elegíveis (estáticos com MAC/client-id)"
            if delete_missing:
                _warn(msg)
                reservations_by_subnet[subnet_int] = []
            else:
                _debug(msg + " — preservando reservas atuais")
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

        reservations = [reservation_from_item(it) for it in items]
        reservations_by_subnet[subnet_int] = reservations

        for it in items:
            identifier_log = it.get("log_identifier", it["identifier_hex"])
            _info(
                f"Reserva preparada {it['ip']} ({identifier_log}) subnet-id={kea_subnet_id}"
            )

    if not processed_subnets:
        _warn("Nenhuma sub-rede foi processada com sucesso; nada para escrever.")
        return (0, 0, errors if errors else 1)

    total_reservations, subnets_modified = apply_reservations(
        config, reservations_by_subnet, delete_missing
    )

    if dry_run:
        _info(
            f"DRY-RUN: {total_reservations} reservas seriam gravadas em {subnets_modified} sub-redes"
        )
        return (total_reservations, subnets_modified, errors)

    try:
        write_config(output_path, config)
    except Exception as exc:
        errors += 1
        _err(f"Falha ao escrever {output_path}: {exc}")
        return (total_reservations, subnets_modified, errors)

    remote_attempted, remote_ok = deploy_config_to_pfsense(output_path, output_path)
    if remote_attempted and not remote_ok:
        errors += 1

    if total_reservations > 0 or subnets_modified > 0:
        if not remote_attempted or remote_ok:
            kea_reload_if_enabled()
        else:
            _warn("PULANDO reload: envio via SSH falhou")
    else:
        _debug("PULANDO reload: nada mudou")

    remove_local = parse_bool(
        env_first("PF_SSH_REMOVE_LOCAL_COPY", "PFSENSE_REMOVE_LOCAL_COPY"),
        default=False,
    )
    if remove_local and fetched_remote and (not remote_attempted or remote_ok):
        try:
            os.remove(output_path)
            _info(f"Arquivo local temporário removido: {output_path}")
        except OSError as exc:
            _warn(f"Falha ao remover arquivo local temporário {output_path}: {exc}")

    return (total_reservations, subnets_modified, errors)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sincroniza reservas do phpIPAM -> arquivo kea-dhcp4.conf"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Não grava arquivo; apenas exibe as alterações planejadas",
    )
    parser.add_argument(
        "--skip-delete",
        dest="skip_delete",
        action="store_true",
        help="Não remove reservas existentes quando o phpIPAM não retornar entradas",
    )
    parser.add_argument(
        "--no-delete",
        dest="skip_delete",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--env", default=".env", help="Caminho do arquivo .env (padrão: .env)")
    args = parser.parse_args()

    load_env(args.env)
    setup_logging(force=True)

    start = time.time()
    total_reservations, subnets_modified, errors = sync(
        dry_run=args.dry_run,
        delete_missing=not getattr(args, "skip_delete", False),
    )
    elapsed = time.time() - start

    print()
    _log(
        logging.INFO,
        f"Resumo: reservas={total_reservations}, sub-redes alteradas={subnets_modified}, erros={errors}  ({elapsed:.2f}s)",
    )

    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
