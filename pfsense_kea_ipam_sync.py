#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sincroniza reservas do phpIPAM diretamente em static-maps nativos do pfSense."""

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
        // Evita TypeError no array_path_enabled() quando notificações não existem
        if (!isset($config['notifications']) || !is_array($config['notifications'])) {{
            $config['notifications'] = array();
        }}
        if (!isset($config['notifications']['smtp']) || !is_array($config['notifications']['smtp'])) {{
            $config['notifications']['smtp'] = array();
        }}
        write_config($note);

        // Reload do serviço DHCP nativo
        if (function_exists('services_dhcpd_configure')) {{
            services_dhcpd_configure();
        }} elseif (function_exists('dhcpd_configure')) {{
            dhcpd_configure();
        }} elseif (file_exists('/usr/local/sbin/rc.dhcpd')) {{
            mwexec('/usr/local/sbin/rc.dhcpd restart');
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
        return iface
    network = _fetch_ipam_subnet_network(base, token, subnet_id, verify_tls, network_cache)
    if network:
        iface = _match_network_to_iface(network, iface_networks)
        if iface:
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
        entry["hostname"] = hostname
        entry["descr"] = hostname
    return entry


def _apply_staticmaps(
    dhcpd_config: Dict[str, Any],
    staticmaps_by_iface: Dict[str, List[Dict[str, Any]]],
    delete_missing: bool,
) -> Tuple[int, int]:
    interfaces_modified = 0
    total_mappings = 0

    for iface, entries in staticmaps_by_iface.items():
        iface_section = dhcpd_config.get(iface)
        if not isinstance(iface_section, dict):
            iface_section = {}
            dhcpd_config[iface] = iface_section
        current = iface_section.get("staticmap")
        if not isinstance(current, list):
            current = []
        if entries or delete_missing:
            if current != entries:
                iface_section["staticmap"] = entries
                interfaces_modified += 1
                jk._info(
                    f"Atualizadas {len(entries)} reservas para interface={iface}"
                )
        else:
            jk._debug(
                f"Interface {iface} não recebeu reservas e --skip-delete está ativo; mantendo static-maps atuais"
            )
        total_mappings += len(entries)

    return total_mappings, interfaces_modified


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

    ipam_subnet_ids = _parse_ipam_subnet_ids()
    if not ipam_subnet_ids:
        jk._err(
            "Configure SUBNET_ID_MAP_JSON (ou SUBNET_ID_MAP/IPAM_SUBNETID_TO_ID) no .env para listar as sub-redes do phpIPAM a sincronizar."
        )
        return (0, 0, 1)

    ssh_settings = jk._load_ssh_settings()
    path_segments = get_config_path_segments()
    errors = 0
    remote_config = fetch_pfsense_config(path_segments, ssh_settings)
    if remote_config is None:
        jk._err("Não foi possível ler a configuração DHCP atual do pfSense; abortando para evitar sobrescrita.")
        return (0, 0, 1)

    interfaces_config = fetch_pfsense_config(["interfaces"], ssh_settings)
    if interfaces_config is None:
        jk._err("Não foi possível ler $config['interfaces'] no pfSense; necessário para localizar as redes de cada interface.")
        return (0, 0, 1)

    iface_networks = _build_iface_network_index(interfaces_config)
    if not iface_networks:
        jk._err("Nenhuma interface com IPv4 válido encontrada no pfSense; habilite DHCP nas VLANs desejadas antes de sincronizar.")
        return (0, 0, 1)

    config = remote_config

    iface_results: Dict[str, Dict[str, Any]] = {}
    processed_ifaces: Set[str] = set()
    subnet_network_cache: Dict[str, Optional[ipaddress.IPv4Network]] = {}

    for ipam_subnet in ipam_subnet_ids:
        rc, data = jk.ipam_get_addresses(base, token, str(ipam_subnet), verify_tls)
        if rc != 0 or data is None:
            errors += 1
            continue
        items = jk.build_items_from_ipam(data)

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
            jk._err(
                f"Não foi possível associar a sub-rede {ipam_subnet} a nenhuma interface do pfSense; confira o config.xml e as VLANs."
            )
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

    staticmaps_by_iface: Dict[str, List[Dict[str, Any]]] = {}
    for iface, result in iface_results.items():
        reservations = result.get("reservations") or []
        if reservations:
            staticmaps_by_iface[iface] = reservations
        elif delete_missing and result.get("delete"):
            staticmaps_by_iface[iface] = []

    total_reservations, interfaces_modified = _apply_staticmaps(
        config, staticmaps_by_iface, delete_missing
    )

    if dry_run:
        jk._info(
            f"DRY-RUN: {total_reservations} reservas seriam gravadas em {interfaces_modified} interfaces"
        )
        return (total_reservations, interfaces_modified, errors)

    if interfaces_modified <= 0:
        jk._info("Nenhuma alteração detectada — pfSense já estava sincronizado")
        return (total_reservations, interfaces_modified, errors)

    note = jk.env_first("PF_CONFIG_WRITE_NOTE", "PFSENSE_CONFIG_NOTE", default="Kea_IPAM_Sync") or "Kea_IPAM_Sync"
    success, changed = push_pfsense_config(config, path_segments, ssh_settings, note)
    if not success:
        errors += 1
        return (total_reservations, interfaces_modified, errors)

    if changed:
        jk._info("Configuração do pfSense atualizada e serviço recarregado")
    else:
        jk._info("pfSense já possuía a mesma configuração — sem reload adicional")

    return (total_reservations, interfaces_modified, errors)


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
