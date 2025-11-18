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


def _php_apply_staticmaps_code(payload_b64: str, note_b64: str) -> str:
    return _compact_php(
        f"""
        @ini_set('display_errors','0');
        require_once('/etc/inc/config.inc');
        @require_once('/etc/inc/util.inc');
        @require_once('/etc/inc/functions.inc');
        @require_once('/etc/inc/services.inc');

        function normalize_staticmap_entry($entry) {{
            if (!is_array($entry)) {{
                return null;
            }}
            $fields = array('mac','cid','ipaddr','hostname','descr');
            $normalized = array();
            foreach ($fields as $field) {{
                if (!array_key_exists($field, $entry)) {{
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
            if (!isset($normalized['ipaddr'])) {{
                return null;
            }}
            if (!isset($normalized['mac']) && !isset($normalized['cid'])) {{
                return null;
            }}
            return $normalized;
        }}

        function normalize_staticmap_entries($entries) {{
            $result = array();
            if (!is_array($entries)) {{
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
        if (!is_array($payload) || !isset($payload['ifaces']) || !is_array($payload['ifaces'])) {{
            echo base64_encode(json_encode(['ok'=>false,'error'=>'payload inválido']));
            exit(1);
        }}
        if (!isset($config['dhcpd']) || !is_array($config['dhcpd'])) {{
            $config['dhcpd'] = array();
        }}
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
            $delete = !empty($data['delete']);
            if (!isset($config['dhcpd'][$iface]) || !is_array($config['dhcpd'][$iface])) {{
                $config['dhcpd'][$iface] = array();
            }}
            $current = array();
            if (isset($config['dhcpd'][$iface]['staticmap']) && is_array($config['dhcpd'][$iface]['staticmap'])) {{
                $current = array_values($config['dhcpd'][$iface]['staticmap']);
            }}
            if ($delete && empty($entries)) {{
                if (!empty($current)) {{
                    unset($config['dhcpd'][$iface]['staticmap']);
                    $changed_ifaces[] = $iface;
                }}
                continue;
            }}
            if (empty($entries)) {{
                continue;
            }}
            if (!empty($current) && staticmaps_equal($current, $entries)) {{
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
        if (!isset($config['notifications']) || !is_array($config['notifications'])) {{
            $config['notifications'] = array();
        }}
        if (!isset($config['notifications']['smtp']) || !is_array($config['notifications']['smtp'])) {{
            $config['notifications']['smtp'] = array();
        }}
        write_config($note);
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
    payload = {"ifaces": staticmaps_by_iface}
    payload_b64 = _encode_b64_json(payload)
    note_b64 = _encode_b64_text(note)
    code = _php_apply_staticmaps_code(payload_b64, note_b64)
    rc, stdout, stderr = _run_php(code, ssh_settings)
    if rc != 0:
        message = stderr or stdout or f"php retornou código {rc}"
        jk._err(f"Falha ao atualizar o pfSense: {message}")
        return False, False, []
    response = _decode_base64_json(stdout)
    if not response:
        return True, True, list(staticmaps_by_iface.keys())
    if not response.get("ok", True):
        error_msg = response.get("error") or "erro desconhecido"
        jk._err(f"pfSense rejeitou atualização: {error_msg}")
        return False, False, []
    changed_ifaces = []
    if response.get("changed"):
        payload_ifaces = response.get("ifaces")
        if isinstance(payload_ifaces, list):
            changed_ifaces = [str(iface) for iface in payload_ifaces]
        else:
            changed_ifaces = list(staticmaps_by_iface.keys())
    return True, bool(response.get("changed", False)), changed_ifaces


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
