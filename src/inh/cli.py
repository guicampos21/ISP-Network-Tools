#
# Copyright (C) 2026 Guilherme Campos
# SPDX-License-Identifier: GPL-3.0-or-later
#
from __future__ import annotations

import getpass
import http.client
import importlib
import locale
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import quote


# These sources are designed to flag network ranges, policy blocks or
# infrastructure-wide reputation rather than just individual IPv4 abuse.
NETWORK_SCOPE_BLACKLISTS = {
    "all.spamrats.com",
    "badnets.spameatingmonkey.net",
    "bogons.cymru.com",
    "cidr.bl.mcafee.com",
    "dnsbl-2.uceprotect.net",
    "dnsbl-3.uceprotect.net",
    "netscan.rbl.blockedservers.com",
}

DIRECT_IP_BLACKLISTS = {
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "cbl.abuseat.org",
    "ix.dnsbl.manitu.net",
    "psbl.surriel.com",
    "spam.abuse.ch",
    "spam.spamrats.com",
    "dyna.spamrats.com",
    "noptr.spamrats.com",
    "dnsbl.sorbs.net",
}

CONSERVATIVE_SCAN_BLACKLISTS = DIRECT_IP_BLACKLISTS | NETWORK_SCOPE_BLACKLISTS

WHITELIST_SOURCES = {
    "_vouch.dwl.spamhaus.org",
    "hostkarma.junkemailfilter.com",
    "iddb.isipp.com",
    "nobl.junkemailfilter.com",
    "white.uribl.com",
}

CURRENT_SCAN_APPROACH = "conservative"

BLACKLIST_SEVERITY = {
    "zen.spamhaus.org": "muito alta",
    "bl.spamcop.net": "muito alta",
    "b.barracudacentral.org": "alta",
    "cbl.abuseat.org": "alta",
    "ix.dnsbl.manitu.net": "alta",
    "psbl.surriel.com": "alta",
    "spam.abuse.ch": "alta",
    "all.spamrats.com": "media",
    "spam.spamrats.com": "media",
    "dyna.spamrats.com": "media",
    "noptr.spamrats.com": "media",
    "dnsbl.sorbs.net": "media",
    "dul.pacifier.net": "media",
    "dnsbl-2.uceprotect.net": "media",
    "dnsbl-3.uceprotect.net": "media",
    "badnets.spameatingmonkey.net": "media",
    "netscan.rbl.blockedservers.com": "media",
    "bogons.cymru.com": "informacional",
    "cidr.bl.mcafee.com": "informacional",
}

BLACKLIST_SCOPE = {
    **{name: "ip" for name in DIRECT_IP_BLACKLISTS},
    **{name: "bloco" for name in NETWORK_SCOPE_BLACKLISTS},
}

BLACKLIST_DESCRIPTIONS = {
    "zen.spamhaus.org": "Conjunto Spamhaus para reputacao IP; cobre SBL, CSS, XBL e PBL.",
    "bl.spamcop.net": "Lista dinamica baseada em reportes e analise de spam recente.",
    "b.barracudacentral.org": "Reputacao Barracuda para emissores associados a spam.",
    "cbl.abuseat.org": "Indicadores de hosts comprometidos, proxies abertos e botnets.",
    "ix.dnsbl.manitu.net": "DNSBL focada em spam observado por infraestrutura Manitu.",
    "psbl.surriel.com": "Passive Spam Block List baseada em spamtraps.",
    "spam.abuse.ch": "Indicadores Abuse.ch relacionados a abuso e malware/spam.",
    "spam.spamrats.com": "SpamRATS para fontes observadas enviando spam.",
    "dyna.spamrats.com": "SpamRATS para faixas dinamicas ou hosts improprios para SMTP direto.",
    "noptr.spamrats.com": "SpamRATS para IPs sem PTR adequado.",
    "dnsbl.sorbs.net": "SORBS como evidencia complementar de reputacao.",
    "all.spamrats.com": "Visao agregada SpamRATS, aplicada como contexto de bloco/rede.",
    "badnets.spameatingmonkey.net": "Contexto de redes com reputacao negativa historica.",
    "bogons.cymru.com": "Identifica enderecos bogon ou espacos nao roteaveis.",
    "cidr.bl.mcafee.com": "Lista por faixa/CIDR, usada apenas como contexto de bloco.",
    "dnsbl-2.uceprotect.net": "UCEPROTECT nivel 2: reputacao em escopo de rede/provedor.",
    "dnsbl-3.uceprotect.net": "UCEPROTECT nivel 3: reputacao ampla de ASN/provedor.",
    "netscan.rbl.blockedservers.com": "Indicadores de rede associados a varredura/abuso.",
}

SEVERITY_RANK = {
    "informacional": 0,
    "baixa": 1,
    "media": 2,
    "alta": 3,
    "muito alta": 4,
}

SEVERITY_SCORE = {
    "informacional": 0,
    "baixa": 1,
    "media": 2,
    "alta": 4,
    "muito alta": 8,
}

DNSBL_ERROR_NETWORKS = ("127.255.255.0/24",)
BGP_TOOLS_WEBSITE_CACHE: dict[str, str] = {}
WHOIS_ASN_CACHE: dict[str, dict[str, object]] = {}
REACHABILITY_CACHE: dict[str, str] = {}
REPORT_BRAND = "ISP - Network Health"
INVENTORY_ALL_IPS_DEFAULT = False
RUN_CONTEXT: dict[str, object] = {}

BLACKLIST_FAMILY_MAP = {
    "b.barracudacentral.org": "barracuda",
    "bb.barracudacentral.org": "barracuda",
    "zen.spamhaus.org": "spamhaus",
    "sbl.spamhaus.org": "spamhaus",
    "xbl.spamhaus.org": "spamhaus",
    "pbl.spamhaus.org": "spamhaus",
    "sbl-xbl.spamhaus.org": "spamhaus",
    "bl.spamcop.net": "spamcop",
    "cbl.abuseat.org": "abuseat_cbl",
    "ix.dnsbl.manitu.net": "manitu",
    "psbl.surriel.com": "psbl",
    "spam.abuse.ch": "abuse_ch",
    "dnsbl.sorbs.net": "sorbs",
    "spam.spamrats.com": "spamrats",
    "dyna.spamrats.com": "spamrats",
    "noptr.spamrats.com": "spamrats",
    "all.spamrats.com": "spamrats",
    "dnsbl-2.uceprotect.net": "uceprotect",
    "dnsbl-3.uceprotect.net": "uceprotect",
    "badnets.spameatingmonkey.net": "spameatingmonkey",
    "netscan.rbl.blockedservers.com": "blockedservers",
    "bogons.cymru.com": "cymru",
    "cidr.bl.mcafee.com": "mcafee",
}

FAMILY_LABELS = {
    "barracuda": "Barracuda",
    "spamhaus": "Spamhaus",
    "spamcop": "SpamCop",
    "abuseat_cbl": "CBL",
    "manitu": "Manitu",
    "psbl": "PSBL",
    "abuse_ch": "Abuse.ch",
    "sorbs": "SORBS",
    "spamrats": "SpamRATS",
    "uceprotect": "UCEProtect",
    "spameatingmonkey": "SpamEatingMonkey",
    "blockedservers": "BlockedServers",
    "cymru": "Team Cymru",
    "mcafee": "McAfee",
}

CRITICAL_FAMILIES = {
    "spamhaus",
    "spamcop",
    "abuseat_cbl",
    "barracuda",
    "abuse_ch",
    "manitu",
    "psbl",
}


def _detect_system_language() -> str:
    for env_name in ("LC_ALL", "LANG", "LC_MESSAGES"):
        env_lang = (os.environ.get(env_name) or "").strip().lower()
        if not env_lang or env_lang in {"c", "c.utf-8", "posix"}:
            continue
        if "pt_br" in env_lang or env_lang.startswith("pt"):
            return "pt-BR"
        if env_lang.startswith("en"):
            return "en-US"
    try:
        locale.setlocale(locale.LC_ALL, "")
        locale_lang = (locale.getlocale()[0] or "").lower()
        if "pt_br" in locale_lang or locale_lang.startswith("pt"):
            return "pt-BR"
    except locale.Error:
        pass
    return "en-US"


CURRENT_UI_LANG = _detect_system_language()

LANGUAGE_NAMES = {
    "pt-BR": "Português (Brasil)",
    "en-US": "English (United States)",
}

SUPPORTED_INPUT_EN = (
    "domain, single IPv4, IPv4 CIDR block or ASN in ASxxxx format "
    "(e.g. example.com, 203.0.113.25, 203.0.113.0/28, AS15169)"
)

I18N = {
    "pt-BR": {
        "report_brand": "ISP - Network Health",
        "start_title": "ISP - Network Health",
        "start_subtitle": "Análise de reputação para domínio, IPv4, bloco CIDR IPv4 e ASN.",
        "accepted_inputs": "Entradas aceitas:",
        "flow_guided": "Fluxo guiado:",
        "flow_1": "1. Defina o alvo de análise",
        "flow_2": "2. Escolha a estratégia de consulta",
        "flow_3": "3. Opcionalmente habilite inventário completo de IPs",
        "flow_4": "4. Decida se deseja usar modo turbo",
        "prompt_inventory_all": "Inventariar todos os IPs individualmente no relatório? [s/N]: ",
        "prompt_target": "Alvo para análise: ",
        "prompt_approach": "Estratégia de consulta [1=essencial, 2=ampliada] [Enter=1]: ",
        "menu_domain": "Domínio: exemplo.com",
        "menu_ipv4": "IPv4: 203.0.113.25",
        "menu_block": "Bloco CIDR: 203.0.113.0/28",
        "menu_asn": "ASN: AS15169",
        "detected_language": "Idioma detectado: {current}. Manter idioma atual ou alternar para {other}? [Enter=manter / t=trocar]: ",
        "cancelled": "Operação cancelada pelo usuário.",
        "error_prefix": "Erro",
        "help_unavailable": "Ajuda detalhada indisponível.",
        "arg_description": "Consulta profissional de blacklists para domínio, IPv4, CIDR IPv4 ou ASN.",
        "arg_workers": "Quantidade máxima de consultas paralelas. 0 = automático.",
        "arg_boost": "Ativa o modo turbo com maior paralelismo e consumo de recursos.",
        "arg_approach": "Seleciona a estratégia de consulta: conservative=fontes mais críticas; aggressive=todas as fontes disponíveis.",
        "arg_report_type": "Mantido por compatibilidade. Esta versão sempre gera o relatório completo HTML.",
        "full_report": "Relatório completo",
        "developer_label": "Desenvolvedor",
        "metadata_title": "Metadados de execução",
        "metadata_lead": "Identificação do ambiente e da conta que executou a análise.",
        "meta_username": "Usuário",
        "meta_os": "Sistema operacional",
        "meta_language": "Idioma",
        "meta_started": "Início",
        "meta_finished": "Fim",
        "meta_duration": "Duração total",
        "meta_not_informed": "não informado",
        "html_title": "Relatório Executivo de Reputação de IP",
        "method_scope_auto": "Modo de scan: avaliação automática por escopo; listas de IP afetam IPs, listas de bloco afetam bloco/ASN e fontes informacionais ficam como contexto.",
        "method_dnsbl_codes": "Classificação: respostas DNSBL só contam quando retornam códigos loopback válidos; códigos 127.255.255.x são tratados como erro de consulta.",
        "method_asn_drop_scope": "ASN-DROP: lista de bloqueio em escopo ASN/rede; não marca todos os IPs como individualmente blacklistados.",
        "method_source_curation": "Curadoria de fontes: Spamhaus ZEN substitui consultas separadas a SBL/XBL/PBL; URIBL/SURBL/RHSBL e fontes obsoletas ficam fora do scan de IP.",
        "method_out_of_scope_sources": "Fontes fora do escopo IP: listas de URL/domínio/RHSBL, whitelists e duplicatas cobertas por Spamhaus ZEN.",
    },
    "en-US": {
        "report_brand": "ISP - Network Health",
        "start_title": "ISP - Network Health",
        "start_subtitle": "Reputation analysis for domains, IPv4, IPv4 CIDR blocks, and ASNs.",
        "accepted_inputs": "Accepted inputs:",
        "flow_guided": "Guided flow:",
        "flow_1": "1. Set the analysis target",
        "flow_2": "2. Choose the query approach",
        "flow_3": "3. Optionally enable full IP inventory",
        "flow_4": "4. Decide whether to use turbo mode",
        "prompt_inventory_all": "Inventory every IP individually in the report? [y/N]: ",
        "prompt_target": "Analysis target: ",
        "prompt_approach": "Query approach [1=essential, 2=expanded] [Enter=1]: ",
        "menu_domain": "Domain: example.com",
        "menu_ipv4": "IPv4: 203.0.113.25",
        "menu_block": "CIDR block: 203.0.113.0/28",
        "menu_asn": "ASN: AS15169",
        "detected_language": "Detected language: {current}. Keep current language or switch to {other}? [Enter=keep / s=switch]: ",
        "cancelled": "Operation cancelled by user.",
        "error_prefix": "Error",
        "help_unavailable": "Detailed help is unavailable.",
        "arg_description": "Professional blacklist querying for domain, IPv4, IPv4 CIDR, or ASN.",
        "arg_workers": "Maximum number of parallel queries. 0 = automatic.",
        "arg_boost": "Enables turbo mode with higher parallelism and resource usage.",
        "arg_approach": "Choose the query approach: conservative=curated critical sources; aggressive=all available sources.",
        "arg_report_type": "Kept for compatibility. This version always generates the complete HTML report.",
        "full_report": "Complete report",
        "developer_label": "Developer",
        "metadata_title": "Execution metadata",
        "metadata_lead": "Environment and account identification for the machine that executed the analysis.",
        "meta_username": "Username",
        "meta_os": "Operating system",
        "meta_language": "Language",
        "meta_started": "Started at",
        "meta_finished": "Finished at",
        "meta_duration": "Total duration",
        "meta_not_informed": "not informed",
        "html_title": "IP Reputation Executive Report",
        "method_scope_auto": "Scan mode: automatic scope evaluation; IP lists affect IPs, block lists affect block/ASN, and informational sources remain context only.",
        "method_dnsbl_codes": "Classification: DNSBL answers only count when they return valid loopback codes; 127.255.255.x codes are treated as query errors.",
        "method_asn_drop_scope": "ASN-DROP: ASN/network-scope blocklist signal; it does not mark every IP as individually blacklist-listed.",
        "method_source_curation": "Source curation: Spamhaus ZEN replaces separate SBL/XBL/PBL queries; URIBL/SURBL/RHSBL and obsolete sources stay out of the IP scan.",
        "method_out_of_scope_sources": "Sources outside IP scope: URL/domain/RHSBL lists, whitelists, and duplicates already covered by Spamhaus ZEN.",
    },
}


def tr(key: str, **kwargs) -> str:
    lang = kwargs.pop("lang", CURRENT_UI_LANG)
    value = I18N.get(lang, I18N["en-US"]).get(key, key)
    return value.format(**kwargs) if kwargs else value


def _summary_ui_lang(summary=None) -> str:
    if summary is not None:
        metadata = getattr(summary, "scan_metadata", {}) or {}
        language = str(metadata.get("ui_language") or "").strip()
        if language in I18N:
            return language
    runtime_language = str(RUN_CONTEXT.get("language") or "").strip()
    if runtime_language in I18N:
        return runtime_language
    return CURRENT_UI_LANG


def _prompt_language_preference() -> None:
    global CURRENT_UI_LANG
    if not sys.stdin.isatty():
        return
    current = CURRENT_UI_LANG
    other = "en-US" if current == "pt-BR" else "pt-BR"
    answer = clear_and_prompt(
        tr(
            "detected_language",
            current=LANGUAGE_NAMES[current],
            other=LANGUAGE_NAMES[other],
        )
    ).strip().lower()
    if answer in {"t", "trocar", "s", "switch", "y", "yes"}:
        CURRENT_UI_LANG = other


def _runtime_metadata(summary=None) -> dict[str, object]:
    started = RUN_CONTEXT.get("started_at")
    finished = datetime.now().astimezone()
    duration = None
    if isinstance(started, datetime):
        duration = round((finished - started).total_seconds(), 2)
    return {
        "username": str(RUN_CONTEXT.get("username") or tr("meta_not_informed")),
        "os": str(RUN_CONTEXT.get("os") or tr("meta_not_informed")),
        "language": CURRENT_UI_LANG,
        "started_at": started.isoformat() if isinstance(started, datetime) else tr("meta_not_informed"),
        "finished_at": finished.isoformat(),
        "duration_seconds": duration if duration is not None else tr("meta_not_informed"),
    }


def _load_original_module():
    return importlib.import_module("inh.core")


def _apply_blacklist_catalog(module) -> None:
    relevance = {}
    priority = {}
    for blacklist in ORIGINAL_BLACKLISTS:
        severity = _catalog_relevance(blacklist)
        if blacklist in WHITELIST_SOURCES:
            severity = "informacional"
        relevance[blacklist] = severity
        if severity != "informacional":
            priority[blacklist] = severity

    module.BLACKLIST_RELEVANCE = relevance
    module.BLACKLIST_PRIORITY = priority
    globals()["BLACKLIST_RELEVANCE"] = relevance
    globals()["BLACKLIST_PRIORITY"] = priority


def _selected_scan_blacklists() -> set[str]:
    if CURRENT_SCAN_APPROACH == "aggressive":
        return {
            name
            for name in ORIGINAL_BLACKLISTS
            if name not in WHITELIST_SOURCES
        }
    return set(CONSERVATIVE_SCAN_BLACKLISTS)


def _source_part(name: str) -> str:
    scope = _catalog_scope(name)
    if scope == "ip":
        return "direct"
    if scope == "bloco":
        return "network"
    return "informational"


def _catalog_scope(name: str) -> str:
    lowered = name.lower()
    if name in NETWORK_SCOPE_BLACKLISTS:
        return "bloco"
    if any(token in lowered for token in ("dnsbl-2.uceprotect", "dnsbl-3.uceprotect", "badnets", "bogons", "cidr.", "netscan", "netbl.", "l2.bbfh", "l3.bbfh", "l4.bbfh")):
        return "bloco"
    if any(token in lowered for token in ("uribl", "rhsbl", "surbl", "url", "domain", "fresh", "whois", "postmaster", "nomail", "badconf", "dob.")):
        return "informativo"
    if name in WHITELIST_SOURCES:
        return "informativo"
    return "ip"


def _catalog_relevance(name: str) -> str:
    if name in BLACKLIST_SEVERITY:
        return BLACKLIST_SEVERITY[name]
    scope = _catalog_scope(name)
    if scope == "informativo":
        return "informacional"
    if "spamhaus" in name:
        return "muito alta"
    if any(token in name for token in ("barracuda", "spamcop", "abuse", "uceprotect")):
        return "alta"
    return "media"


def _is_ipv4_literal(value: str) -> bool:
    try:
        _original.ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _valid_dnsbl_positive_answers(answers: list[str]) -> tuple[list[str], list[str]]:
    positives = []
    error_codes = []
    error_networks = [_original.ipaddress.ip_network(network) for network in DNSBL_ERROR_NETWORKS]

    for answer in answers:
        try:
            ip = _original.ipaddress.ip_address(answer)
        except ValueError:
            continue
        if ip.version != 4:
            continue
        if any(ip in network for network in error_networks):
            error_codes.append(answer)
            continue
        if ip.is_loopback and answer != "127.0.0.1":
            positives.append(answer)

    return positives, error_codes


def _ipv4_int(value: str) -> int | None:
    try:
        ip = _original.ipaddress.ip_address(value)
    except ValueError:
        return None
    if ip.version != 4:
        return None
    return int(ip)


def _format_ipv4_range(start: int, end: int) -> str:
    start_ip = str(_original.ipaddress.ip_address(start))
    end_ip = str(_original.ipaddress.ip_address(end))
    if start == end:
        return start_ip
    return f"{start_ip}-{end_ip}"


def _format_compact_date(value: str) -> str:
    value = value.strip()
    if not value or value == "-":
        return "-"
    if re.fullmatch(r"\d{8}", value):
        return f"{value[6:8]}/{value[4:6]}/{value[0:4]}"
    return value


def _ping_command_available() -> bool:
    return shutil.which("ping") is not None


def _first_present(mapping: dict[str, object], *keys: str) -> str:
    for key in keys:
        value = mapping.get(key)
        if value is None:
            continue
        if isinstance(value, (list, tuple)):
            for item in value:
                text = str(item).strip()
                if text and text != "-":
                    return text
            continue
        text = str(value).strip()
        if text and text != "-":
            return text
    return "-"


def _has_meaningful_value(value: object) -> bool:
    if value is None:
        return False
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    text = str(value).strip()
    return bool(text and text != "-")


def _whois_command_available() -> bool:
    return shutil.which("whois") is not None


def _parse_whois_key_values(text: str) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("%"):
            continue
        if ":" not in stripped:
            continue
        key, raw_value = stripped.split(":", 1)
        normalized_key = key.strip().lower()
        value = raw_value.strip()
        if not normalized_key or not value:
            continue
        values.setdefault(normalized_key, []).append(value)
    return values


def _fetch_asn_whois_profile(primary_asn: str) -> dict[str, object]:
    normalized = primary_asn.strip().upper()
    if not normalized:
        return {}
    if normalized in WHOIS_ASN_CACHE:
        return dict(WHOIS_ASN_CACHE[normalized])

    for loader in (
        _fetch_asn_whois_profile_from_command,
        _fetch_asn_whois_profile_from_rdap,
        _fetch_asn_whois_profile_from_socket,
    ):
        profile = loader(normalized)
        if profile:
            WHOIS_ASN_CACHE[normalized] = profile
            return dict(profile)

    WHOIS_ASN_CACHE[normalized] = {}
    return {}


def _normalize_parsed_asn_profile(parsed: dict[str, list[str]]) -> dict[str, object]:
    contact_handle = _first_present(parsed, "owner-c", "nic-hdl-br")
    return {
        "asn": _first_present(parsed, "aut-num"),
        "owner": _first_present(parsed, "owner"),
        "holder": _first_present(parsed, "owner"),
        "ownerid": _first_present(parsed, "ownerid"),
        "owner_id": _first_present(parsed, "ownerid"),
        "responsible": _first_present(parsed, "responsible"),
        "country": _first_present(parsed, "country"),
        "owner-c": _first_present(parsed, "owner-c"),
        "owner_c": _first_present(parsed, "owner-c"),
        "routing-c": _first_present(parsed, "routing-c"),
        "routing_c": _first_present(parsed, "routing-c"),
        "abuse-c": _first_present(parsed, "abuse-c"),
        "abuse_c": _first_present(parsed, "abuse-c"),
        "created": _first_present(parsed, "created"),
        "registered": _first_present(parsed, "created"),
        "changed": _first_present(parsed, "changed"),
        "contact_handle": contact_handle,
        "nic_hdl_br": _first_present(parsed, "nic-hdl-br"),
        "email": _first_present(parsed, "e-mail", "email"),
        "e-mail": _first_present(parsed, "e-mail", "email"),
        "contact_email": _first_present(parsed, "e-mail", "email"),
        "prefixes": parsed.get("inetnum", []),
    }


def _fetch_asn_whois_profile_from_command(normalized: str) -> dict[str, object]:
    if not _whois_command_available():
        return {}

    try:
        completed = subprocess.run(
            ["whois", normalized],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=12,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return {}

    output = completed.stdout or ""
    if not output.strip():
        return {}
    return _normalize_parsed_asn_profile(_parse_whois_key_values(output))


def _rdap_vcard_value(entity: dict[str, object], key_name: str) -> str:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return "-"
    for item in vcard[1]:
        if not isinstance(item, list) or len(item) < 4:
            continue
        if str(item[0]).lower() != key_name.lower():
            continue
        value = item[3]
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "-"


def _fetch_asn_whois_profile_from_rdap(normalized: str) -> dict[str, object]:
    asn_number = normalized.removeprefix("AS")
    if not asn_number.isdigit():
        return {}
    urls = [
        f"https://rdap.lacnic.net/rdap/autnum/{asn_number}",
    ]
    for url in urls:
        try:
            request_obj = _original.request.Request(
                url,
                headers={
                    "User-Agent": "INH ISP Network Health/1.0",
                    "Accept": "application/rdap+json, application/json",
                },
            )
            with _original.request.urlopen(request_obj, timeout=8) as response:
                payload = _original.json.loads(response.read().decode("utf-8", "ignore"))
        except OSError:
            continue
        except ValueError:
            continue

        if not isinstance(payload, dict):
            continue

        entities = payload.get("entities", [])
        registrant = {}
        if isinstance(entities, list):
            for entity in entities:
                if not isinstance(entity, dict):
                    continue
                roles = entity.get("roles", [])
                if isinstance(roles, list) and any(str(role).lower() in {"registrant", "abuse", "technical", "administrative"} for role in roles):
                    registrant = entity
                    break
            if not registrant:
                registrant = next((entity for entity in entities if isinstance(entity, dict)), {})

        events = payload.get("events", [])
        event_map: dict[str, str] = {}
        if isinstance(events, list):
            for event in events:
                if not isinstance(event, dict):
                    continue
                action = str(event.get("eventAction", "")).strip().lower()
                date = str(event.get("eventDate", "")).strip()
                if action and date:
                    event_map[action] = date[:10]

        remarks = payload.get("remarks", [])
        email = "-"
        if isinstance(remarks, list):
            for remark in remarks:
                if not isinstance(remark, dict):
                    continue
                for line in remark.get("description", []) or []:
                    text = str(line).strip()
                    if "@" in text:
                        email = text
                        break
                if email != "-":
                    break

        raw_country = str(payload.get("country") or registrant.get("country") or "").strip()
        rdap_profile = {
            "asn": normalized,
            "owner": str(payload.get("name") or payload.get("handle") or "").strip() or "-",
            "holder": str(payload.get("name") or payload.get("handle") or "").strip() or "-",
            "country": raw_country or "-",
            "ownerid": _rdap_vcard_value(registrant, "kind"),
            "responsible": _rdap_vcard_value(registrant, "fn"),
            "owner_c": str(registrant.get("handle") or "-"),
            "owner-c": str(registrant.get("handle") or "-"),
            "contact_handle": str(registrant.get("handle") or "-"),
            "contact_email": _rdap_vcard_value(registrant, "email") if _rdap_vcard_value(registrant, "email") != "-" else email,
            "email": _rdap_vcard_value(registrant, "email") if _rdap_vcard_value(registrant, "email") != "-" else email,
            "e-mail": _rdap_vcard_value(registrant, "email") if _rdap_vcard_value(registrant, "email") != "-" else email,
            "registered": event_map.get("registration", "-"),
            "created": event_map.get("registration", "-"),
            "changed": event_map.get("last changed", event_map.get("last update of rdap database", "-")),
        }
        if any(_has_meaningful_value(value) for value in rdap_profile.values()):
            return rdap_profile
    return {}


def _fetch_asn_whois_profile_from_socket(normalized: str) -> dict[str, object]:
    servers = ("whois.registro.br", "whois.lacnic.net", "whois.radb.net")
    query = f"{normalized}\r\n".encode("utf-8")
    for host in servers:
        try:
            with socket.create_connection((host, 43), timeout=8) as conn:
                conn.sendall(query)
                chunks = []
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    chunks.append(data)
        except OSError:
            continue
        output = b"".join(chunks).decode("utf-8", "replace")
        if not output.strip():
            continue
        profile = _normalize_parsed_asn_profile(_parse_whois_key_values(output))
        if any(_has_meaningful_value(value) for value in profile.values()):
            return profile
    return {}


def _detect_target_inventory_scope(value: str) -> str | None:
    candidate = value.strip()
    if not candidate:
        return None
    upper = candidate.upper()
    if re.fullmatch(r"AS\d+", upper):
        return "asn"
    try:
        network = _original.ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        return None
    if network.version == 4 and network.prefixlen < 24:
        return "large_block"
    return None


def _choose_full_inventory_mode(target: str) -> bool:
    scope = _detect_target_inventory_scope(target)
    if scope is None:
        return False
    answer = clear_and_prompt(
        tr("prompt_inventory_all")
    ).strip().lower()
    return answer in {"s", "sim", "y", "yes"}


def _terminal_half_width() -> int:
    terminal_width = shutil.get_terminal_size((120, 30)).columns
    half_width = max(44, terminal_width // 2)
    return min(half_width, 58)


def _boxed_lines(title: str, lines: list[str]) -> str:
    width = _terminal_half_width()
    inner = width - 4
    top = f"╭{'─' * (width - 2)}╮"
    bottom = f"╰{'─' * (width - 2)}╯"
    title_text = title[:inner]
    title_row = f"│ {title_text.ljust(inner)} │"
    body_rows = []
    for line in lines:
        wrapped = textwrap.wrap(line, width=inner) or [""]
        for part in wrapped:
            body_rows.append(f"│ {part.ljust(inner)} │")
    return "\n".join([top, title_row, *body_rows, bottom])


def _print_start_menu() -> None:
    menu = _boxed_lines(
        tr("start_title"),
        [
            tr("start_subtitle"),
            "",
            tr("accepted_inputs"),
            tr("menu_domain"),
            tr("menu_ipv4"),
            tr("menu_block"),
            tr("menu_asn"),
            "",
            tr("flow_guided"),
            tr("flow_1"),
            tr("flow_2"),
            tr("flow_3"),
            tr("flow_4"),
        ],
    )
    print(menu)


def _compress_ipv4_values(values: list[str]) -> list[str]:
    numeric_values = sorted({value for value in (_ipv4_int(str(item)) for item in values) if value is not None})
    if not numeric_values:
        return []

    ranges: list[str] = []
    start = prev = numeric_values[0]
    for value in numeric_values[1:]:
        if value == prev + 1:
            prev = value
            continue
        ranges.append(_format_ipv4_range(start, prev))
        start = prev = value
    ranges.append(_format_ipv4_range(start, prev))
    return ranges


def _compress_inventory_rows_to_ranges(rows) -> list[str]:
    ips = [
        str(row.get("ip"))
        for row in rows
        if isinstance(row, dict) and row.get("status") in {"very_high", "high", "medium"}
    ]
    return _compress_ipv4_values(ips)


def _compress_group_ips(group) -> list[str]:
    ips = group.get("ips", [])
    if not isinstance(ips, list):
        return ips
    return _compress_ipv4_values([str(item) for item in ips])


def _compress_blacklist_groups(summary) -> None:
    groups = getattr(summary, "blacklist_groups", None)
    if not isinstance(groups, list):
        return

    compressed_groups = []
    for group in groups:
        if not isinstance(group, dict):
            compressed_groups.append(group)
            continue
        updated = dict(group)
        updated["ips"] = _compress_group_ips(updated)
        compressed_groups.append(updated)
    summary.blacklist_groups = compressed_groups


def _patched_compress_ip_ranges(rows) -> list[str]:
    return _compress_inventory_rows_to_ranges(rows)


def _patched_execute_task(task):
    if task.query_mode == "asn_drop":
        return _original_execute_task(task)

    started = _original.time.monotonic()
    answers, status = _original.run_dig(task.query_name)
    duration_ms = int((_original.time.monotonic() - started) * 1000)

    if status == "timeout":
        return CheckResult(task=task, status="timeout", answers=[], duration_ms=duration_ms)
    if status != "ok":
        return CheckResult(task=task, status="error", answers=answers, duration_ms=duration_ms)

    positive_answers, error_codes = _valid_dnsbl_positive_answers(answers)
    if error_codes:
        return CheckResult(task=task, status="error", answers=error_codes, duration_ms=duration_ms)
    if not positive_answers:
        return CheckResult(task=task, status="not_listed", answers=[], duration_ms=duration_ms)
    if task.blacklist in WHITELIST_SOURCES:
        return CheckResult(task=task, status="whitelisted", answers=positive_answers, duration_ms=duration_ms)

    return CheckResult(task=task, status="listed", answers=positive_answers, duration_ms=duration_ms)


def _set_scan_scope(module) -> None:
    _apply_blacklist_catalog(module)

    allowed = _selected_scan_blacklists()
    selected = [name for name in ORIGINAL_BLACKLISTS if name in allowed]

    if not selected:
        raise RuntimeError("Nenhuma blacklist disponivel para o modo selecionado.")

    module.BLACKLISTS = selected
    globals()["BLACKLISTS"] = selected


def _severity_for(name: str) -> str:
    return BLACKLIST_RELEVANCE.get(name, _catalog_relevance(name))


def _blacklist_family(name: str) -> str:
    if name in BLACKLIST_FAMILY_MAP:
        return BLACKLIST_FAMILY_MAP[name]
    parts = [part for part in name.lower().split(".") if part]
    if len(parts) >= 2:
        return re.sub(r"[^a-z0-9]+", "_", parts[-2]) or re.sub(r"[^a-z0-9]+", "_", name.lower())
    return re.sub(r"[^a-z0-9]+", "_", name.lower())


def _family_label(family: str) -> str:
    return FAMILY_LABELS.get(family, family.replace("_", " ").title())


def _risk_display_label(status: str) -> str:
    labels = {
        "very_high": "Muito alto",
        "high": "Alto",
        "medium": "Moderado",
        "informational": "Informacional",
        "clean": "Sem risco",
        "timeout": "Nao concluido",
        "low": "Baixo",
        "none": "Sem risco",
    }
    return labels.get(status, status)


def _source_type_label(source_type: str) -> str:
    return {
        "direct": "direct",
        "network": "network",
        "informational": "informational",
    }.get(source_type, source_type)


def _result_returned_code(result: CheckResult) -> str:
    if result.answers:
        return ", ".join(result.answers)
    if result.status == "timeout":
        return "timeout"
    if result.status == "error":
        return "error"
    return "-"


def _severity_to_risk(severity: str) -> str:
    if severity == "muito alta":
        return "Muito alto"
    if severity in {"muito alta", "alta"}:
        return "Alto"
    if severity == "media":
        return "Moderado"
    if severity == "baixa":
        return "Baixo"
    return "Sem risco"


def _risk_status_from_hits(relevant_hits: list[str], informational_hits: list[str], has_block_context: bool) -> str:
    severities = [_severity_for(name) for name in relevant_hits]
    high_families = {
        _blacklist_family(name)
        for name in relevant_hits
        if _severity_for(name) == "alta"
    }
    very_high_count = sum(1 for severity in severities if severity == "muito alta")
    high_count = sum(1 for severity in severities if severity == "alta")
    medium_count = sum(1 for severity in severities if severity == "media")

    if very_high_count or len(high_families) >= 2:
        return "very_high"
    if high_count >= 1 or medium_count >= 3 or (medium_count >= 1 and has_block_context):
        return "high"
    if medium_count >= 1:
        return "medium"
    if informational_hits:
        return "informational"
    return "clean"


def _risk_level_from_statuses(statuses: set[str], asn_drop_listed: bool) -> str:
    if asn_drop_listed or "very_high" in statuses:
        return "Muito alto"
    if "high" in statuses:
        return "Alto"
    if "medium" in statuses:
        return "Moderado"
    if "informational" in statuses:
        return "Baixo"
    return "Sem risco"


def _block_targets_by_ip(results: list[CheckResult]) -> dict[str, set[str]]:
    block_targets: dict[str, set[str]] = {}
    for result in results:
        if result.status != "listed" or result.task.target_kind != "block":
            continue
        target = result.task.target_value
        try:
            network = _original.ipaddress.ip_network(target, strict=False)
        except ValueError:
            continue
        for row_ip in _iter_result_ips(results):
            try:
                ip = _original.ipaddress.ip_address(row_ip)
            except ValueError:
                continue
            if ip in network:
                block_targets.setdefault(row_ip, set()).add(target)
    return block_targets


def _block_results_by_ip(results: list[CheckResult], statuses: set[str]) -> dict[str, list[CheckResult]]:
    mapping: dict[str, list[CheckResult]] = {}
    ip_values = sorted(_iter_result_ips(results))
    for result in results:
        if result.status not in statuses:
            continue
        if result.task.target_kind == "ip":
            if _source_part(result.task.blacklist) == "network":
                mapping.setdefault(result.task.target_value, []).append(result)
            continue
        if result.task.target_kind != "block":
            continue
        try:
            network = _original.ipaddress.ip_network(result.task.target_value, strict=False)
        except ValueError:
            continue
        for ip_value in ip_values:
            try:
                if _original.ipaddress.ip_address(ip_value) in network:
                    mapping.setdefault(ip_value, []).append(result)
            except ValueError:
                continue
    return mapping


def _timeout_error_results_by_ip(results: list[CheckResult]) -> dict[str, list[CheckResult]]:
    mapping: dict[str, list[CheckResult]] = {}
    block_mapping = _block_results_by_ip(results, {"timeout", "error"})
    for ip_value, entries in block_mapping.items():
        mapping.setdefault(ip_value, []).extend(entries)
    for result in results:
        if result.status not in {"timeout", "error"} or result.task.target_kind != "ip":
            continue
        mapping.setdefault(result.task.target_value, []).append(result)
    return mapping


def _hit_details_from_results(results: list[CheckResult], source_type: str) -> list[dict[str, object]]:
    details = []
    for result in results:
        family = _blacklist_family(result.task.blacklist)
        details.append(
            {
                "blacklist": result.task.blacklist,
                "returned_code": _result_returned_code(result),
                "severity": _severity_for(result.task.blacklist),
                "family": family,
                "family_label": _family_label(family),
                "source_type": source_type,
                "delist_url": _removal_url_for_blacklist(result.task.blacklist, result.task.target_value),
            }
        )
    return details


def _highest_severity(details: list[dict[str, object]]) -> str:
    if not details:
        return "none"
    return max((str(item["severity"]) for item in details), key=lambda severity: SEVERITY_RANK.get(severity, -1))


def _ip_confidence(
    risk_level: str,
    timeout_count: int,
    error_count: int,
    unique_families_count: int,
    has_very_high_source: bool,
) -> str:
    degraded = timeout_count + error_count
    if risk_level == "timeout":
        return "inconclusive" if degraded >= 2 else "low"
    if risk_level == "very_high":
        return "high" if has_very_high_source or unique_families_count >= 2 else "medium_high"
    if risk_level == "high":
        return "medium_high"
    if risk_level == "medium":
        return "medium"
    if risk_level == "informational":
        return "low"
    if degraded:
        return "medium"
    return "high"


def _ip_risk_reason(
    risk_level: str,
    direct_details: list[dict[str, object]],
    network_details: list[dict[str, object]],
    informational_details: list[dict[str, object]],
    timeout_results: list[CheckResult],
    error_results: list[CheckResult],
) -> str:
    direct_high = [item for item in direct_details if item["severity"] == "alta"]
    direct_very_high = [item for item in direct_details if item["severity"] == "muito alta"]
    direct_medium = [item for item in direct_details if item["severity"] == "media"]
    high_families = sorted({_family_label(str(item["family"])) for item in direct_high})
    if risk_level == "very_high":
        if direct_very_high:
            return f"Classificado como very_high porque possui hit em fonte de severidade muito alta: {direct_very_high[0]['blacklist']}."
        if len(high_families) >= 2:
            return f"Classificado como very_high porque possui hits high em famílias independentes: {', '.join(high_families)}."
        if network_details and any(str(item["family"]) in CRITICAL_FAMILIES for item in direct_high):
            return "Classificado como very_high porque combina fonte direct crítica de severidade alta com contexto de rede relevante."
    if risk_level == "high":
        if direct_high:
            grouped: dict[str, int] = {}
            for item in direct_high:
                label = _family_label(str(item["family"]))
                grouped[label] = grouped.get(label, 0) + 1
            repeated = [f"{label}" for label, count in grouped.items() if count >= 2]
            if repeated:
                return f"Classificado como high porque possui {len(direct_high)} hits de severidade alta na mesma família {', '.join(repeated)}."
            return f"Classificado como high porque possui hit direct de severidade alta em {direct_high[0]['blacklist']}."
        if len(direct_medium) >= 3:
            return "Classificado como high porque possui 3 ou mais hits de severidade média."
        if direct_medium and network_details:
            return "Classificado como high porque combina hit de severidade média com contexto de rede relevante."
    if risk_level == "medium":
        return "Classificado como medium porque possui hit de severidade média sem contexto adicional forte."
    if risk_level == "informational":
        return "Classificado como informational porque apareceu apenas em fontes informacionais."
    if risk_level == "timeout":
        return "Classificado como timeout porque não houve hit relevante, mas parte das consultas falhou por timeout ou erro."
    return "Classificado como clean porque não houve evidência relevante de listagem."


def _analyze_ip_results(
    ip_value: str,
    direct_results: list[CheckResult],
    network_results: list[CheckResult],
    informational_results: list[CheckResult],
    timeout_results: list[CheckResult],
    error_results: list[CheckResult],
) -> dict[str, object]:
    direct_details = _hit_details_from_results(direct_results, "direct")
    network_details = _hit_details_from_results(network_results, "network")
    informational_details = _hit_details_from_results(informational_results, "informational")
    all_hit_details = [*direct_details, *network_details, *informational_details]
    unique_blacklists = sorted({str(item["blacklist"]) for item in all_hit_details})
    unique_family_keys = sorted({str(item["family"]) for item in all_hit_details})
    unique_family_labels = [_family_label(key) for key in unique_family_keys]
    highest_severity = _highest_severity(all_hit_details)
    has_very_high_source = any(str(item["severity"]) == "muito alta" for item in direct_details)
    has_high_source = any(str(item["severity"]) == "alta" for item in direct_details)
    has_network_context = bool(network_details)
    has_informational_only = bool(informational_details) and not direct_details and not network_details
    high_families = {
        str(item["family"])
        for item in direct_details
        if str(item["severity"]) == "alta"
    }
    medium_count = sum(1 for item in direct_details if str(item["severity"]) == "media")
    critical_high = any(str(item["family"]) in CRITICAL_FAMILIES for item in direct_details if str(item["severity"]) == "alta")

    if has_very_high_source:
        risk_level = "very_high"
    elif len(high_families) >= 2:
        risk_level = "very_high"
    elif has_network_context and critical_high:
        risk_level = "very_high"
    elif has_high_source:
        risk_level = "high"
    elif medium_count >= 3:
        risk_level = "high"
    elif medium_count >= 1 and has_network_context:
        risk_level = "high"
    elif medium_count >= 1:
        risk_level = "medium"
    elif has_informational_only:
        risk_level = "informational"
    elif timeout_results or error_results:
        risk_level = "timeout"
    else:
        risk_level = "clean"

    timeout_sources = sorted({result.task.blacklist for result in timeout_results})
    error_sources = sorted({result.task.blacklist for result in error_results})
    return {
        "ip": ip_value,
        "risk_level": risk_level,
        "risk_label": _risk_display_label(risk_level),
        "risk_reason": _ip_risk_reason(
            risk_level,
            direct_details,
            network_details,
            informational_details,
            timeout_results,
            error_results,
        ),
        "confidence": _ip_confidence(
            risk_level,
            len(timeout_results),
            len(error_results),
            len(unique_family_keys),
            has_very_high_source,
        ),
        "direct_hits_count": len(direct_details),
        "network_hits_count": len(network_details),
        "informational_hits_count": len(informational_details),
        "dnsbl_occurrences_count": len(all_hit_details),
        "unique_blacklists_count": len(unique_blacklists),
        "unique_families_count": len(unique_family_keys),
        "affected_families": unique_family_labels,
        "affected_family_keys": unique_family_keys,
        "highest_severity": highest_severity,
        "has_very_high_source": has_very_high_source,
        "has_high_source": has_high_source,
        "has_network_context": has_network_context,
        "has_informational_only": has_informational_only,
        "has_timeout": bool(timeout_results or error_results),
        "timeout_sources": timeout_sources,
        "error_sources": error_sources,
        "hits": all_hit_details,
        "relevant": sorted({str(item["blacklist"]) for item in [*direct_details, *network_details]}),
        "informational": sorted({str(item["blacklist"]) for item in informational_details}),
        "risk_count": sum(SEVERITY_SCORE.get(str(item["severity"]), 0) for item in [*direct_details, *network_details]),
        "status": risk_level,
    }


def _report_confidence(
    report_risk_level: str,
    affected_families_count: int,
    has_critical_family_hits: bool,
    timeout_ratio: float,
    affected_count: int,
) -> str:
    if affected_count == 0 and timeout_ratio >= 0.2:
        return "inconclusive"
    if timeout_ratio >= 0.15:
        return "medium"
    if report_risk_level == "very_high":
        return "high"
    if report_risk_level == "high":
        return "high" if affected_families_count >= 2 else "medium_high"
    if report_risk_level == "medium":
        return "medium"
    if report_risk_level == "low":
        return "medium"
    return "high" if affected_count == 0 else "medium"


def _analyze_report_risk(summary, results: list[CheckResult]) -> dict[str, object]:
    rows = [row for row in getattr(summary, "inventory_rows", []) or [] if _ipv4_int(str(row.get("ip", ""))) is not None]
    total_ips = max(1, int(summary.unique_ips_scanned or len(rows) or 1))
    very_high_rows = [row for row in rows if row.get("status") == "very_high"]
    high_rows = [row for row in rows if row.get("status") == "high"]
    medium_rows = [row for row in rows if row.get("status") == "medium"]
    informational_rows = [row for row in rows if row.get("status") == "informational"]
    timeout_rows = [row for row in rows if row.get("status") == "timeout"]
    affected_rows = [row for row in rows if row.get("status") in {"very_high", "high", "medium"}]
    affected_families = sorted({
        family
        for row in affected_rows
        for family in row.get("affected_families", [])
    })
    affected_family_keys = sorted({
        family
        for row in affected_rows
        for family in row.get("affected_family_keys", [])
    })
    critical_family_hits = any(family in CRITICAL_FAMILIES for family in affected_family_keys)
    affected_ratio = len(affected_rows) / total_ips
    timeout_sources = sorted({result.task.blacklist for result in results if result.status == "timeout"})
    error_sources = sorted({result.task.blacklist for result in results if result.status == "error"})
    timeout_ratio = (summary.timeout_results + summary.error_results) / max(1, summary.total_checks)
    has_network_scope_hits = bool(getattr(summary, "network_scope_listed", False))

    if summary.asn_drop_listed:
        report_risk_level = "very_high"
    elif very_high_rows:
        if len(very_high_rows) >= 1 and (len(affected_family_keys) >= 2 or affected_ratio >= 0.05 or critical_family_hits):
            report_risk_level = "very_high"
        else:
            report_risk_level = "high"
    elif has_network_scope_hits and (high_rows or affected_ratio >= 0.1):
        report_risk_level = "very_high"
    elif high_rows:
        report_risk_level = "high"
    elif medium_rows:
        report_risk_level = "medium"
    elif informational_rows:
        report_risk_level = "low"
    else:
        report_risk_level = "none"

    reasons: list[str] = []
    if summary.asn_drop_listed:
        reasons.extend([
            "O ASN foi encontrado em ASN-DROP.",
            "ASN-DROP tem impacto crítico no risco geral.",
            "Classificação geral definida como Muito Alto independentemente da quantidade de IPs individuais listados.",
        ])
    else:
        reasons.append(f"{len(affected_rows)} de {total_ips} IPs possuem hits relevantes diretos.")
        if affected_families:
            if len(affected_families) == 1:
                reasons.append(f"As ocorrências estão concentradas em uma única família DNSBL: {affected_families[0]}.")
            else:
                reasons.append(f"Foram encontrados hits relevantes em múltiplas famílias independentes: {', '.join(affected_families)}.")
        if has_network_scope_hits:
            reasons.append("Houve ocorrência em listas de escopo de rede, bloco ou ASN.")
        else:
            reasons.append("Não houve ocorrência em listas de escopo de rede, bloco ou ASN.")
        if informational_rows and not affected_rows:
            reasons.append("Foram encontrados apenas sinais informacionais.")
        if report_risk_level == "very_high":
            reasons.append("Classificação geral definida como Muito Alto devido à dispersão dos hits ou à presença de fontes críticas.")
        elif report_risk_level == "high":
            reasons.append("Classificação geral definida como Alto, pois há impacto relevante em IPs individuais sem evidência de comprometimento amplo do ASN.")
        elif report_risk_level == "medium":
            reasons.append("Classificação geral definida como Moderado, pois há evidência relevante, mas com impacto ainda limitado.")
        elif report_risk_level == "low":
            reasons.append("Classificação geral definida como Baixo, pois os sinais encontrados são apenas informacionais ou fracos.")
        else:
            reasons.append("Classificação geral definida como Sem risco, pois não houve evidência relevante.")
    if timeout_sources or error_sources:
        reasons.append(
            f"A confiança do resultado foi ajustada por {len(timeout_sources)} fontes com timeout e {len(error_sources)} fontes com erro."
        )

    return {
        "report_risk_level": report_risk_level,
        "report_risk_label": _risk_display_label(report_risk_level),
        "report_confidence": _report_confidence(
            report_risk_level,
            len(affected_family_keys),
            critical_family_hits,
            timeout_ratio,
            len(affected_rows),
        ),
        "report_risk_reason": reasons,
        "affected_ips_count": len(affected_rows),
        "affected_ips_ratio": round(affected_ratio, 6),
        "very_high_ips_count": len(very_high_rows),
        "high_ips_count": len(high_rows),
        "medium_ips_count": len(medium_rows),
        "informational_ips_count": len(informational_rows),
        "timeout_ips_count": len(timeout_rows),
        "dnsbl_occurrences_count": sum(int(row.get("dnsbl_occurrences_count", 0)) for row in rows),
        "unique_blacklists_count": len({
            name
            for row in rows
            for name in row.get("relevant", []) + row.get("informational", [])
        }),
        "unique_families_count": len(affected_family_keys),
        "affected_families": affected_families,
        "direct_hits_count": sum(int(row.get("direct_hits_count", 0)) for row in rows),
        "network_hits_count": sum(int(row.get("network_hits_count", 0)) for row in rows),
        "informational_hits_count": sum(int(row.get("informational_hits_count", 0)) for row in rows),
        "asn_drop_status": "listed" if summary.asn_drop_listed else "not_listed",
        "has_asn_drop": bool(summary.asn_drop_listed),
        "has_network_scope_hits": has_network_scope_hits,
        "has_critical_family_hits": critical_family_hits,
        "timeout_sources_count": len(timeout_sources),
        "error_sources_count": len(error_sources),
    }


def _asn_drop_result(results: list[CheckResult]) -> CheckResult | None:
    return next((result for result in results if result.task.query_mode == "asn_drop"), None)


def _asn_drop_detail_line(result: CheckResult | None) -> str | None:
    if result is None:
        return None
    if result.status == "listed":
        details = "; ".join(result.answers) if result.answers else "registro encontrado"
        return f"ASN-DROP: listado - {details}"
    if result.status in {"timeout", "error"}:
        return f"ASN-DROP: consulta nao concluida ({result.status})"
    return "ASN-DROP: nao listado"


def _asn_drop_status_fields(result: CheckResult | None) -> tuple[str, str]:
    if result is None:
        return "Nao aplicavel", "Nao houve consulta ASN-DROP para este tipo de alvo."
    if result.status == "listed":
        details = "; ".join(result.answers) if result.answers else "registro encontrado"
        return "Listado", details
    if result.status in {"timeout", "error"}:
        return "Nao concluido", f"Consulta ASN-DROP retornou {result.status}."
    return "Nao listado", "Nenhum registro ASN-DROP encontrado."


def _iter_result_ips(results: list[CheckResult]) -> set[str]:
    return {
        result.task.target_value
        for result in results
        if result.task.target_kind == "ip"
    }


def _inventory_status_label(row: dict[str, object]) -> str:
    status = row.get("status")
    label = _risk_display_label(str(status if status is not None else "clean")).replace("Sem risco", "Limpo")
    if str(status) == "timeout":
        return "Nao listado"
    return label


def _patched_risk_badge_class(risk_level: str) -> str:
    if risk_level in {"Muito alto", "Alto"}:
        return "risk-high"
    if risk_level == "Moderado":
        return "risk-medium"
    if risk_level in {"Baixo", "Sem risco"}:
        return "risk-low"
    return "risk-none"


def _direct_inventory_rows_from_results(results: list[CheckResult]) -> list[dict[str, object]]:
    direct_by_ip: dict[str, list[CheckResult]] = {}
    network_by_ip = _block_results_by_ip(results, {"listed"})
    informational_by_ip: dict[str, list[CheckResult]] = {}
    degraded_by_ip = _timeout_error_results_by_ip(results)
    for result in results:
        if result.status != "listed" or result.task.target_kind != "ip":
            continue
        source_type = _source_part(result.task.blacklist)
        if source_type == "direct":
            direct_by_ip.setdefault(result.task.target_value, []).append(result)
        elif source_type == "informational":
            informational_by_ip.setdefault(result.task.target_value, []).append(result)

    rows: list[dict[str, object]] = []
    for ip_value in sorted(
        set(direct_by_ip) | set(network_by_ip) | set(informational_by_ip) | set(degraded_by_ip),
        key=lambda value: (_ipv4_int(value) is None, _ipv4_int(value) or value),
    ):
        rows.append(
            _analyze_ip_results(
                ip_value,
                direct_by_ip.get(ip_value, []),
                network_by_ip.get(ip_value, []),
                informational_by_ip.get(ip_value, []),
                [result for result in degraded_by_ip.get(ip_value, []) if result.status == "timeout"],
                [result for result in degraded_by_ip.get(ip_value, []) if result.status == "error"],
            )
        )
    return rows


def _direct_only_risk_level(results: list[CheckResult]) -> str:
    statuses = {str(row.get("status")) for row in _direct_inventory_rows_from_results(results)}
    if not statuses:
        return "Sem risco"
    if "very_high" in statuses:
        return "Muito alto"
    if "high" in statuses:
        return "Alto"
    if "medium" in statuses:
        return "Moderado"
    return "Sem risco"


def _part_results(results: list[CheckResult], part: str) -> list[CheckResult]:
    selected: list[CheckResult] = []
    for result in results:
        if result.status != "listed":
            continue
        if result.task.query_mode == "asn_drop":
            if part == "asn_drop":
                selected.append(result)
            continue

        source_part = _source_part(result.task.blacklist)
        if part == "direct" and source_part == "direct" and result.task.target_kind == "ip":
            selected.append(result)
        elif part == "network" and source_part == "network":
            selected.append(result)
        elif part == "informational" and source_part == "informational":
            selected.append(result)
    return selected


def _block_target_for_ip(ip_value: str, metadata: dict[str, object]) -> str:
    prefixes = metadata.get("prefixes", [])
    try:
        ip = _original.ipaddress.ip_address(ip_value)
    except ValueError:
        return str(metadata.get("primary_prefix") or ip_value)

    for prefix in prefixes:
        try:
            network = _original.ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            continue
        if ip in network:
            return str(network)

    return str(metadata.get("primary_prefix") or ip_value)


def _find_website_value(value) -> str:
    if isinstance(value, str):
        lowered = value.lower()
        if lowered.startswith(("http://", "https://", "www.")):
            return value
        return "-"
    if isinstance(value, dict):
        for key in ("website", "url", "homepage"):
            found = _find_website_value(value.get(key))
            if found != "-":
                return found
        for key, nested in value.items():
            if str(key).lower() in {"remarks", "entities", "vcardarray", "links", "events"}:
                found = _find_website_value(nested)
                if found != "-":
                    return found
    if isinstance(value, (list, tuple)):
        for item in value:
            found = _find_website_value(item)
            if found != "-":
                return found
    return "-"


def _is_registry_or_policy_url(value: str) -> bool:
    lowered = value.lower().strip()
    blocked_fragments = (
        "registro.br/upp",
        "registro.br/termos",
        "registro.br/whois",
        "rdap",
        "lacnic.net",
        "arin.net",
        "ripe.net",
        "apnic.net",
        "afrinic.net",
        "peeringdb.com",
        "bgp.tools",
    )
    return any(fragment in lowered for fragment in blocked_fragments)


def _normalize_website(value: str) -> str:
    value = value.strip().rstrip(".,);")
    if not value:
        return "-"
    if value.startswith("www."):
        value = f"http://{value}"
    if not value.lower().startswith(("http://", "https://")):
        return "-"
    if _is_registry_or_policy_url(value):
        return "-"
    return value


def _fetch_bgp_tools_website(primary_asn: str) -> str:
    normalized = primary_asn.upper().removeprefix("AS")
    if not normalized:
        return "-"
    if normalized in BGP_TOOLS_WEBSITE_CACHE:
        return BGP_TOOLS_WEBSITE_CACHE[normalized]

    url = f"https://bgp.tools/as/{normalized}"
    try:
        request_obj = _original.request.Request(
            url,
            headers={
                "User-Agent": "INH ISP Network Health/1.0",
                "Accept": "text/html,application/xhtml+xml",
            },
        )
        with _original.request.urlopen(request_obj, timeout=8) as response:
            page = response.read().decode("utf-8", "ignore")
    except OSError:
        return "-"

    patterns = (
        r"(?is)Website\s*<a[^>]+href=[\"']([^\"']+)[\"']",
        r"(?is)<dt[^>]*>\s*Website\s*</dt>\s*<dd[^>]*>.*?<a[^>]+href=[\"']([^\"']+)[\"']",
        r"(?is)website screenshot for\s+(https?://[^\"'<>\s]+)",
    )
    for pattern in patterns:
        match = re.search(pattern, page)
        if match:
            website = _normalize_website(_original.html.unescape(match.group(1)))
            if website != "-":
                BGP_TOOLS_WEBSITE_CACHE[normalized] = website
                return website

    BGP_TOOLS_WEBSITE_CACHE[normalized] = "-"
    return "-"


def _profile_website(profile: dict[str, object]) -> str:
    raw_website = str(profile.get("website", "-"))
    website = _normalize_website(raw_website)
    if website != "-":
        return website
    fallback = _find_website_value(profile)
    return _normalize_website(fallback)


def _patched_build_asn_box_lines(primary_asn: str) -> list[str]:
    if primary_asn == "-":
        return [
            "ASN principal: -",
            "Titular: -",
            "Data de registro: -",
            "Network status: -",
            "Prefixos originados: -",
            "Upstreams: -",
            "Site: -",
        ]

    profile = dict(fetch_asn_profile(primary_asn))
    profile.update({k: v for k, v in _fetch_asn_whois_profile(primary_asn).items() if _has_meaningful_value(v)})
    upstreams = profile.get("upstreams", [])
    upstream_text = ", ".join(str(item) for item in upstreams[:4]) if upstreams else "-"
    website = _fetch_bgp_tools_website(primary_asn)
    if website == "-":
        website = _profile_website(profile)

    return [
        f"ASN principal: {profile.get('asn', primary_asn)}",
        f"Titular: {profile.get('holder', '-')}",
        f"Data de registro: {profile.get('registered', '-')}",
        f"Network status: {profile.get('network_status', '-')}",
        f"Prefixos originados: {profile.get('originated_prefixes', '-')}",
        f"Upstreams: {upstream_text}",
        f"Site: {website or '-'}",
    ]


def _asn_summary_data(summary) -> list[tuple[str, str]]:
    profile = {}
    primary_asn = str(getattr(summary, "primary_asn", "-") or "-")
    if primary_asn != "-":
        try:
            profile = dict(fetch_asn_profile(primary_asn))
        except OSError:
            profile = {}
        profile.update({k: v for k, v in _fetch_asn_whois_profile(primary_asn).items() if _has_meaningful_value(v)})

    metadata = getattr(summary, "scan_metadata", {}) or {}
    prefixes = [
        str(prefix).strip()
        for prefix in (metadata.get("prefixes", []) or [])
        if str(prefix).strip()
    ]
    unique_prefixes: list[str] = []
    for prefix in prefixes:
        if prefix not in unique_prefixes:
            unique_prefixes.append(prefix)
    primary_prefix = str(getattr(summary, "primary_prefix", "-") or "-")
    if primary_prefix != "-" and primary_prefix not in unique_prefixes:
        unique_prefixes.insert(0, primary_prefix)

    website = _fetch_bgp_tools_website(primary_asn) if primary_asn != "-" else "-"
    if website == "-":
        website = _profile_website(profile)

    combined = dict(metadata)
    combined.update({k: v for k, v in profile.items() if _has_meaningful_value(v)})

    holder = _first_present(combined, "holder", "owner") 
    if holder == "-":
        holder = str(getattr(summary, "primary_holder", "-") or "-")
    owner_id = _first_present(combined, "owner_id", "ownerid")
    responsible = _first_present(combined, "responsible")
    country = _first_present(combined, "country")
    created = _format_compact_date(_first_present(combined, "registered", "created"))
    changed = _format_compact_date(_first_present(combined, "changed", "updated"))
    owner_contact = _first_present(combined, "owner_contact", "owner_c", "owner-c", "contact_handle", "nic_hdl_br")
    routing_contact = _first_present(combined, "routing_contact", "routing_c", "routing-c")
    abuse_contact = _first_present(combined, "abuse_contact", "abuse_c", "abuse-c")
    contact_email = _first_present(combined, "contact_email", "email", "e-mail")

    if country == "-" and unique_prefixes and any("2804:" in prefix.lower() for prefix in unique_prefixes):
        country = "BR"

    return [
        ("AS", primary_asn),
        ("owner", holder),
        ("ownerid", owner_id),
        ("responsible", responsible),
        ("country", country),
        ("owner-c", owner_contact),
        ("created", created),
        ("changed", changed),
        ("Prefixo principal", primary_prefix),
        ("Inetnums", ", ".join(unique_prefixes) if unique_prefixes else "-"),
        ("routing-c", routing_contact),
        ("abuse-c", abuse_contact),
        ("e-mail", contact_email),
        ("Site", website or "-"),
    ]


def _asn_overview_html(summary) -> str:
    rows = []
    for label, value in _asn_summary_data(summary):
        rows.append(
            "<tr>"
            f"<th>{_original.html.escape(label)}</th>"
            f"<td>{_original.html.escape(value)}</td>"
            "</tr>"
        )
    return (
        '<section class="section">'
        '<h2>Informacoes do AS</h2>'
        '<p class="lead">Resumo cadastral e de roteamento associado ao ASN principal identificado para o alvo analisado.</p>'
        '<table class="asn-overview"><tbody>'
        f'{"".join(rows)}'
        '</tbody></table>'
        '</section>'
    )


def _online_status_chart_html(summary) -> str:
    _populate_reachability(summary)
    rows = [
        row for row in (getattr(summary, "inventory_rows", []) or [])
        if _ipv4_int(str(row.get("ip", ""))) is not None
    ]
    if not rows:
        return ""

    online = sum(1 for row in rows if str(row.get("online_status")) == "online")
    offline = sum(1 for row in rows if str(row.get("online_status")) == "offline")
    total = online + offline
    if total <= 0:
        return ""

    online_pct = int(round((online / total) * 100))
    chart_style = (
        f"background:conic-gradient(var(--low) 0 {online_pct}%, "
        f"var(--high) {online_pct}% 100%);"
    )
    return (
        '<section class="section layout-two availability-section">'
        '<div>'
        '<h2>Disponibilidade dos IPs</h2>'
        '<p class="lead">Resumo visual da verificacao de disponibilidade dos enderecos IP inventariados.</p>'
        '</div>'
        '<div class="donut-wrap">'
        f'<div class="donut-graphic" style="{chart_style}">'
        '<div class="donut-center">'
        f'<strong>{online_pct}%</strong><span>IPs online</span>'
        '</div></div>'
        '<div class="legend-list">'
        f'<div class="legend-item"><span class="legend-swatch" style="background:var(--low)"></span><span>Online: {online}</span></div>'
        f'<div class="legend-item"><span class="legend-swatch" style="background:var(--high)"></span><span>Offline: {offline}</span></div>'
        f'<div class="legend-item"><span class="legend-swatch" style="background:var(--line-strong)"></span><span>Total verificado: {total}</span></div>'
        '</div>'
        '</div>'
        '</section>'
    )


def _probe_ip_reachability(ip_value: str) -> str:
    cached = REACHABILITY_CACHE.get(ip_value)
    if cached is not None:
        return cached

    methods = []

    if _ping_command_available():
        try:
            ping_result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip_value],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
                check=False,
            )
            if ping_result.returncode == 0:
                methods.append("icmp")
        except (OSError, subprocess.SubprocessError):
            pass

    for scheme, port in (("http", 80), ("https", 443)):
        try:
            connection = http.client.HTTPConnection(ip_value, port=port, timeout=1.2) if scheme == "http" else http.client.HTTPSConnection(ip_value, port=port, timeout=1.5, context=ssl._create_unverified_context())
            connection.request("HEAD", "/")
            response = connection.getresponse()
            response.read()
            connection.close()
            if 100 <= int(response.status) < 600:
                methods.append(f"{scheme}-head")
                break
        except OSError:
            continue
        except Exception:
            continue

    for port in (80, 443, 22, 25, 53):
        try:
            with socket.create_connection((ip_value, port), timeout=0.8):
                methods.append(f"tcp-{port}")
                break
        except OSError:
            continue

    if methods:
        REACHABILITY_CACHE[ip_value] = "online"
        return "online"

    REACHABILITY_CACHE[ip_value] = "offline"
    return "offline"


def _populate_reachability(summary) -> None:
    rows = getattr(summary, "inventory_rows", []) or []
    targets = [
        str(row.get("ip"))
        for row in rows
        if _ipv4_int(str(row.get("ip", ""))) is not None
    ]
    if not targets:
        return

    unique_targets = sorted(set(targets), key=lambda value: _ipv4_int(value) or 0)
    max_workers = min(16, max(1, len(unique_targets)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(_probe_ip_reachability, ip_value): ip_value for ip_value in unique_targets}
        for future in as_completed(future_map):
            ip_value = future_map[future]
            try:
                status = future.result()
            except Exception:
                status = "offline"
            REACHABILITY_CACHE[ip_value] = status

    for row in rows:
        ip_value = str(row.get("ip", ""))
        if ip_value in REACHABILITY_CACHE:
            row["online_status"] = REACHABILITY_CACHE[ip_value]
        else:
            row["online_status"] = "-"


def _combined_blacklists(row: dict[str, object]) -> list[str]:
    names = []
    for key in ("relevant", "informational"):
        for item in row.get(key, []) or []:
            value = str(item).strip()
            if value and value not in names:
                names.append(value)
    return sorted(names, key=lambda name: (-SEVERITY_RANK.get(_severity_for(name), 0), name))


def _severity_badge_class(name: str) -> str:
    severity = _severity_for(name)
    if severity == "informacional":
        return "severity-info"
    if severity == "media":
        return "severity-medium"
    if severity == "alta":
        return "severity-high"
    if severity == "muito alta":
        return "severity-critical"
    return "severity-neutral"


def _blacklist_badges_html(row: dict[str, object]) -> str:
    names = _combined_blacklists(row)
    if not names:
        return '<span class="muted">-</span>'
    ip_value = str(row.get("ip", "")).strip()
    badges = []
    for name in names:
        css_class = _severity_badge_class(name)
        title = _original.html.escape(_severity_for(name))
        label = _original.html.escape(name)
        url = _removal_url_for_blacklist(name, ip_value)
        if url:
            badges.append(
                f'<a class="badge badge-link {css_class}" href="{_original.html.escape(url)}" target="_blank" rel="noopener noreferrer" title="{title}">{label}</a>'
            )
        else:
            badges.append(
                f'<span class="badge {css_class}" title="{title}">{label}</span>'
            )
    return "".join(badges)


def _blacklist_dropdown_html(row: dict[str, object]) -> str:
    names = _combined_blacklists(row)
    if not names:
        return '<span class="muted">-</span>'
    count = len(names)
    return (
        '<details class="blacklist-dropdown">'
        f'<summary>Ver blacklists ({count})</summary>'
        f'<div class="blacklist-dropdown-body">{_blacklist_badges_html(row)}</div>'
        '</details>'
    )


def _catalog_group_dropdown_html(scope_label: str, rows: list[str], total_items: int) -> str:
    return (
        '<details class="catalog-dropdown">'
        f'<summary>{_original.html.escape(scope_label)} ({total_items})</summary>'
        '<div class="catalog-dropdown-body">'
        '<table><thead><tr><th>Blacklist</th><th>Tipo</th><th>Relevância</th><th>Descrição</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
        '</div>'
        '</details>'
    )


def _removal_url_for_blacklist(name: str, ip_value: str) -> str:
    lowered = name.lower()
    if "abuseat" in lowered or lowered == "cbl.abuseat.org":
        return f"https://www.abuseat.org/lookup.cgi?ip={quote(ip_value)}"
    if "spamhaus" in lowered:
        return "https://check.spamhaus.org/"
    if "barracuda" in lowered:
        return "https://www.barracudacentral.org/rbl/removal-request"
    if "spamcop" in lowered:
        return "https://www.spamcop.net/fom-serve/cache/298.html"
    if "uceprotect" in lowered:
        return "https://www.uceprotect.net/en/index.php?m=7&s=0"
    if "spamrats" in lowered:
        return "https://www.spamrats.com/removal.php"
    if "nszones" in lowered:
        return "https://www.nszones.com/contact/"
    if "justspam" in lowered:
        return "https://www.justspam.org/"
    return ""


def _blacklist_vendor_label(name: str) -> str:
    lowered = name.lower()
    if "barracuda" in lowered:
        return "Barracuda"
    if "spamhaus" in lowered:
        return "Spamhaus"
    if "abuseat" in lowered:
        return "CBL"
    if "spamcop" in lowered:
        return "SpamCop"
    if "uceprotect" in lowered:
        return "UCEProtect"
    if "spamrats" in lowered:
        return "SpamRATS"
    if "nszones" in lowered:
        return "NSZones"
    if "justspam" in lowered:
        return "JustSpam"
    return name


def _removal_actions_html(row: dict[str, object]) -> str:
    ip_value = str(row.get("ip", "")).strip()
    names = [str(item).strip() for item in row.get("relevant", []) or [] if str(item).strip()]
    if not ip_value or not names:
        return '<span class="muted">-</span>'
    links = []
    seen_urls = set()
    for name in names:
        url = _removal_url_for_blacklist(name, ip_value)
        if url in seen_urls:
            continue
        seen_urls.add(url)
        links.append(
            f'<a class="action-link" href="{_original.html.escape(url)}" target="_blank" rel="noopener noreferrer">Remover via {_original.html.escape(_blacklist_vendor_label(name))}</a>'
        )
    return "".join(links) if links else '<span class="muted">-</span>'


def _patched_write_json_summary(summary) -> None:
    asn_drop_line = next((line for line in summary.asn_context_lines if line.startswith("ASN-DROP:")), "ASN-DROP: Nao aplicavel")
    _populate_reachability(summary)
    payload = {
        "target": summary.normalized_input,
        "asn": summary.primary_asn,
        "holder": summary.primary_holder,
        "primary_prefix": summary.primary_prefix,
        "risk_level": summary.risk_level,
        "report_risk_level": getattr(summary, "report_risk_level", "none"),
        "report_risk_label": getattr(summary, "report_risk_label", summary.risk_level),
        "report_confidence": getattr(summary, "report_confidence", "medium"),
        "report_risk_reason": getattr(summary, "report_risk_reason", []),
        "asn_drop": {
            "status": asn_drop_line,
            "listed": summary.asn_drop_listed,
            "details": summary.asn_drop_details,
        },
        "affected_ips_count": getattr(summary, "affected_ips_count", summary.unique_ips_listed),
        "affected_ips_ratio": getattr(summary, "affected_ips_ratio", 0.0),
        "very_high_ips_count": getattr(summary, "very_high_ips_count", 0),
        "high_ips_count": getattr(summary, "high_ips_count", 0),
        "medium_ips_count": getattr(summary, "medium_ips_count", 0),
        "informational_ips_count": getattr(summary, "informational_ips_count", 0),
        "timeout_ips_count": getattr(summary, "timeout_ips_count", 0),
        "dnsbl_occurrences_count": getattr(summary, "dnsbl_occurrences_count", 0),
        "unique_blacklists_count": getattr(summary, "unique_blacklists_count", summary.unique_blacklists_hit),
        "unique_families_count": getattr(summary, "unique_families_count", 0),
        "affected_families": getattr(summary, "affected_families", []),
        "direct_hits_count": getattr(summary, "direct_hits_count", 0),
        "network_hits_count": getattr(summary, "network_hits_count", 0),
        "informational_hits_count": getattr(summary, "informational_hits_count", 0),
        "asn_drop_status": getattr(summary, "asn_drop_status", "not_listed"),
        "has_asn_drop": getattr(summary, "has_asn_drop", bool(summary.asn_drop_listed)),
        "has_network_scope_hits": getattr(summary, "has_network_scope_hits", bool(summary.network_scope_listed)),
        "has_critical_family_hits": getattr(summary, "has_critical_family_hits", False),
        "timeout_sources_count": getattr(summary, "timeout_sources_count", 0),
        "error_sources_count": getattr(summary, "error_sources_count", 0),
        "ips_scanned": summary.unique_ips_scanned,
        "ips_listed": summary.unique_ips_listed,
        "ips_clean": summary.unique_ips_clean,
        "blacklists": [
            {
                "name": name,
                "count": count,
                "relevance": blacklist_relevance(name),
                "family": _family_label(_blacklist_family(name)),
            }
            for name, count in summary.top_blacklists
        ],
        "evidence_by_ip": [
            {
                "ip": row.get("ip"),
                "risk_level": row.get("risk_level", row.get("status")),
                "status": row.get("status"),
                "risk_label": row.get("risk_label", _inventory_status_label(row)),
                "risk_reason": row.get("risk_reason"),
                "confidence": row.get("confidence"),
                "direct_hits_count": row.get("direct_hits_count", 0),
                "network_hits_count": row.get("network_hits_count", 0),
                "informational_hits_count": row.get("informational_hits_count", 0),
                "dnsbl_occurrences_count": row.get("dnsbl_occurrences_count", 0),
                "unique_blacklists_count": row.get("unique_blacklists_count", 0),
                "unique_families_count": row.get("unique_families_count", 0),
                "affected_families": row.get("affected_families", []),
                "highest_severity": row.get("highest_severity", "none"),
                "has_very_high_source": row.get("has_very_high_source", False),
                "has_high_source": row.get("has_high_source", False),
                "has_network_context": row.get("has_network_context", False),
                "has_informational_only": row.get("has_informational_only", False),
                "has_timeout": row.get("has_timeout", False),
                "timeout_sources": row.get("timeout_sources", []),
                "error_sources": row.get("error_sources", []),
                "online_status": row.get("online_status", "-"),
                "blacklists": _combined_blacklists(row),
                "relevant_blacklists": row.get("relevant", []),
                "informational_blacklists": row.get("informational", []),
                "risk_score": row.get("risk_count", 0),
                "hits": row.get("hits", []),
            }
            for row in summary.inventory_rows
            if row.get("status") != "clean"
            or row.get("relevant")
            or row.get("informational")
        ],
        "critical_findings": summary.critical_findings,
        "execution_metadata": _runtime_metadata(summary),
    }
    summary.report_json_path.write_text(
        _original.json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _execution_metadata_html(summary) -> str:
    metadata = _runtime_metadata(summary)
    lang = _summary_ui_lang(summary)
    rows = [
        (tr("meta_username", lang=lang), metadata["username"]),
        (tr("meta_os", lang=lang), metadata["os"]),
        (tr("meta_language", lang=lang), metadata["language"]),
        (tr("meta_started", lang=lang), metadata["started_at"]),
        (tr("meta_finished", lang=lang), metadata["finished_at"]),
        (tr("meta_duration", lang=lang), metadata["duration_seconds"]),
    ]
    body = "".join(
        "<tr>"
        f"<th>{_original.html.escape(str(label))}</th>"
        f"<td>{_original.html.escape(str(value))}</td>"
        "</tr>"
        for label, value in rows
    )
    return (
        '<section class="section">'
        f'<h2>{_original.html.escape(tr("metadata_title", lang=lang))}</h2>'
        f'<p class="lead">{_original.html.escape(tr("metadata_lead", lang=lang))}</p>'
        f'<table class="asn-overview"><tbody>{body}</tbody></table>'
        '</section>'
    )


def _report_replacements(lang: str | None = None) -> dict[str, str]:
    effective_lang = lang or CURRENT_UI_LANG
    if effective_lang == "en-US":
        return {
            "Relatório Executivo de Reputação de IP": tr("html_title", lang=effective_lang),
            "Classificação de Risco": "Risk Rating",
            "Resumo Executivo": "Executive Summary",
            "Distribuição de Reputação": "Reputation Distribution",
            "IPs por Blacklist": "IPs by Blacklist",
            "Heatmap do Bloco /24": "/24 Block Heatmap",
            "Detalhamento por Blacklist": "Blacklist Details",
            "Inventário Completo de IPs": "Full IP Inventory",
            "Inventário Geral de Blocos /24": "General /24 Block Inventory",
            "Blacklists Consultadas": "Queried Blacklists",
            "Metodologia": "Methodology",
            "Legenda de Relevância": "Relevance Legend",
            "Informações do AS": "AS Information",
            "Informacoes do AS": "AS Information",
            "Disponibilidade dos IPs": "Network Probe Response",
            "Status ASN-DROP": "ASN-DROP Status",
            "listado": "listed",
            "nao listado": "not listed",
            "Nao listado": "Not listed",
            "Listado": "Listed",
            "Nao concluido": "Not completed",
            "Sem risco": "No risk",
            "Baixo": "Low",
            "Moderado": "Moderate",
            "Alto": "High",
            "Muito alto": "Very high",
            "Online": "Online",
            "Offline": "No response",
            "IPs online": "IPs online",
            "Total verificado": "Total checked",
            "Parte 1: DIRECT_IP_BLACKLISTS": "Part 1: Direct IP Blacklists",
            "Parte 2: NETWORK_SCOPE_BLACKLISTS": "Part 2: Network, Block, or ASN Lists",
            "Parte 3: ASN-DROP": "Part 3: ASN-DROP",
            "Parte 4: Listas Informativas": "Part 4: Informational Sources",
            "Nenhuma ocorrencia nesta categoria.": "No findings in this category.",
            "Modo de scan: avaliacao automatica por escopo; listas de IP afetam IPs, listas de bloco afetam bloco/ASN e fontes informacionais ficam como contexto.": "Scan mode: automatic scope evaluation; IP lists affect IPs, block lists affect block/ASN, and informational sources remain context only.",
        }
    return {
        "Informacoes do AS": "Informações do AS",
        "Disponibilidade dos IPs": "Resposta a probes de rede",
        "Inventário Completo de IPs": "Inventário de IPs analisados",
        "Nenhuma ocorrencia nesta categoria.": "Nenhuma ocorrência nesta categoria.",
        "Dados e graficos filtrados apenas por blacklists diretas de IP.": "Dados e gráficos filtrados apenas por blacklists diretas de IP.",
        "Dados e graficos filtrados apenas por listas de escopo de rede, bloco, provedor ou ASN.": "Dados e gráficos filtrados apenas por listas de escopo de rede, bloco, provedor ou ASN.",
        "Resultado exclusivo da consulta ASN-DROP.": "Resultado exclusivo da consulta ASN-DROP.",
        "Dados e graficos filtrados apenas por listas de carater informativo.": "Dados e gráficos filtrados apenas por listas de caráter informativo.",
        "Resumo visual da verificacao de disponibilidade dos enderecos IP inventariados.": "Resumo visual da verificação de disponibilidade dos endereços IP inventariados.",
        "Offline": "Sem resposta",
    }


def _localize_report_html(html_text: str, summary=None) -> str:
    lang = _summary_ui_lang(summary)
    for source, target in _report_replacements(lang).items():
        html_text = html_text.replace(source, target)
    return html_text


def _inject_report_meta_tags(html_text: str, summary) -> str:
    metadata = _runtime_metadata(summary)
    tags = [
        ("inh-username", metadata["username"]),
        ("inh-os", metadata["os"]),
        ("inh-language", metadata["language"]),
        ("inh-started-at", metadata["started_at"]),
        ("inh-finished-at", metadata["finished_at"]),
    ]
    block = "\n".join(
        f'<meta name="{_original.html.escape(name)}" content="{_original.html.escape(str(value))}">'
        for name, value in tags
    )
    return html_text.replace("</head>", f"{block}\n</head>", 1)


def _asn_drop_badge_html(summary) -> str:
    listed = bool(summary.asn_drop_listed)
    label = "listado" if listed else "nao listado"
    css_class = "listed" if listed else "not-listed"
    title = _original.html.escape("; ".join(summary.asn_drop_details) if summary.asn_drop_details else label)
    return (
        f'<div class="asn-drop-badge {css_class}" title="{title}">'
        "<strong>ASN-DROP</strong>"
        f"<span>{label}</span>"
        "</div>"
    )


def _inject_report_enhancements(html_text: str, summary) -> str:
    lang = _summary_ui_lang(summary)
    style = """
    @media screen {
      .report-shell { max-width: 210mm; margin: 18px auto 72px; }
      .section, .part-chapter, .heatmap-print-group, .distribution-print-group { break-inside: avoid; }
    }
    .risk-stack { display:flex; flex-direction:column; align-items:flex-end; gap:7px; }
    .risk-stack > .asn-drop-badge { min-width:132px; transform:scale(.92); transform-origin:top right; }
    .asn-drop-badge { min-width:132px; border-radius:15px; padding:8px 14px; text-align:center; border:1px solid var(--line-strong); background:#e5e7eb; color:#6b7280; box-sizing:border-box; }
    .asn-drop-badge strong { display:block; font-size:13px; line-height:1.1; letter-spacing:0; }
    .asn-drop-badge span { display:block; margin-top:3px; font-size:9px; line-height:1.1; text-transform:uppercase; font-weight:800; letter-spacing:0; }
    .asn-drop-badge.listed { background:var(--high); color:#fff; border-color:var(--high); }
    .risk-badge-label { display:block; margin-bottom:4px; font-size:11px; line-height:1; font-weight:700; letter-spacing:0; text-transform:none; opacity:0.92; }
    .risk-badge-value { display:block; line-height:1.05; }
    .part-chapter { border:1px solid var(--line-strong); border-left:8px solid var(--accent); border-radius:18px; padding:18px; background:var(--surface-soft); margin-top:28px; break-after:avoid; page-break-after:avoid; }
    .part-chapter h2 { margin-bottom:6px; }
    .part-chapter .lead { margin:0; }
    .part-empty { border:1px dashed var(--line-strong); border-radius:16px; padding:18px; color:var(--muted); background:var(--surface-soft); }
    .part-asn-panel { display:grid; grid-template-columns:auto 1fr; gap:18px; align-items:start; }
    .part-asn-panel .bullets { margin-top:2px; }
    .asn-overview th { width:180px; background:var(--surface-soft); color:var(--primary); text-transform:none; letter-spacing:0; font-size:11px; }
    .asn-overview td { word-break:break-word; }
    .severity-info { background:color-mix(in srgb, var(--accent) 18%, var(--surface)); color:var(--accent); border-color:color-mix(in srgb, var(--accent) 38%, var(--surface)); }
    .severity-medium { background:color-mix(in srgb, var(--medium) 22%, var(--surface)); color:color-mix(in srgb, var(--medium) 84%, #111827); border-color:color-mix(in srgb, var(--medium) 42%, var(--surface)); }
    .severity-high { background:color-mix(in srgb, var(--high) 14%, var(--surface)); color:color-mix(in srgb, var(--high) 84%, #111827); border-color:color-mix(in srgb, var(--high) 34%, var(--surface)); }
    .severity-critical { background:var(--high); color:#fff; border-color:color-mix(in srgb, var(--high) 76%, #000); }
    .severity-neutral { background:var(--surface-soft); color:var(--muted); border-color:var(--line-strong); }
    .status-pill { display:inline-flex; align-items:center; justify-content:center; min-width:76px; padding:5px 10px; border-radius:999px; font-size:10px; font-weight:800; text-transform:uppercase; border:1px solid transparent; }
    .status-online { background:color-mix(in srgb, var(--low) 18%, var(--surface)); color:color-mix(in srgb, var(--low) 82%, #111827); border-color:color-mix(in srgb, var(--low) 38%, var(--surface)); }
    .status-offline { background:color-mix(in srgb, var(--high) 12%, var(--surface)); color:color-mix(in srgb, var(--high) 78%, #111827); border-color:color-mix(in srgb, var(--high) 28%, var(--surface)); }
    .status-na { background:var(--surface-soft); color:var(--muted); border-color:var(--line-strong); }
    .badge-link { text-decoration:none; cursor:pointer; }
    .badge-link:hover { filter:brightness(1.02); box-shadow:0 0 0 1px color-mix(in srgb, currentColor 14%, transparent); }
    .action-cell { display:flex; flex-wrap:wrap; gap:6px; }
    .action-link { display:inline-flex; align-items:center; justify-content:center; padding:6px 10px; border-radius:10px; border:1px solid var(--line-strong); background:var(--surface-soft); color:var(--primary); font-size:10px; font-weight:700; text-decoration:none; white-space:nowrap; }
    .blacklist-dropdown { min-width:220px; }
    .blacklist-dropdown summary, .catalog-dropdown summary { cursor:pointer; color:var(--primary); font-weight:700; }
    .blacklist-dropdown summary::marker, .catalog-dropdown summary::marker { color:var(--accent); }
    .blacklist-dropdown-body { margin-top:8px; display:flex; flex-wrap:wrap; gap:6px; }
    .catalog-dropdown { width:100%; }
    .catalog-dropdown-body { margin-top:10px; }
    .footer { display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:6px 12px; font-size:11px; line-height:1.25; }
    .footer a { color:inherit; text-decoration:none; }
    .footer span, .footer a { display:inline-flex; align-items:center; gap:6px; white-space:nowrap; }
    .footer-icon { width:12px; height:12px; display:inline-block; flex:0 0 auto; }
    .print-keep, .heatmap-print-group, .distribution-print-group { break-inside:avoid; page-break-inside:avoid; }
    @media print {
      @page { size:A4; margin:16mm 12mm 18mm 12mm; }
      body { padding-bottom:18mm; }
      .report-shell { padding-bottom:18mm; }
      .section { break-inside:auto; page-break-inside:auto; }
      .distribution-print-group, .heatmap-print-group, .donut-wrap, .bars, .heat-layout, .heat-box, .legend-table, .part-chapter { break-inside:avoid; page-break-inside:avoid; }
      .distribution-print-group, .heatmap-print-group { display:block; }
      .heatmap-print-group { break-before:auto; page-break-before:auto; }
      .heat-layout { margin-top:10px; }
      .heat-svg { max-height:150mm; }
      h2, h3 { break-after:avoid; page-break-after:avoid; }
      .catalog-dropdown, .blacklist-dropdown { display:block; }
      .catalog-dropdown > summary, .blacklist-dropdown > summary { list-style:none; }
      .catalog-dropdown > summary::-webkit-details-marker, .blacklist-dropdown > summary::-webkit-details-marker { display:none; }
      .footer {
        position:fixed;
        left:0;
        right:0;
        bottom:0;
        z-index:50;
        padding:3mm 8mm;
        background:var(--surface);
        border-top:1px solid var(--line-strong);
        font-size:8.5pt;
        flex-wrap:nowrap;
        overflow:hidden;
      }
    }
    .risk-low { background:var(--low); color:#fff; }
    """
    html_text = html_text.replace("</style>", f"{style}\n  </style>", 1)
    print_details_script = """
    <script>
      let printDetailsState = [];
      function expandDetailsForPrint() {
        const details = Array.from(document.querySelectorAll("details"));
        printDetailsState = details.map((node) => node.open);
        details.forEach((node) => { node.open = true; });
      }
      function restoreDetailsAfterPrint() {
        const details = Array.from(document.querySelectorAll("details"));
        details.forEach((node, index) => {
          node.open = Boolean(printDetailsState[index]);
        });
      }
      window.addEventListener("beforeprint", expandDetailsForPrint);
      window.addEventListener("afterprint", restoreDetailsAfterPrint);
    </script>
    """
    html_text = html_text.replace("</head>", f"{print_details_script}\n</head>", 1)

    badge = _asn_drop_badge_html(summary)
    marker = '</div>\n      </div>\n      <div class="divider"></div>'
    if marker in html_text and '<div class="asn-drop-badge' not in html_text:
        html_text = html_text.replace(
            marker,
            f'</div>\n        {badge}\n        </div>\n      </div>\n      <div class="divider"></div>',
            1,
        )
        html_text = html_text.replace('<div class="risk-badge ', '<div class="risk-stack"><div class="risk-badge ', 1)

    def _label_risk_badge(match: re.Match[str]) -> str:
        opening_tag = match.group(1)
        value = match.group(2).strip()
        closing_tag = match.group(3)
        return (
            f"{opening_tag}"
            '<span class="risk-badge-label">Classificação de Risco</span>'
            f'<span class="risk-badge-value">{_original.html.escape(value)}</span>'
            f"{closing_tag}"
        )

    html_text = re.sub(
        r'(<div class="risk-badge [^"]+">)([^<]+)(</div>)',
        _label_risk_badge,
        html_text,
        count=1,
    )

    html_text = html_text.replace("<title>Relatório Executivo de Reputação de IP</title>", f"<title>{_original.html.escape(tr('report_brand', lang=lang))}</title>", 1)
    html_text = html_text.replace("<h1>Relatório Executivo de Reputação de IP</h1>", f"<h1>{_original.html.escape(tr('report_brand', lang=lang))}</h1>", 1)
    html_text = html_text.replace('<div class="watermark">REPUTAÇÃO IP</div>', f'<div class="watermark">{REPORT_BRAND}</div>', 1)
    html_text = re.sub(
        r'<div class="footer"><span>(.*?)</span><span>(.*?)</span><span>(.*?)</span></div>',
        (
            '<div class="footer">'
            f'<span><a href="https://www.linkedin.com/in/guilherme-campos353/" target="_blank" rel="noopener noreferrer">{_original.html.escape(tr("developer_label", lang=lang))}: Guilherme Campos</a></span>'
            '<span><a href="mailto:guilherme@sentrixit.com">'
            '<svg class="footer-icon" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M3 5h18a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1Zm0 2v.511l9 6 9-6V7l-9 6-9-6Z"/></svg>'
            'guilherme@sentrixit.com</a></span>'
            '<span><a href="https://www.linkedin.com/in/guilherme-campos353/" target="_blank" rel="noopener noreferrer">'
            '<svg class="footer-icon" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M6.94 8.5H3.56V20h3.38V8.5ZM5.25 3A2 2 0 1 0 5.3 7a2 2 0 0 0-.05-4ZM20.44 12.54c0-3.47-1.85-5.08-4.32-5.08a3.74 3.74 0 0 0-3.37 1.85V8.5H9.38c.04.54 0 11.5 0 11.5h3.37v-6.42c0-.34.02-.68.12-.92.27-.68.88-1.39 1.91-1.39 1.35 0 1.89 1.03 1.89 2.54V20H20v-7.46Z"/></svg>'
            'LinkedIn</a></span>'
            '<span><a href="https://github.com/guicampos21" target="_blank" rel="noopener noreferrer">'
            '<svg class="footer-icon" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 .5a12 12 0 0 0-3.79 23.39c.6.11.82-.26.82-.58v-2.04c-3.34.73-4.04-1.42-4.04-1.42a3.19 3.19 0 0 0-1.34-1.76c-1.1-.75.08-.73.08-.73a2.53 2.53 0 0 1 1.85 1.24 2.57 2.57 0 0 0 3.52 1 2.57 2.57 0 0 1 .76-1.61c-2.67-.3-5.47-1.33-5.47-5.93a4.64 4.64 0 0 1 1.24-3.22 4.3 4.3 0 0 1 .12-3.18s1.01-.32 3.3 1.23a11.35 11.35 0 0 1 6 0c2.29-1.55 3.3-1.23 3.3-1.23a4.3 4.3 0 0 1 .12 3.18 4.63 4.63 0 0 1 1.24 3.22c0 4.61-2.8 5.62-5.48 5.92a2.88 2.88 0 0 1 .82 2.23v3.3c0 .32.21.69.82.58A12 12 0 0 0 12 .5Z"/></svg>'
            'GitHub</a></span>'
            '</div>'
        ),
        html_text,
        count=1,
    )

    html_text = html_text.replace(
        '<section class="section layout-two">\n      <div>\n        <h2>Distribuição de Reputação</h2>',
        '<section class="section layout-two distribution-print-group">\n      <div>\n        <h2>Distribuição de Reputação</h2>',
        1,
    )
    html_text = html_text.replace(
        '<section class="section">\n      <h2>Heatmap do Bloco /24</h2>',
        '<section class="section heatmap-print-group">\n      <h2>Heatmap do Bloco /24</h2>',
        1,
    )

    html_text = re.sub(
        r'<p class="lead"><strong>Vis[ãa]o resumida por faixas:</strong>.*?</p>\s*',
        "",
        html_text,
        count=1,
        flags=re.S | re.I,
    )
    html_text = _inject_report_meta_tags(html_text, summary)
    html_text = _localize_report_html(html_text, summary)
    return html_text


def _part_result_sets(summary) -> dict[str, list[CheckResult]]:
    results = list(getattr(summary, "all_results", []))
    return {
        "direct": [
            result for result in results
            if result.status == "listed"
            and _source_part(result.task.blacklist) == "direct"
            and result.task.target_kind == "ip"
        ],
        "network": [
            result for result in results
            if result.status == "listed"
            and result.task.query_mode != "asn_drop"
            and (
                _source_part(result.task.blacklist) == "network"
                or result.task.target_kind == "block"
            )
        ],
        "asn_drop": [
            result for result in results
            if result.task.query_mode == "asn_drop"
        ],
        "informational": [
            result for result in results
            if result.status == "listed"
            and result.task.query_mode != "asn_drop"
            and _source_part(result.task.blacklist) == "informational"
        ],
    }


def _summary_for_part(summary, results: list[CheckResult]):
    metadata = dict(getattr(summary, "scan_metadata", {}))
    part_summary = _original_build_scan_summary(
        kind=summary.kind,
        original_input=summary.original_input,
        normalized_input=summary.normalized_input,
        detected_mode=summary.detected_mode,
        details=list(summary.details),
        metadata=metadata,
        results=list(results),
    )
    part_summary.report_path = summary.report_path
    part_summary.report_json_path = summary.report_json_path
    return _decorate_summary(part_summary, list(results))


def _extract_report_sections(html_text: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    for section in re.findall(r'<section class="section[^"]*">.*?</section>', html_text, flags=re.S):
        heading = re.search(r'<h2>(.*?)</h2>', section, flags=re.S)
        if not heading:
            continue
        title = re.sub(r"<.*?>", "", heading.group(1)).strip()
        sections[title] = section
    return sections


def _chapter_html(title: str, description: str) -> str:
    return (
        '<section class="section part-chapter">'
        f'<h2>{_original.html.escape(title)}</h2>'
        f'<p class="lead">{_original.html.escape(description)}</p>'
        '</section>'
    )


def _empty_part_html(message: str) -> str:
    return f'<section class="section"><div class="part-empty">{_original.html.escape(message)}</div></section>'


def _asn_drop_part_html(summary) -> str:
    if not summary.asn_drop_listed:
        return _empty_part_html("Nenhuma ocorrencia nesta categoria.")
    details = summary.asn_drop_details or ["Nenhuma incidencia em ASN-DROP."]
    bullets = "".join(
        f'<li><span class="dot"></span><span>{_original.html.escape(detail)}</span></li>'
        for detail in details
    )
    return (
        '<section class="section">'
        '<h2>Status ASN-DROP</h2>'
        '<div class="blacklist-section part-asn-panel">'
        f'{_asn_drop_badge_html(summary)}'
        f'<ul class="bullets">{bullets}</ul>'
        '</div>'
        '</section>'
    )


def _summary_ip_values(summary) -> list[str]:
    ips = set()
    for row in getattr(summary, "inventory_rows", []) or []:
        value = str(row.get("ip", ""))
        if _ipv4_int(value) is not None:
            ips.add(value)
    metadata = getattr(summary, "scan_metadata", {}) or {}
    for value in metadata.get("ip_targets", []) or []:
        value = str(value)
        if _ipv4_int(value) is not None:
            ips.add(value)
    for result in getattr(summary, "all_results", []) or []:
        if result.task.target_kind == "ip" and _ipv4_int(result.task.target_value) is not None:
            ips.add(result.task.target_value)
    return sorted(ips, key=lambda value: _ipv4_int(value) or 0)


def _ip_to_24(value: str) -> str:
    ip = _original.ipaddress.ip_address(value)
    return str(_original.ipaddress.ip_network(f"{ip}/24", strict=False))


def _block_inventory_rows(summary) -> list[dict[str, object]]:
    rows: dict[str, dict[str, object]] = {}
    for ip_value in _summary_ip_values(summary):
        block = _ip_to_24(ip_value)
        row = rows.setdefault(block, {"block": block, "ips_scanned": 0, "direct_ips": set(), "network_lists": set(), "status": "Limpo"})
        row["ips_scanned"] = int(row["ips_scanned"]) + 1

    for inventory_row in getattr(summary, "inventory_rows", []) or []:
        ip_value = str(inventory_row.get("ip", ""))
        if _ipv4_int(ip_value) is None:
            continue
        if str(inventory_row.get("status")) not in {"very_high", "high", "medium"}:
            continue
        block = _ip_to_24(ip_value)
        row = rows.setdefault(block, {"block": block, "ips_scanned": 0, "direct_ips": set(), "network_lists": set(), "status": "Limpo"})
        row["direct_ips"].add(ip_value)

    for result in getattr(summary, "all_results", []) or []:
        if result.status != "listed":
            continue
        if _source_part(result.task.blacklist) == "network" or result.task.target_kind == "block":
            try:
                network = _original.ipaddress.ip_network(result.task.target_value, strict=False)
            except ValueError:
                continue
            if network.version != 4:
                continue
            targets = []
            for block_name in list(rows):
                block_network = _original.ipaddress.ip_network(block_name, strict=False)
                if block_network.subnet_of(network) or network.subnet_of(block_network):
                    targets.append(block_name)
            if not targets and network.prefixlen >= 24:
                targets = [str(_original.ipaddress.ip_network(f"{network.network_address}/24", strict=False))]
            for block in targets:
                row = rows.setdefault(block, {"block": block, "ips_scanned": 0, "direct_ips": set(), "network_lists": set(), "status": "Limpo"})
                row["network_lists"].add(result.task.blacklist)

    for row in rows.values():
        if row["network_lists"]:
            row["status"] = "Muito alto"
        elif row["direct_ips"]:
            row["status"] = "Listado"

    return sorted(rows.values(), key=lambda row: _original.ipaddress.ip_network(str(row["block"])).network_address)


def _block_inventory_html(summary) -> str:
    rows = _block_inventory_rows(summary)
    if len(rows) <= 1:
        return ""
    body = []
    for row in rows:
        network_lists = sorted(row["network_lists"])
        body.append(
            "<tr>"
            f"<td>{_original.html.escape(str(row['block']))}</td>"
            f"<td>{row['ips_scanned']}</td>"
            f"<td>{len(row['direct_ips'])}</td>"
            f"<td>{_original.html.escape(', '.join(network_lists) if network_lists else '-')}</td>"
            f"<td>{_original.html.escape(str(row['status']))}</td>"
            "</tr>"
        )
    return (
        '<section class="section">'
        '<h2>Inventário Geral de Blocos /24</h2>'
        '<table><thead><tr><th>Bloco /24</th><th>IPs escaneados</th><th>IPs listados</th><th>Network Scope</th><th>Status</th></tr></thead>'
        f'<tbody>{"".join(body)}</tbody></table>'
        '</section>'
    )


def _block_distribution_html(summary, title: str = "Distribuição de Reputação por Bloco /24") -> str:
    rows = _block_inventory_rows(summary)
    if len(rows) <= 1:
        return ""
    max_value = max(max(int(row["ips_scanned"]), len(row["direct_ips"]), len(row["network_lists"])) for row in rows) or 1
    bars = []
    for row in rows:
        value = len(row["network_lists"]) or len(row["direct_ips"])
        width = max(6, int((value / max_value) * 100)) if value else 6
        label = f"{row['block']} - {row['status']}"
        bars.append(
            '<div class="bar-row">'
            f'<span class="bar-label">{_original.html.escape(label)}</span>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{width}%"></div></div>'
            f'<span class="bar-value">{value}</span>'
            '</div>'
        )
    return (
        '<section class="section layout-two distribution-print-group">'
        '<div>'
        f'<h2>{_original.html.escape(title)}</h2>'
        '<p class="lead">Cada linha representa um /24 dentro do bloco escaneado. Listas de escopo de rede elevam o bloco, sem marcar todos os IPs como sujos.</p>'
        '</div>'
        f'<div class="bars">{"".join(bars)}</div>'
        '</section>'
    )


def _inventory_section_html(summary) -> str:
    metadata = getattr(summary, "scan_metadata", {}) or {}
    if len(_summary_ip_values(summary)) > 256 and not bool(metadata.get("inventory_all_ips")):
        return ""
    _populate_reachability(summary)
    rows = getattr(summary, "inventory_rows", []) or []
    body = []
    for row in rows:
        ip_value = str(row.get("ip", "")).strip()
        if _ipv4_int(ip_value) is None:
            continue
        status_label = _inventory_status_label(row)
        online_status = str(row.get("online_status", "-"))
        online_class = "status-online" if online_status == "online" else "status-offline" if online_status == "offline" else "status-na"
        body.append(
            "<tr>"
            f"<td>{_original.html.escape(ip_value)}</td>"
            f"<td>{_original.html.escape(status_label)}</td>"
            f"<td>{_blacklist_badges_html(row)}</td>"
            f"<td><span class=\"status-pill {online_class}\">{_original.html.escape(online_status)}</span></td>"
            "</tr>"
        )
    if not body:
        return ""
    return (
        '<section class="section">'
        '<h2>Inventário Completo de IPs</h2>'
        '<p class="lead">Blacklists unificadas por IP, com destaque visual por relevância. Quando houver página útil de revisão/remocao, a própria tag da blacklist funciona como atalho.</p>'
        '<table><thead><tr><th>IP</th><th>Risco</th><th>Blacklists</th><th>Status</th></tr></thead>'
        f'<tbody>{"".join(body)}</tbody></table>'
        '</section>'
    )


def _blacklist_catalog_html() -> str:
    selected = sorted(_selected_scan_blacklists())
    type_labels = {
        "ip": "DIRECT_IP_BLACKLISTS",
        "bloco": "NETWORK_SCOPE_BLACKLISTS",
        "informativo": "Listas informativas",
    }
    relevance_order = ["muito alta", "alta", "media", "baixa", "informacional"]
    grouped: dict[str, dict[str, list[str]]] = {}
    for name in selected:
        scope = _catalog_scope(name)
        relevance = _catalog_relevance(name)
        grouped.setdefault(scope, {}).setdefault(relevance, []).append(name)

    blocks: list[str] = []
    for scope in ["ip", "bloco", "informativo"]:
        relevance_groups = grouped.get(scope)
        if not relevance_groups:
            continue
        rows = []
        for relevance in relevance_order:
            for name in relevance_groups.get(relevance, []):
                description = BLACKLIST_DESCRIPTIONS.get(name, "-")
                rows.append(
                    "<tr>"
                    f"<td>{_original.html.escape(name)}</td>"
                    f"<td>{_original.html.escape(type_labels.get(scope, scope))}</td>"
                    f"<td>{_original.html.escape(relevance)}</td>"
                    f"<td>{_original.html.escape(description)}</td>"
                    "</tr>"
                )
        blocks.append(
            '<div class="blacklist-section">'
            f'{_catalog_group_dropdown_html(type_labels.get(scope, scope), rows, len(rows))}'
            '</div>'
        )

    if not blocks:
        return ""
    return (
        '<section class="section">'
        '<h2>Blacklists Consultadas</h2>'
        '<p class="lead">Fontes utilizadas nesta execução, agrupadas por tipo e ordenadas por relevância dentro de cada grupo.</p>'
        f'{"".join(blocks)}'
        '</section>'
    )


def _plain_methodology_html() -> str:
    bullets = [
        "A ferramenta verifica se o dominio, IP, bloco ou ASN aparecem em listas publicas usadas para identificar reputacao ruim ou abuso na internet.",
        "Nem toda lista tem o mesmo peso: algumas indicam problema forte no IP, enquanto outras servem apenas como contexto.",
        "Quando duas listas pertencem ao mesmo provedor, isso nao conta como duas evidencias independentes de mesmo peso.",
        "Listas de rede ou ASN indicam problema mais amplo no bloco ou no provedor, e nao significam automaticamente que todos os IPs estao listados.",
        "ASN-DROP e tratado separadamente porque aponta para impacto mais grave em nivel de ASN.",
        "Timeout ou erro de consulta nao contam como listagem; eles apenas reduzem a confianca do resultado final.",
    ]
    rows = [
        ("Muito alta", "Sinal forte de problema e prioridade alta de analise."),
        ("Alta", "Evidencia relevante que merece acao operacional."),
        ("Media", "Indicio importante, mas que pode precisar de correlacao adicional."),
        ("Informacional", "Contexto complementar; sozinho nao classifica o IP como listado."),
    ]
    bullets_html = "".join(
        f'<li><span class="dot"></span><span>{_original.html.escape(text)}</span></li>'
        for text in bullets
    )
    table_html = "".join(
        "<tr>"
        f"<th>{_original.html.escape(level)}</th>"
        f"<td>{_original.html.escape(text)}</td>"
        "</tr>"
        for level, text in rows
    )
    return (
        '<section class="section method-grid">'
        '<div>'
        '<h2>Metodologia</h2>'
        '<p class="lead">Resumo em linguagem simples de como a ferramenta interpreta os achados.</p>'
        f'<ul class="bullets">{bullets_html}</ul>'
        '</div>'
        '<div>'
        '<h2>Legenda de Relevância</h2>'
        f'<table class="relevance-table">{table_html}</table>'
        '</div>'
        '</section>'
    )


def _build_complete_report_body(summary) -> str:
    result_sets = _part_result_sets(summary)
    part_defs = [
        ("direct", "Parte 1: DIRECT_IP_BLACKLISTS", "Dados e graficos filtrados apenas por blacklists diretas de IP."),
        ("network", "Parte 2: NETWORK_SCOPE_BLACKLISTS", "Dados e graficos filtrados apenas por listas de escopo de rede, bloco, provedor ou ASN."),
        ("asn_drop", "Parte 3: ASN-DROP", "Resultado exclusivo da consulta ASN-DROP."),
        ("informational", "Parte 4: Listas Informativas", "Dados e graficos filtrados apenas por listas de carater informativo."),
    ]
    visual_titles = [
        "Distribuição de Reputação",
        "IPs por Blacklist",
    ]
    body_parts: list[str] = []
    body_parts.append(_plain_methodology_html())
    body_parts.append(_asn_overview_html(summary))
    availability = _online_status_chart_html(summary)
    if availability:
        body_parts.append(availability)
    body_parts.append(_execution_metadata_html(summary))
    for key, title, description in part_defs:
        body_parts.append(_chapter_html(title, description))
        if key == "asn_drop":
            body_parts.append(_asn_drop_part_html(summary))
            continue

        part_results = result_sets[key]
        if not part_results:
            body_parts.append(_empty_part_html("Nenhuma ocorrencia nesta categoria."))
            continue

        part_summary = _summary_for_part(summary, part_results)
        part_html = _original_render_report_type2_html(part_summary)
        sections = _extract_report_sections(part_html)
        for section_title in visual_titles:
            section = sections.get(section_title)
            if section:
                body_parts.append(section)

    catalog = _blacklist_catalog_html()
    if catalog:
        body_parts.append(catalog)
    global_block_distribution = _block_distribution_html(summary, "Distribuição Geral por /24")
    if global_block_distribution:
        body_parts.append(global_block_distribution)
    block_inventory = _block_inventory_html(summary)
    if block_inventory:
        body_parts.append(block_inventory)
    inventory = _inventory_section_html(summary)
    if inventory:
        body_parts.append(inventory)
    return "".join(body_parts)


def _render_complete_report_in_original_shell(summary) -> str:
    html_text = _original_render_report_type2_html(summary)
    pattern = re.compile(
        r'(?s)(?P<prefix>.*?<div class="report">\s*<section>.*?</section>)(?P<body>.*?)(?P<suffix>\s*</div>\s*</div>\s*<div class="footer".*)'
    )
    match = pattern.search(html_text)
    if match:
        html_text = pattern.sub(
            match.group("prefix") + _build_complete_report_body(summary) + match.group("suffix"),
            html_text,
            count=1,
        )
    return _inject_report_enhancements(html_text, summary)


def _patched_render_report_type2_html(summary) -> str:
    return _render_complete_report_in_original_shell(summary)


def _patched_render_report_html(summary) -> str:
    return _render_complete_report_in_original_shell(summary)


RISK_HELP_TEXT = """

Classificacao de risco:
  Sem risco
      Bloco/ASN 100% limpo: nenhum IP listado, nenhuma evidencia de bloco/rede,
      nenhum ASN-DROP e nenhuma fonte informativa acionada.

  Baixo
      Apenas fontes informativas ou sinais fracos sem confirmacao direta.

  Moderado
      Evidencias diretas limitadas em DIRECT_IP_BLACKLISTS.

  Alto
      Volume relevante de IPs em DIRECT_IP_BLACKLISTS.

  Muito alto
      Qualquer incidencia em ASN-DROP ou NETWORK_SCOPE_BLACKLISTS,
      ou criticidade elevada em DIRECT_IP_BLACKLISTS.

Observacoes:
  - Blacklists de IP afetam IPs individuais.
  - Blacklists de bloco/rede afetam bloco/ASN, nao todos os IPs individualmente.
  - ASN-DROP e evidencia de escopo ASN/rede e nao marca cada IP como blacklistado.
  - Fontes informativas aparecem como contexto, mas nao elevam risco sozinhas.
"""

RISK_HELP_TEXT_EN = """

Risk classification:
  No risk
      100% clean block/ASN: no listed IPs, no network/block evidence,
      no ASN-DROP, and no informational-only source triggered.

  Low
      Informational-only sources or weak signals without direct confirmation.

  Moderate
      Limited direct evidence in DIRECT_IP_BLACKLISTS.

  High
      Relevant number of IPs listed in DIRECT_IP_BLACKLISTS.

  Very high
      Any ASN-DROP or NETWORK_SCOPE_BLACKLISTS finding,
      or elevated criticality in DIRECT_IP_BLACKLISTS.

Notes:
  - IP blacklists affect individual IPs.
  - Network/block blacklists affect the block/ASN, not every IP individually.
  - ASN-DROP is ASN/network-scope evidence and does not mark every IP as individually listed.
  - Informational sources remain context and do not raise risk by themselves.
"""


def _choose_scan_approach(value: str | None) -> str:
    if value in {"conservative", "aggressive"}:
        return value

    answer = clear_and_prompt(
        tr("prompt_approach")
    ).strip().lower()
    if answer in {"2", "a", "agressiva", "aggressive"}:
        return "aggressive"
    return "conservative"


def _show_selected_blacklists() -> None:
    selected = sorted(_selected_scan_blacklists())
    type_labels = {
        "ip": "DIRECT_IP_BLACKLISTS",
        "bloco": "NETWORK_SCOPE_BLACKLISTS",
        "informativo": "Listas informativas",
    }
    relevance_order = ["muito alta", "alta", "media", "baixa", "informacional"]
    grouped: dict[str, dict[str, list[str]]] = {}
    for name in selected:
        scope = _catalog_scope(name)
        relevance = _catalog_relevance(name)
        grouped.setdefault(scope, {}).setdefault(relevance, []).append(name)

    print("\nBlacklists selecionadas para consulta:")
    for scope in ["ip", "bloco", "informativo"]:
        if scope not in grouped:
            continue
        print(f"\n[{type_labels.get(scope, scope)}]")
        for relevance in relevance_order:
            names = grouped[scope].get(relevance, [])
            if not names:
                continue
            print(f"  {relevance}:")
            for name in names:
                print(f"    - {name}")
    print("")


def _choose_only_complete_report(_value: str | None) -> str:
    return "2"


def _patched_parse_args():
    help_text = ""
    try:
        help_name = "help_text.txt" if CURRENT_UI_LANG == "pt-BR" else "help_text_en.txt"
        help_file = Path(__file__).resolve().parent / "resources" / help_name
        help_text = help_file.read_text(encoding="utf-8")
    except OSError:
        help_text = tr("help_unavailable")

    parser = argparse.ArgumentParser(
        prog="inh",
        description=tr("arg_description"),
        epilog=f"{help_text}{RISK_HELP_TEXT if CURRENT_UI_LANG == 'pt-BR' else RISK_HELP_TEXT_EN}",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("target", nargs="?", help=SUPPORTED_INPUT if CURRENT_UI_LANG == "pt-BR" else SUPPORTED_INPUT_EN)
    parser.add_argument("--workers", type=int, default=0, help=tr("arg_workers"))
    parser.add_argument("--boost", action="store_true", default=None, help=tr("arg_boost"))
    parser.add_argument(
        "--approach",
        choices=("conservative", "aggressive"),
        help=tr("arg_approach"),
    )
    parser.add_argument("--report-type", choices=("1", "2"), help=tr("arg_report_type"))
    return parser.parse_args()


def _normalize_incomplete_inventory_rows(summary, results: list[CheckResult]) -> None:
    results_by_ip: dict[str, list[CheckResult]] = {}
    for result in results:
        if result.task.target_kind == "ip":
            results_by_ip.setdefault(result.task.target_value, []).append(result)

    for row in summary.inventory_rows:
        if row.get("status") != "timeout":
            continue
        if row.get("relevant") or row.get("informational"):
            continue

        ip_results = results_by_ip.get(str(row.get("ip")), [])
        completed_without_listing = any(
            result.status in {"not_listed", "whitelisted"}
            for result in ip_results
        )
        if completed_without_listing:
            row["status"] = "clean"


def _apply_weighted_inventory_risk(summary, results: list[CheckResult]) -> None:
    direct_by_ip: dict[str, list[CheckResult]] = {}
    informational_by_ip: dict[str, list[CheckResult]] = {}
    network_by_ip = _block_results_by_ip(results, {"listed"})
    degraded_by_ip = _timeout_error_results_by_ip(results)

    for result in results:
        if result.status != "listed" or result.task.target_kind != "ip":
            continue
        source_type = _source_part(result.task.blacklist)
        if source_type == "direct":
            direct_by_ip.setdefault(result.task.target_value, []).append(result)
        elif source_type == "informational":
            informational_by_ip.setdefault(result.task.target_value, []).append(result)

    for row in summary.inventory_rows:
        ip_value = str(row.get("ip"))
        analysis = _analyze_ip_results(
            ip_value,
            direct_by_ip.get(ip_value, []),
            network_by_ip.get(ip_value, []),
            informational_by_ip.get(ip_value, []),
            [result for result in degraded_by_ip.get(ip_value, []) if result.status == "timeout"],
            [result for result in degraded_by_ip.get(ip_value, []) if result.status == "error"],
        )
        row.update(analysis)


def _ip_risk_level_from_inventory(summary) -> str:
    statuses = {str(row.get("status")) for row in summary.inventory_rows}
    if "very_high" in statuses:
        return "Muito alto"
    if "high" in statuses:
        return "Alto"
    if "medium" in statuses:
        return "Moderado"
    if "informational" in statuses:
        return "Baixo"
    return "Sem risco"


def _overall_risk_level(summary) -> str:
    return str(getattr(summary, "report_risk_label", "Sem risco"))


def _decorate_summary(summary, results: list[CheckResult]):
    summary.all_results = list(results)
    summary.scan_metadata = dict(getattr(summary, "scan_metadata", {}))
    _normalize_incomplete_inventory_rows(summary, results)
    _apply_weighted_inventory_risk(summary, results)
    asn_drop_result = _asn_drop_result(results)
    asn_drop_line = _asn_drop_detail_line(asn_drop_result)
    asn_drop_status, asn_drop_details = _asn_drop_status_fields(asn_drop_result)

    lang = _summary_ui_lang(summary)
    mode_line = tr(
        "method_scope_auto",
        lang=lang,
    )

    if mode_line not in summary.details:
        summary.details = [mode_line, *summary.details]
    if mode_line not in summary.methodology_lines:
        summary.methodology_lines = [mode_line, *summary.methodology_lines]

    severity_line = tr(
        "method_dnsbl_codes",
        lang=lang,
    )
    if severity_line not in summary.methodology_lines:
        summary.methodology_lines = [*summary.methodology_lines, severity_line]

    if asn_drop_line and asn_drop_line not in summary.details:
        summary.details = [*summary.details, asn_drop_line]
    asn_drop_context_line = f"ASN-DROP: {asn_drop_status} ({asn_drop_details})"
    if asn_drop_result is not None and asn_drop_context_line not in summary.asn_context_lines:
        summary.asn_context_lines = [asn_drop_context_line, *summary.asn_context_lines]
    if asn_drop_result is not None:
        asn_drop_method_line = tr(
            "method_asn_drop_scope",
            lang=lang,
        )
        if asn_drop_method_line not in summary.methodology_lines:
            summary.methodology_lines = [*summary.methodology_lines, asn_drop_method_line]

    curation_line = tr(
        "method_source_curation",
        lang=lang,
    )
    if curation_line not in summary.methodology_lines:
        summary.methodology_lines = [*summary.methodology_lines, curation_line]

    excluded_note = tr(
        "method_out_of_scope_sources",
        lang=lang,
    )
    if excluded_note not in summary.excluded_sources:
        summary.excluded_sources = [*summary.excluded_sources, excluded_note]

    block_results = [
        result
        for result in results
        if result.status == "listed"
        and (
            _source_part(result.task.blacklist) == "network"
            or result.task.target_kind == "block"
        )
    ]

    block_hits_by_blacklist: dict[str, set[str]] = {}
    for result in block_results:
        block_hits_by_blacklist.setdefault(result.task.blacklist, set()).add(result.task.target_value)

    if block_hits_by_blacklist:
        highest_block_severity = "informacional"
        block_findings = []
        for blacklist, targets in sorted(block_hits_by_blacklist.items()):
            severity = _severity_for(blacklist)
            if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(highest_block_severity, 0):
                highest_block_severity = severity
            block_findings.append(
                f"{blacklist} ({severity}) indicou reputacao de bloco para {len(targets)} endereco(s) consultado(s); evidencia aplicada ao bloco/ASN, nao a cada IP."
            )

        summary.critical_findings = [*block_findings, *summary.critical_findings]

    summary.direct_inventory_rows = _direct_inventory_rows_from_results(results)
    summary.direct_results = _part_results(results, "direct")
    summary.network_scope_results = _part_results(results, "network")
    summary.informational_results = _part_results(results, "informational")
    summary.network_scope_listed = bool(block_hits_by_blacklist)

    if summary.asn_drop_listed:
        finding = f"ASN listado em Spamhaus ASN-DROP (muito alta): {'; '.join(summary.asn_drop_details) if summary.asn_drop_details else 'registro encontrado'}."
        if finding not in summary.critical_findings:
            summary.critical_findings = [finding, *summary.critical_findings]

    report_analysis = _analyze_report_risk(summary, results)
    for key, value in report_analysis.items():
        setattr(summary, key, value)
    summary.risk_level = summary.report_risk_label
    summary.risk_reason = list(summary.report_risk_reason)

    summary.relevance_legend = [
        "Muito alta: fonte prioritária, forte impacto reputacional.",
        "Alta: sinal importante para bloqueio operacional.",
        "Media: evidencia relevante, normalmente exige correlacao.",
        "Informacional: contexto tecnico; nao qualifica isoladamente o objeto como blacklistado.",
    ]
    _compress_blacklist_groups(summary)
    return summary


def _patched_build_scan_summary(*, kind: str, original_input: str, normalized_input: str, detected_mode: str, details: list[str], metadata: dict[str, object], results: list[CheckResult]) -> ScanSummary:
    summary = _original_build_scan_summary(
        kind=kind,
        original_input=original_input,
        normalized_input=normalized_input,
        detected_mode=detected_mode,
        details=details,
        metadata=metadata,
        results=results,
    )
    summary.scan_metadata = dict(metadata)
    summary.scan_metadata["ui_language"] = _summary_ui_lang()
    return _decorate_summary(summary, results)


def _patched_run_scan(original_input: str, requested_workers: int, boost: bool, report_type: str) -> int:
    _set_scan_scope(_original)
    globals()["build_scan_summary"] = _patched_build_scan_summary
    _original.build_scan_summary = _patched_build_scan_summary
    globals()["build_asn_box_lines"] = _patched_build_asn_box_lines
    _original.build_asn_box_lines = _patched_build_asn_box_lines
    globals()["write_json_summary"] = _patched_write_json_summary
    _original.write_json_summary = _patched_write_json_summary
    globals()["render_report_type2_html"] = _patched_render_report_type2_html
    _original.render_report_type2_html = _patched_render_report_type2_html
    globals()["render_report_html"] = _patched_render_report_html
    _original.render_report_html = _patched_render_report_html
    globals()["_inventory_risk_label"] = _inventory_status_label
    _original._inventory_risk_label = _inventory_status_label
    globals()["_risk_badge_class"] = _patched_risk_badge_class
    _original._risk_badge_class = _patched_risk_badge_class
    globals()["_compress_ip_ranges"] = _patched_compress_ip_ranges
    _original._compress_ip_ranges = _patched_compress_ip_ranges
    globals()["execute_task"] = _patched_execute_task
    _original.execute_task = _patched_execute_task
    original_terminal_box = _original.TerminalUI._box

    def patched_terminal_box(self, title, raw_lines, width, height=None, nowrap=False):
        if title == "Atividade Recente":
            styled_lines = []
            for line in raw_lines:
                text = str(line)
                if text.startswith("Timeout:"):
                    styled_lines.append(f"{ANSI['yellow']}{text}{ANSI['reset']}")
                elif text.startswith("Positivo:"):
                    styled_lines.append(f"{ANSI['bg_red']}\033[97m{text}{ANSI['reset']}")
                else:
                    styled_lines.append(text)
            raw_lines = styled_lines
        return original_terminal_box(self, title, raw_lines, width, height=height, nowrap=nowrap)

    _original.TerminalUI._box = patched_terminal_box

    original_build_tasks = _original.build_tasks

    def build_tasks_with_mode(kind, value):
        tasks, details, detected_mode, metadata = original_build_tasks(kind, value)
        metadata = dict(metadata)
        metadata["scan_scope_mode"] = "auto"
        metadata["inventory_all_ips"] = INVENTORY_ALL_IPS_DEFAULT
        if any(task.query_mode == "asn_drop" for task in tasks):
            asn_box_lines = list(metadata.get("asn_box_lines", []))
            asn_drop_panel_line = "ASN-DROP: consultado; status final exibido no relatorio e logs finais."
            if asn_drop_panel_line not in asn_box_lines:
                asn_box_lines.append(asn_drop_panel_line)
            metadata["asn_box_lines"] = asn_box_lines
            details = [*details, "ASN-DROP: consultado"]
        scoped_tasks = []
        for task in tasks:
            if _source_part(task.blacklist) == "network" and task.target_kind == "ip":
                block_target = _block_target_for_ip(task.target_value, metadata)
                scoped_tasks.append(CheckTask(
                    query_mode=task.query_mode,
                    target_kind="block",
                    target_value=block_target,
                    query_name=task.query_name,
                    blacklist=task.blacklist,
                    label=f"Bloco/contexto {block_target}",
                ))
            else:
                scoped_tasks.append(task)
        return scoped_tasks, details, detected_mode, metadata

    _original.build_tasks = build_tasks_with_mode
    try:
        return _original_run_scan(original_input, requested_workers, boost, report_type)
    finally:
        _original.build_tasks = original_build_tasks
        _original.build_asn_box_lines = _original_build_asn_box_lines
        _original.write_json_summary = _original_write_json_summary
        _original.render_report_type2_html = _original_render_report_type2_html
        _original.render_report_html = _original_render_report_html
        _original.execute_task = _original_execute_task
        _original.TerminalUI._box = original_terminal_box
        _original._inventory_risk_label = _original_inventory_risk_label
        _original._risk_badge_class = _original_risk_badge_class
        _original._compress_ip_ranges = _original_compress_ip_ranges
        _original.BLACKLISTS = list(ORIGINAL_BLACKLISTS)
        globals()["BLACKLISTS"] = list(ORIGINAL_BLACKLISTS)
        globals()["_compress_ip_ranges"] = _original_compress_ip_ranges


def _patched_main() -> int:
    ensure_dependencies()
    try:
        global CURRENT_SCAN_APPROACH
        global INVENTORY_ALL_IPS_DEFAULT
        args = parse_args()
        _prompt_language_preference()
        if args.target is None:
            _print_start_menu()
        target = args.target or clear_and_prompt(tr("prompt_target"))
        CURRENT_SCAN_APPROACH = _choose_scan_approach(args.approach)
        INVENTORY_ALL_IPS_DEFAULT = _choose_full_inventory_mode(target)
        report_type = _choose_only_complete_report(args.report_type)
        boost_mode = choose_boost_mode(args.boost)
        RUN_CONTEXT.clear()
        RUN_CONTEXT.update(
            {
                "started_at": datetime.now().astimezone(),
                "username": getpass.getuser(),
                "os": platform.platform(),
                "language": CURRENT_UI_LANG,
            }
        )
        return _patched_run_scan(target, args.workers, boost_mode, report_type)
    except KeyboardInterrupt:
        print(f"\n{tr('cancelled')}")
        return 130
    except (RuntimeError, ValueError, socket.gaierror) as exc:
        print(f"{tr('error_prefix')}: {exc}", file=sys.stderr)
        return 2


_original = _load_original_module()
ORIGINAL_BLACKLISTS = list(_original.BLACKLISTS)
_original_build_scan_summary = _original.build_scan_summary
_original_build_asn_box_lines = _original.build_asn_box_lines
_original_write_json_summary = _original.write_json_summary
_original_render_report_type2_html = _original.render_report_type2_html
_original_render_report_html = _original.render_report_html
_original_execute_task = _original.execute_task
_original_inventory_risk_label = _original._inventory_risk_label
_original_risk_badge_class = _original._risk_badge_class
_original_compress_ip_ranges = _original._compress_ip_ranges
_original_run_scan = _original.run_scan

for _name, _value in _original.__dict__.items():
    if _name in {"__builtins__", "__cached__", "__file__", "__loader__", "__name__", "__package__", "__spec__"}:
        continue
    globals()[_name] = _value

APP_NAME = "INH - ISP - Network Health"
parse_args = _patched_parse_args
build_scan_summary = _patched_build_scan_summary
run_scan = _patched_run_scan
choose_report_type = _choose_only_complete_report
main = _patched_main


if __name__ == "__main__":
    raise SystemExit(main())
