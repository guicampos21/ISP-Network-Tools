from __future__ import annotations

import html
import ipaddress
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.graphics.shapes import Drawing, Rect, String
from inh.core import blacklist_relevance


def scan_reference(scan: dict[str, Any]) -> str:
    created = _parse_datetime(scan.get("created_at"))
    if not created:
        return f"NH-{int(scan.get('id') or 0):06d}"
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    stamp = created.astimezone(timezone.utc).strftime("%Y%m%d-%H%M%S%f")
    # The database sequence guarantees uniqueness even for simultaneous scans.
    return f"NH-{stamp}-{int(scan.get('id') or 0):06d}"


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _human_datetime(value: Any) -> str:
    parsed = _parse_datetime(value)
    if not parsed:
        return "Indisponível"
    if parsed.tzinfo:
        parsed = parsed.astimezone()
    timezone = parsed.tzname() or ""
    suffix = f" {timezone}" if timezone else ""
    return parsed.strftime("%d/%m/%Y às %H:%M") + suffix


def _duration_label(start: Any, finish: Any) -> str:
    started = _parse_datetime(start)
    ended = _parse_datetime(finish)
    if not started or not ended:
        return "Indisponível"
    seconds = max(0, int((ended - started).total_seconds()))
    if seconds < 60:
        return f"{seconds} s"
    minutes, remainder = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes} min {remainder:02d} s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} h {minutes:02d} min"


def _duration_ms(start: Any, finish: Any) -> int:
    started = _parse_datetime(start)
    ended = _parse_datetime(finish)
    if not started or not ended:
        return 0
    return max(0, int((ended - started).total_seconds() * 1000))


def _sort_ip(value: str) -> tuple[int, int | str]:
    try:
        address = ipaddress.ip_address(value)
        return (address.version, int(address))
    except ValueError:
        return (9, value)


def _network_sort(value: str) -> tuple[int, int | str, int]:
    try:
        network = ipaddress.ip_network(value, strict=False)
        return (network.version, int(network.network_address), network.prefixlen)
    except ValueError:
        return (9, value, 0)


def _target_network(scan: dict[str, Any]) -> ipaddress.IPv4Network | None:
    if str(scan.get("target_kind", "")) != "cidr":
        return None
    try:
        network = ipaddress.ip_network(str(scan.get("target", "")), strict=False)
    except ValueError:
        return None
    return network if network.version == 4 else None


def _block_for_ip(address: str, scan: dict[str, Any]) -> str:
    target_network = _target_network(scan)
    if target_network and target_network.prefixlen > 24:
        return str(target_network)
    try:
        prefix_length = 24 if target_network or scan.get("target_kind") == "asn" else 32
        return str(ipaddress.ip_network(f"{address}/{prefix_length}", strict=False))
    except ValueError:
        return "Bloco não identificado"


def _blocks_for_network(value: str, scan: dict[str, Any]) -> list[str]:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        target_network = _target_network(scan)
        return [str(target_network)] if target_network else []
    if network.version != 4:
        return []
    if network.prefixlen > 24:
        return [str(network)]
    return [str(item) for item in network.subnets(new_prefix=24)] if network.prefixlen < 24 else [str(network)]


def _status_state(checks: list[dict[str, Any]]) -> tuple[str, str, str]:
    statuses = {str(check.get("status", "")).lower() for check in checks}
    if "listed" in statuses:
        return "detected", "Detectado", "listed"
    if statuses & {"timeout", "error"}:
        return "incomplete", "Não concluído", "warning"
    return "clean", "Limpo", "clean"


def _blacklist_status(name: str, checks: list[dict[str, Any]]) -> dict[str, Any]:
    state, label, tone = _status_state(checks)
    answers: list[str] = []
    for check in checks:
        for answer in check.get("answers") or []:
            value = str(answer)
            if value and value not in answers:
                answers.append(value)
    detail = ", ".join(answers)
    if name.endswith(".spamhaus.org") and any(answer.startswith("127.255.255.") for answer in answers):
        detail = "Consulta recusada pelo Spamhaus: política do resolvedor ou limite de consultas. " + detail
    return {
        "name": name,
        "state": state,
        "label": label,
        "tone": tone,
        "detail": detail,
        "title": f"{name}: {label}" + (f" · {detail}" if detail else ""),
    }


def _ip_row(address: str, checks_by_blacklist: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    blacklists = [
        _blacklist_status(name, checks_by_blacklist[name])
        for name in sorted(checks_by_blacklist, key=str.casefold)
    ]
    detected = [item for item in blacklists if item["state"] == "detected"]
    incomplete = [item for item in blacklists if item["state"] == "incomplete"]
    state = "detected" if detected else "incomplete" if incomplete else "clean"
    visible = detected or incomplete[:3] or [{"name": "Limpo", "label": "Limpo", "tone": "clean", "state": "clean", "title": "Nenhuma blacklist detectou este alvo."}]
    if not detected and len(incomplete) > 3:
        visible = [*visible, {"name": f"+{len(incomplete) - 3} inconclusivas", "tone": "warning", "title": "Passe o mouse ou use o foco para ver todas as fontes."}]
    return {
        "ip": address,
        "blacklists": blacklists,
        "detected_blacklists": detected,
        "incomplete_blacklists": incomplete,
        "visible_blacklists": visible,
        "state": state,
        "has_detection": bool(detected),
        "is_incomplete": bool(incomplete),
        "detected_names": [item["name"] for item in detected],
        "consulted_count": len(blacklists),
    }


def _risk_value(scan: dict[str, Any]) -> str:
    summary = scan.get("summary_json")
    if isinstance(summary, dict):
        return str(summary.get("risk_level") or "Indisponível")
    return "Indisponível"


def _risk_slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "indisponivel"


def report_target_label(scan: dict[str, Any]) -> str:
    """Show an individual IPv4 with the CIDR mask used by the report."""
    target = str(scan.get("target") or "").strip()
    if str(scan.get("target_kind") or "") == "ip":
        try:
            return f"{ipaddress.ip_address(target)}/32"
        except ValueError:
            return target
    return target


def _subnet24_count(scan: dict[str, Any], groups: list[dict[str, Any]], ip_rows: dict[str, Any]) -> int:
    network = _target_network(scan)
    if network:
        return 2 ** (24 - network.prefixlen) if network.prefixlen <= 24 else 0
    if scan.get("target_kind") != "asn":
        return 0
    return sum(not group.get("is_domain") and group["block"].endswith("/24") for group in groups)


def _scope_presentation(scan: dict[str, Any], stats: dict[str, Any]) -> dict[str, Any]:
    network = _target_network(scan)
    kind = scan.get("target_kind")
    individual = kind == "ip" or (network is not None and network.prefixlen == 32)
    count = stats["scanned_ips"]
    noun = "endereço IP" if count == 1 else "endereços IP"
    coverage = f"{'Foi verificado' if count == 1 else 'Foram verificados'} {count} {noun}"
    presentation = {
        "scope_label": "Sub-redes /24", "scope_value": stats["subnets_24"],
        "scope_detail": "blocos analisados", "results_heading": "Resultados por bloco",
        "chart_scope_heading": "Situação por bloco",
    }
    if individual:
        target = str(network) if network else str(ipaddress.ip_network(f"{scan['target']}/32"))
        presentation.update(scope_label="Prefixo informado", scope_value=target,
                            scope_detail="endereço IPv4 individual", results_heading="Resultado do endereço IP",
                            chart_scope_heading="Situação do endereço IP")
        coverage = f"Foi verificado o endereço IP {target}"
    elif network and network.prefixlen > 24:
        presentation.update(scope_label="Bloco analisado", scope_value=str(network), scope_detail="prefixo informado")
        coverage += f" no bloco {network}"
    elif kind == "domain":
        domains = stats["scanned_domains"]
        presentation.update(scope_label="Domínios analisados", scope_value=domains,
                            scope_detail="alvos consultados", results_heading="Resultados por alvo",
                            chart_scope_heading="Situação dos endereços resolvidos")
        coverage = f"{'Foi analisado' if domains == 1 else 'Foram analisados'} {domains} {'domínio' if domains == 1 else 'domínios'}"
        if count:
            coverage += f" e {count} {noun} resolvidos"
    elif stats["subnets_24"]:
        subnets = stats["subnets_24"]
        coverage += f" em {subnets} {'sub-rede /24' if subnets == 1 else 'sub-redes /24'}"
    presentation["coverage_description"] = coverage
    return presentation


def build_report_model(scan: dict[str, Any], results: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate one database row per query into one row per IP and block."""
    checks_by_ip: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    checks_by_domain: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    network_findings: dict[str, set[str]] = defaultdict(set)
    all_blacklists: set[str] = set()
    global_findings: set[str] = set()

    for raw_result in results:
        result = dict(raw_result)
        blacklist = str(result.get("blacklist") or "").strip()
        if blacklist:
            all_blacklists.add(blacklist)
        target_kind = str(result.get("target_kind") or "")
        target_value = str(result.get("target_value") or "").strip()
        if target_kind == "domain" and target_value and blacklist:
            checks_by_domain[target_value][blacklist].append(result)
        if target_kind == "ip":
            try:
                address = ipaddress.ip_address(target_value)
            except ValueError:
                continue
            if address.version == 4 and blacklist:
                checks_by_ip[str(address)][blacklist].append(result)
            continue
        if str(result.get("status", "")).lower() != "listed":
            continue
        if target_kind == "block":
            for block in _blocks_for_network(target_value, scan):
                network_findings[block].add(blacklist or "Fonte de rede")
        elif blacklist:
            global_findings.add(blacklist)

    groups_by_block: dict[str, dict[str, Any]] = {}
    rows_by_ip: dict[str, dict[str, Any]] = {}
    for address, checks in checks_by_ip.items():
        block = _block_for_ip(address, scan)
        rows_by_ip[address] = _ip_row(address, checks)
        group = groups_by_block.setdefault(
            block,
            {
                "block": block,
                "rows": [],
                "network_findings": set(),
            },
        )
        group["rows"].append(rows_by_ip[address])

    target_network = _target_network(scan)
    if not groups_by_block and target_network:
        blocks = [str(target_network)] if target_network.prefixlen >= 24 else [str(item) for item in target_network.subnets(new_prefix=24)]
        for block in blocks:
            groups_by_block[block] = {"block": block, "rows": [], "network_findings": set()}

    domain_rows = [_ip_row(domain, checks) for domain, checks in checks_by_domain.items()]
    for row in domain_rows:
        groups_by_block[row["ip"]] = {"block": row["ip"], "rows": [row], "network_findings": set(), "is_domain": True}

    for block, group in groups_by_block.items():
        group["network_findings"] = sorted(network_findings.get(block, set()), key=str.casefold)
        group["rows"].sort(key=lambda row: _sort_ip(row["ip"]))
        group["detected_count"] = sum(1 for row in group["rows"] if row["has_detection"])
        group["incomplete_count"] = sum(1 for row in group["rows"] if row["is_incomplete"] and not row["has_detection"])
        group["ip_count"] = len(group["rows"])
        group["has_findings"] = bool(group["network_findings"] or group["detected_count"])
        group["is_clean"] = not group["has_findings"] and not group["incomplete_count"]
        group["tone"] = "listed" if group["has_findings"] else "warning" if group["incomplete_count"] else "clean"
        group["clean_count"] = max(0, group["ip_count"] - group["detected_count"] - group["incomplete_count"])
        group["all_blacklists_count"] = len(all_blacklists)
        group["display_block"] = (
            group["rows"][0]["ip"]
            if group["block"].endswith("/32") and len(group["rows"]) == 1
            else group["block"]
        )

    groups = sorted(groups_by_block.values(), key=lambda group: _network_sort(group["block"]))
    listed_ips = sum(1 for row in rows_by_ip.values() if row["has_detection"])
    incomplete_ips = sum(1 for row in rows_by_ip.values() if row["is_incomplete"] and not row["has_detection"])
    scanned_ips = len(rows_by_ip)
    summary = scan.get("summary_json") if isinstance(scan.get("summary_json"), dict) else {}
    if not scanned_ips:
        try:
            scanned_ips = int(summary.get("unique_ips_scanned") or 0)
        except (TypeError, ValueError):
            scanned_ips = 0
    featured = [row for row in sorted(rows_by_ip.values(), key=lambda row: _sort_ip(row["ip"])) if row["has_detection"]][:6]
    risk_level = _risk_value(scan)
    has_detection = bool(listed_ips or global_findings or any(group["has_findings"] for group in groups))
    incomplete_checks = sum(1 for result in results if result.get("status") in {"timeout", "error"})
    if not has_detection and (incomplete_checks or not results):
        risk_level = "Inconclusivo"
    elif has_detection and risk_level in {"Sem evidencias relevantes", "Sem evidências relevantes", "Indisponível"}:
        risk_level = "Detecções encontradas"
    stats = {
        "scanned_ips": scanned_ips,
        "listed_ips": listed_ips,
        "clean_ips": max(0, scanned_ips - listed_ips - incomplete_ips),
        "incomplete_ips": incomplete_ips,
        "scanned_domains": len(domain_rows),
        "listed_domains": sum(1 for row in domain_rows if row["has_detection"]),
        "incomplete_domains": sum(1 for row in domain_rows if row["is_incomplete"] and not row["has_detection"]),
        "subnets_24": _subnet24_count(scan, groups, rows_by_ip),
        "consulted_blacklists": len(all_blacklists),
        "timeouts": sum(1 for result in results if str(result.get("status", "")).lower() == "timeout"),
        "errors": sum(1 for result in results if str(result.get("status", "")).lower() == "error"),
        "risk_level": risk_level,
        "risk_slug": _risk_slug(risk_level),
        "started_label": _human_datetime(scan.get("started_at")),
        "finished_label": _human_datetime(scan.get("finished_at")),
        "duration_label": _duration_label(scan.get("started_at"), scan.get("finished_at")),
        "duration_ms": _duration_ms(scan.get("started_at"), scan.get("finished_at")),
        "unique_blacklists": sorted(all_blacklists, key=str.casefold),
    }
    stats.update(_scope_presentation(scan, stats))
    charts = _report_charts(groups, rows_by_ip, results)
    return {
        "groups": groups,
        "featured": featured,
        "stats": stats,
        "global_findings": sorted(global_findings, key=str.casefold),
        "charts": charts,
    }


def build_summary_report_model(scan: dict[str, Any]) -> dict[str, Any]:
    """Build a bounded report from the aggregate persisted when a scan finishes."""
    summary = scan.get("summary_json") if isinstance(scan.get("summary_json"), dict) else {}

    def number(name: str, fallback: int = 0) -> int:
        try:
            return max(0, int(summary.get(name, fallback) or 0))
        except (TypeError, ValueError):
            return fallback

    scanned_ips = number("unique_ips_scanned")
    listed_ips = min(scanned_ips, number("unique_ips_listed"))
    clean_ips = min(max(0, scanned_ips - listed_ips), number("unique_ips_clean"))
    incomplete_ips = max(0, scanned_ips - listed_ips - clean_ips)
    total_checks = number("total_checks", int(scan.get("total_checks") or 0))
    target_count = max(1, scanned_ips)
    consulted_blacklists = round(total_checks / target_count) if total_checks else 0
    risk_level = _risk_value(scan)
    stats = {
        "scanned_ips": scanned_ips,
        "listed_ips": listed_ips,
        "clean_ips": clean_ips,
        "incomplete_ips": incomplete_ips,
        "scanned_domains": 1 if scan.get("target_kind") == "domain" else 0,
        "listed_domains": 1 if scan.get("target_kind") == "domain" and number("listed_results") else 0,
        "incomplete_domains": 0,
        "subnets_24": _subnet24_count(scan, [], {}),
        "consulted_blacklists": consulted_blacklists,
        "timeouts": number("timeout_results"),
        "errors": number("error_results"),
        "risk_level": risk_level,
        "risk_slug": _risk_slug(risk_level),
        "started_label": _human_datetime(scan.get("started_at")),
        "finished_label": _human_datetime(scan.get("finished_at")),
        "duration_label": _duration_label(scan.get("started_at"), scan.get("finished_at")),
        "duration_ms": _duration_ms(scan.get("started_at"), scan.get("finished_at")),
        "unique_blacklists": [],
        "summary_only": True,
    }
    stats.update(_scope_presentation(scan, stats))

    counts = [listed_ips, clean_ips, incomplete_ips]
    categories = [
        ("listed", "Com detecção", "#e56b79"),
        ("clean", "Sem detecção", "#69dfa5"),
        ("warning", "Inconclusivos", "#e2b35b"),
    ]
    distribution = []
    offset = 0.0
    for (tone, label, color), count in zip(categories, counts):
        percent = round(count * 100 / max(1, scanned_ips), 2)
        distribution.append({"tone": tone, "label": label, "color": color, "count": count, "percent": percent, "offset": -offset})
        offset += percent

    top_hits = []
    raw_top = summary.get("top_blacklists") or []
    parsed_top: list[tuple[str, int]] = []
    for item in raw_top:
        if isinstance(item, dict):
            name, count = item.get("name"), item.get("count")
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            name, count = item[0], item[1]
        else:
            continue
        try:
            parsed_top.append((str(name), max(0, int(count))))
        except (TypeError, ValueError):
            continue
    max_hits = max((count for _, count in parsed_top), default=1)
    for name, count in parsed_top[:6]:
        top_hits.append({"name": name, "count": count, "percent": round(count * 100 / max_hits, 2)})

    listed_ip_map = _summary_listed_ip_map(summary)
    groups = _summary_block_groups(scan, listed_ip_map, consulted_blacklists)
    chart_blocks = []
    for group in sorted(groups, key=lambda item: (-item["detected_count"], _network_sort(item["block"])))[:12]:
        listed_width = group["listed_percent"]
        chart_blocks.append({
            "block": group["block"],
            "ip_count": group["ip_count"],
            "segments": [
                {"x": 0, "width": listed_width, "color": "#e56b79", "label": "Com detecção", "count": group["detected_count"]},
                {"x": listed_width, "width": round(100 - listed_width, 2), "color": "#69dfa5", "label": "Sem detecção", "count": group["clean_count"]},
            ],
        })
    return {
        "groups": groups,
        "featured": [],
        "stats": stats,
        "global_findings": [],
        "charts": {"distribution": distribution, "blocks": chart_blocks, "total_blocks": len(groups), "top_hits": top_hits},
    }


def compact_listed_ip_results(results: list[dict[str, Any]]) -> list[list[Any]]:
    """Collapse positive result rows into the format persisted in summary_json."""
    listed: dict[str, set[str]] = defaultdict(set)
    for result in results:
        address = str(result.get("target_value") or "").strip()
        blacklist = str(result.get("blacklist") or "").strip()
        try:
            if ipaddress.ip_address(address).version != 4:
                continue
        except ValueError:
            continue
        if blacklist and blacklist_relevance(blacklist) != "informacional":
            listed[address].add(blacklist)
    return [
        [address, sorted(names, key=str.casefold)]
        for address, names in sorted(listed.items(), key=lambda item: _sort_ip(item[0]))
        if names
    ]


def _summary_listed_ip_map(summary: dict[str, Any]) -> dict[str, list[str]]:
    listed: dict[str, list[str]] = {}
    for item in summary.get("listed_ips") or []:
        if isinstance(item, dict):
            address, names = item.get("ip"), item.get("blacklists")
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            address, names = item[0], item[1]
        else:
            continue
        try:
            parsed = ipaddress.ip_address(str(address))
            if parsed.version != 4:
                continue
        except ValueError:
            continue
        listed[str(parsed)] = sorted({str(name) for name in (names or []) if name}, key=str.casefold)
    return listed


def _summary_block_groups(
    scan: dict[str, Any], listed_ip_map: dict[str, list[str]], consulted_blacklists: int,
) -> list[dict[str, Any]]:
    network = _target_network(scan)
    if not network or network.version != 4:
        return []
    blocks = list(network.subnets(new_prefix=24)) if network.prefixlen < 24 else [network]
    listed_by_block = Counter(
        str(ipaddress.ip_network(f"{address}/24", strict=False))
        for address in listed_ip_map
    )
    groups = []
    for block in blocks:
        listed_count = listed_by_block[str(block)]
        ip_count = int(block.num_addresses)
        listed_percent = round(listed_count * 100 / max(1, ip_count), 2)
        groups.append({
            "block": str(block),
            "display_block": str(block),
            "rows": [],
            "network_findings": [],
            "detected_count": listed_count,
            "incomplete_count": 0,
            "clean_count": max(0, ip_count - listed_count),
            "ip_count": ip_count,
            "has_findings": bool(listed_count),
            "is_clean": not listed_count,
            "tone": "listed" if listed_count else "clean",
            "all_blacklists_count": consulted_blacklists,
            "listed_percent": listed_percent,
            "lazy": True,
        })
    return groups


def build_summary_block_rows(scan: dict[str, Any], block_value: str) -> list[dict[str, Any]]:
    """Build the 256 address rows for one validated child /24."""
    target = _target_network(scan)
    try:
        block = ipaddress.ip_network(block_value, strict=True)
    except ValueError as exc:
        raise ValueError("Bloco /24 inválido.") from exc
    if not target or block.version != 4 or block.prefixlen != 24 or not block.subnet_of(target):
        raise ValueError("O bloco informado não pertence ao alvo desta análise.")
    summary = scan.get("summary_json") if isinstance(scan.get("summary_json"), dict) else {}
    listed = _summary_listed_ip_map(summary)
    return [
        {"ip": str(address), "detected_names": listed.get(str(address), []), "has_detection": str(address) in listed}
        for address in block
    ]


def _report_charts(groups, rows_by_ip, results) -> dict[str, Any]:
    categories = [("listed", "Com detecção", "#e56b79"), ("clean", "Limpos", "#69dfa5"), ("warning", "Inconclusivos", "#e2b35b")]
    counts = [
        sum(row["has_detection"] for row in rows_by_ip.values()),
        sum(not row["has_detection"] and not row["is_incomplete"] for row in rows_by_ip.values()),
        sum(not row["has_detection"] and row["is_incomplete"] for row in rows_by_ip.values()),
    ]
    distribution = []
    offset = 0.0
    for (tone, label, color), count in zip(categories, counts):
        percent = round(count * 100 / max(1, len(rows_by_ip)), 2)
        distribution.append({"tone": tone, "label": label, "color": color, "count": count, "percent": percent, "offset": -offset})
        offset += percent
    blocks = []
    for group in sorted((g for g in groups if not g.get("is_domain")), key=lambda g: (-g["detected_count"], -g["incomplete_count"], _network_sort(g["block"])) )[:12]:
        x = 0.0
        segments = []
        for (tone, label, color), key in zip(categories, ("detected_count", "clean_count", "incomplete_count")):
            width = round(group[key] * 100 / max(1, group["ip_count"]), 2)
            segments.append({"x": x, "width": width, "color": color, "label": label, "count": group[key]})
            x += width
        blocks.append({"block": group["display_block"], "ip_count": group["ip_count"], "segments": segments})
    hits: dict[str, set[str]] = defaultdict(set)
    for result in results:
        if result.get("status") == "listed":
            hits[str(result.get("blacklist"))].add(str(result.get("target_value")))
    top = sorted(hits.items(), key=lambda item: (-len(item[1]), item[0]))[:6]
    max_hits = max((len(addresses) for _, addresses in top), default=1)
    return {"distribution": distribution, "blocks": blocks, "total_blocks": sum(not g.get("is_domain") for g in groups), "top_hits": [{"name": name, "count": len(addresses), "percent": round(len(addresses) * 100 / max_hits, 2)} for name, addresses in top]}


def _pdf_paragraph(text: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(html.escape(str(text)).replace("\n", "<br/>"), style)


def _pdf_name(target: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", str(target)).strip("-.")
    return value or "scan"


def build_health_pdf(
    scan: dict[str, Any],
    results: list[dict[str, Any]] | None = None,
    *,
    model: dict[str, Any] | None = None,
) -> bytes:
    """Build a readable PDF with automatic per-block expansion decisions."""
    model = model or build_report_model(scan, results or [])
    stats = model["stats"]
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=14 * mm,
        leftMargin=14 * mm,
        topMargin=15 * mm,
        bottomMargin=16 * mm,
        title=f"ISP Network Health · {scan.get('target', '')}",
        author="ISP Network Tools",
    )
    palette = {
        "ink": colors.HexColor("#1b1730"),
        "muted": colors.HexColor("#586174"),
        "line": colors.HexColor("#d5dbe7"),
        "purple": colors.HexColor("#6926a8"),
        "purple_light": colors.HexColor("#f0e7fb"),
        "red": colors.HexColor("#a51d35"),
        "red_light": colors.HexColor("#fde8ed"),
        "green": colors.HexColor("#146b43"),
        "green_light": colors.HexColor("#e4f7ed"),
        "amber": colors.HexColor("#8a5a08"),
        "amber_light": colors.HexColor("#fff5d9"),
    }
    styles = getSampleStyleSheet()
    title = ParagraphStyle("ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=22, leading=26, textColor=palette["ink"], spaceAfter=3)
    subtitle = ParagraphStyle("ReportSubtitle", parent=styles["Normal"], fontSize=10, leading=14, textColor=palette["muted"])
    eyebrow = ParagraphStyle("ReportEyebrow", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=palette["purple"], spaceBefore=8, spaceAfter=4)
    heading = ParagraphStyle("ReportHeading", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=13, leading=16, textColor=palette["ink"], spaceBefore=8, spaceAfter=6)
    block_heading = ParagraphStyle("BlockHeading", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=palette["ink"])
    body = ParagraphStyle("ReportBody", parent=styles["Normal"], fontSize=9, leading=13, textColor=palette["ink"])
    small = ParagraphStyle("ReportSmall", parent=styles["Normal"], fontSize=7.5, leading=10, textColor=palette["muted"])
    small_right = ParagraphStyle("ReportSmallRight", parent=small, alignment=TA_RIGHT)
    cell = ParagraphStyle("ReportCell", parent=body, fontSize=8.5, leading=11)
    cell_muted = ParagraphStyle("ReportCellMuted", parent=cell, textColor=palette["muted"])
    story: list[Any] = [
        _pdf_paragraph("ISP Network Health", title),
        _pdf_paragraph(f"Relatório {scan_reference(scan)} · alvo {scan.get('target', '—')}", subtitle),
        Spacer(1, 5 * mm),
    ]
    metadata = Table(
        [
            [_pdf_paragraph("Perfil", small), _pdf_paragraph(str(scan.get("profile", "—")), body), _pdf_paragraph("Status", small), _pdf_paragraph(str(scan.get("status", "—")), body)],
            [_pdf_paragraph("Início", small), _pdf_paragraph(stats["started_label"], body), _pdf_paragraph("Fim", small), _pdf_paragraph(stats["finished_label"], body)],
        ],
        colWidths=[20 * mm, 54 * mm, 20 * mm, 72 * mm],
    )
    metadata.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f6f8fb")),
        ("BOX", (0, 0), (-1, -1), 0.6, palette["line"]),
        ("INNERGRID", (0, 0), (-1, -1), 0.35, palette["line"]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.extend([metadata, Spacer(1, 5 * mm), _pdf_paragraph("Resumo executivo", eyebrow)])

    kpi_values = [
        ("IPs verificados", stats["scanned_ips"], "endereços IP", palette["purple_light"], palette["purple"]),
        (stats["scope_label"], stats["scope_value"], stats["scope_detail"], colors.HexColor("#e9f2ff"), colors.HexColor("#245a9b")),
        ("Blacklists consultadas", stats["consulted_blacklists"], "fontes únicas", colors.HexColor("#fff5d9"), palette["amber"]),
        ("Tempo total", stats["duration_label"], "da abertura ao encerramento", colors.HexColor("#e4f7ed"), palette["green"]),
    ]
    kpi_cells = []
    for label, value, detail, background, foreground in kpi_values:
        value_style = ParagraphStyle(f"Kpi{label}", parent=body, fontName="Helvetica-Bold", fontSize=16 if isinstance(value, int) else 12, leading=19, textColor=foreground)
        kpi_cells.append([
            _pdf_paragraph(label, small),
            _pdf_paragraph(str(value), value_style),
            _pdf_paragraph(detail, small),
        ])
    kpis = Table([kpi_cells], colWidths=[43 * mm] * 4)
    kpis.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.6, palette["line"]),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, palette["line"]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ] + [("BACKGROUND", (index, 0), (index, 0), value[3]) for index, value in enumerate(kpi_values)]))
    story.extend([kpis, Spacer(1, 4 * mm)])
    if stats["scanned_ips"]:
        drawing = Drawing(480, 68)
        drawing.add(String(0, 53, "Situacao dos enderecos IP", fontName="Helvetica-Bold", fontSize=10))
        x = 0
        for item in model["charts"]["distribution"]:
            width = item["percent"] * 4.8
            if width:
                drawing.add(Rect(x, 23, width, 17, fillColor=colors.HexColor(item["color"]), strokeColor=None))
            x += width
        for index, item in enumerate(model["charts"]["distribution"]):
            drawing.add(String(index * 160, 7, f"{item['label']}: {item['count']} ({item['percent']}%)", fontSize=9))
        story.extend([drawing, Spacer(1, 3 * mm)])
    summary_text = (
        f"{stats['coverage_description']}, "
        f"consultando {stats['consulted_blacklists']} blacklists. O tempo total foi de {stats['duration_label']}. "
        f"Resultado de risco: {stats['risk_level']}."
    )
    summary_box = Table([[_pdf_paragraph(summary_text, body)]], colWidths=[174 * mm])
    summary_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fff8e8")),
        ("BOX", (0, 0), (-1, -1), 0.7, colors.HexColor("#d6a449")),
        ("LINEBEFORE", (0, 0), (0, -1), 3, colors.HexColor("#dc9b1b")),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
    ]))
    results_note = (
        "Visão consolidada por /24; os endereços IP individuais não são incluídos no PDF."
        if stats.get("summary_only")
        else "Os alvos sem detecção permanecem recolhidos neste documento. Quando há detecção, o sistema expande automaticamente os resultados."
    )
    story.extend([summary_box, Spacer(1, 5 * mm), _pdf_paragraph(stats["results_heading"], heading), _pdf_paragraph(results_note, subtitle), Spacer(1, 3 * mm)])

    report_groups = model["groups"]
    if stats.get("summary_only"):
        block_rows = [[
            _pdf_paragraph("Bloco /24", small),
            _pdf_paragraph("IPs analisados", small),
            _pdf_paragraph("IPs listados", small),
            _pdf_paragraph("Percentual listado", small),
        ]]
        block_rows.extend([
            _pdf_paragraph(group["block"], cell),
            _pdf_paragraph(str(group["ip_count"]), cell),
            _pdf_paragraph(str(group["detected_count"]), cell),
            _pdf_paragraph(f"{group['listed_percent']:.2f}%", cell),
        ] for group in report_groups)
        block_table = Table(block_rows, colWidths=[61 * mm, 37 * mm, 37 * mm, 39 * mm], repeatRows=1)
        block_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f2f6")),
            ("TEXTCOLOR", (0, 0), (-1, 0), palette["muted"]),
            ("BOX", (0, 0), (-1, -1), 0.45, palette["line"]),
            ("INNERGRID", (0, 0), (-1, -1), 0.35, palette["line"]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(block_table)
        report_groups = []

    for group in report_groups:
        expanded = bool(group["has_findings"])
        detected_label = f"{group['detected_count']} com detecção" if group["detected_count"] else "sem detecção"
        if group["incomplete_count"]:
            detected_label += f" · {group['incomplete_count']} inconclusivos"
        ip_label = "endereço IP" if group["ip_count"] == 1 else "endereços IP"
        block_summary = Table([[
            _pdf_paragraph(group["display_block"], block_heading),
            _pdf_paragraph(f"{group['ip_count']} {ip_label} · {detected_label}", small_right),
        ]], colWidths=[105 * mm, 69 * mm])
        block_summary.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), palette["red_light"] if expanded else palette["amber_light"] if group["incomplete_count"] else palette["green_light"]),
            ("BOX", (0, 0), (-1, -1), 0.7, palette["red"] if expanded else palette["amber"] if group["incomplete_count"] else palette["green"]),
            ("LINEBEFORE", (0, 0), (0, -1), 3, palette["red"] if expanded else palette["amber"] if group["incomplete_count"] else palette["green"]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 9),
            ("RIGHTPADDING", (0, 0), (-1, -1), 9),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ]))
        story.extend([Spacer(1, 3 * mm), block_summary])
        if group["network_findings"]:
            story.append(_pdf_paragraph("Detecção em consulta de rede: " + ", ".join(group["network_findings"]), ParagraphStyle("NetworkFinding", parent=small, textColor=palette["red"], spaceBefore=4)))
        if not expanded:
            collapsed = Table([[_pdf_paragraph("Resultado recolhido automaticamente · nenhuma detecção registrada." + (" Existem consultas inconclusivas." if group["incomplete_count"] else ""), cell_muted)]], colWidths=[174 * mm])
            collapsed.setStyle(TableStyle([
                ("BOX", (0, 0), (-1, -1), 0.45, palette["line"]),
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("LEFTPADDING", (0, 0), (-1, -1), 9),
                ("RIGHTPADDING", (0, 0), (-1, -1), 9),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(collapsed)
            continue
        table_rows = [[_pdf_paragraph("Endereço IP", small), _pdf_paragraph("Blacklists com detecção", small), _pdf_paragraph("Estado", small)]]
        for row in group["rows"]:
            if row["detected_names"]:
                detections = "<br/>".join(f'<font color="{palette["red"].hexval()}"><b>{html.escape(name)}</b></font>' for name in row["detected_names"])
                detections += f'<br/><font color="{palette["muted"].hexval()}">{row["consulted_count"]} fontes consultadas</font>'
            elif row["is_incomplete"]:
                detections = f'<font color="{palette["amber"].hexval()}">Consulta incompleta</font><br/><font color="{palette["muted"].hexval()}">{row["consulted_count"]} fontes consultadas</font>'
            else:
                detections = f'<font color="{palette["green"].hexval()}">Nenhuma detecção</font><br/><font color="{palette["muted"].hexval()}">{row["consulted_count"]} fontes consultadas</font>'
            status_color = palette["red"] if row["has_detection"] else palette["amber"] if row["is_incomplete"] else palette["green"]
            status_text = "Detectado" if row["has_detection"] else "Não concluído" if row["is_incomplete"] else "Limpo"
            table_rows.append([
                _pdf_paragraph(row["ip"], cell),
                Paragraph(detections, cell),
                Paragraph(f'<font color="{status_color.hexval()}"><b>{status_text}</b></font>', cell),
            ])
        result_table = Table(table_rows, colWidths=[38 * mm, 105 * mm, 31 * mm], repeatRows=1)
        result_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f2f6")),
            ("TEXTCOLOR", (0, 0), (-1, 0), palette["muted"]),
            ("BOX", (0, 0), (-1, -1), 0.45, palette["line"]),
            ("INNERGRID", (0, 0), (-1, -1), 0.35, palette["line"]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(result_table)

    if not model["groups"]:
        message = (
            "Este scan possui um volume elevado de consultas. O PDF apresenta o resumo consolidado "
            "persistido ao término da análise; o inventário individual de consultas foi omitido para "
            "manter o relatório disponível."
            if stats.get("summary_only")
            else "Nenhum resultado de IP foi armazenado para esta análise."
        )
        story.append(_pdf_paragraph(message, body))
    if stats["timeouts"] or stats["errors"]:
        story.extend([Spacer(1, 4 * mm), _pdf_paragraph(f"Atenção: {stats['timeouts']} timeouts e {stats['errors']} erros não representam detecção. Eles indicam consultas que não foram concluídas e reduzem a confiança do resultado.", ParagraphStyle("Warning", parent=body, textColor=palette["amber"]))])

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(palette["line"])
        canvas.line(14 * mm, 11 * mm, A4[0] - 14 * mm, 11 * mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(palette["muted"])
        canvas.drawString(14 * mm, 7 * mm, "ISP Network Tools · ISP Network Health")
        canvas.drawRightString(A4[0] - 14 * mm, 7 * mm, f"Página {doc.page}")
        canvas.restoreState()

    document.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


def pdf_filename(scan: dict[str, Any]) -> str:
    return f"isp-network-health-{_pdf_name(str(scan.get('target') or 'scan'))}-{scan.get('id', 'report')}.pdf"
