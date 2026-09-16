from __future__ import annotations

import html
import ipaddress
import re
from collections import defaultdict
from datetime import datetime
from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


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
        return str(ipaddress.ip_network(f"{address}/24", strict=False))
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
    visible = detected or incomplete or [{"name": "Limpo", "label": "Limpo", "tone": "clean", "state": "clean", "title": "Nenhuma blacklist detectou este IP."}]
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


def _subnet24_count(scan: dict[str, Any], groups: list[dict[str, Any]], ip_rows: dict[str, Any]) -> int:
    subnets = set()
    for address in ip_rows:
        try:
            subnets.add(str(ipaddress.ip_network(f"{address}/24", strict=False)))
        except ValueError:
            pass
    if subnets:
        return len(subnets)
    network = _target_network(scan)
    if not network:
        return len(groups)
    if network.prefixlen >= 24:
        return 1
    return 2 ** (24 - network.prefixlen)


def build_report_model(scan: dict[str, Any], results: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate one database row per query into one row per IP and block."""
    checks_by_ip: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
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

    for block, group in groups_by_block.items():
        group["network_findings"] = sorted(network_findings.get(block, set()), key=str.casefold)
        group["rows"].sort(key=lambda row: _sort_ip(row["ip"]))
        group["detected_count"] = sum(1 for row in group["rows"] if row["has_detection"])
        group["incomplete_count"] = sum(1 for row in group["rows"] if row["is_incomplete"])
        group["ip_count"] = len(group["rows"])
        group["has_findings"] = bool(group["network_findings"] or group["detected_count"])
        group["is_clean"] = not group["has_findings"] and not group["incomplete_count"]
        group["all_blacklists_count"] = len(all_blacklists)

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
    stats = {
        "scanned_ips": scanned_ips,
        "listed_ips": listed_ips,
        "clean_ips": max(0, scanned_ips - listed_ips - incomplete_ips),
        "incomplete_ips": incomplete_ips,
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
    return {
        "groups": groups,
        "featured": featured,
        "stats": stats,
        "global_findings": sorted(global_findings, key=str.casefold),
    }


def _pdf_paragraph(text: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(html.escape(str(text)).replace("\n", "<br/>"), style)


def _pdf_name(target: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", str(target)).strip("-.")
    return value or "scan"


def build_health_pdf(scan: dict[str, Any], results: list[dict[str, Any]]) -> bytes:
    """Build a readable PDF with automatic per-block expansion decisions."""
    model = build_report_model(scan, results)
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
        _pdf_paragraph(f"Relatório da análise #{scan.get('id', '—')} · alvo {scan.get('target', '—')}", subtitle),
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
        ("Sub-redes /24", stats["subnets_24"], "blocos de referência", colors.HexColor("#e9f2ff"), colors.HexColor("#245a9b")),
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
    summary_text = (
        f"Foram verificados {stats['scanned_ips']} endereços IP em {stats['subnets_24']} sub-redes /24, "
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
    story.extend([summary_box, Spacer(1, 5 * mm), _pdf_paragraph("Resultados por bloco", heading), _pdf_paragraph("Os blocos limpos permanecem recolhidos neste documento. Quando há detecção, o sistema expande automaticamente o bloco e mostra os endereços envolvidos.", subtitle), Spacer(1, 3 * mm)])

    for group in model["groups"]:
        expanded = bool(group["has_findings"])
        detected_label = f"{group['detected_count']} com detecção" if group["detected_count"] else "sem detecção"
        ip_label = "endereço IP" if group["ip_count"] == 1 else "endereços IP"
        block_summary = Table([[
            _pdf_paragraph(group["block"], block_heading),
            _pdf_paragraph(f"{group['ip_count']} {ip_label} · {detected_label}", small_right),
        ]], colWidths=[105 * mm, 69 * mm])
        block_summary.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), palette["red_light"] if expanded else palette["green_light"]),
            ("BOX", (0, 0), (-1, -1), 0.7, palette["red"] if expanded else palette["green"]),
            ("LINEBEFORE", (0, 0), (0, -1), 3, palette["red"] if expanded else palette["green"]),
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
            collapsed = Table([[_pdf_paragraph("Bloco recolhido automaticamente · nenhum IP apresentou detecção.", cell_muted)]], colWidths=[174 * mm])
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
        story.append(_pdf_paragraph("Nenhum resultado de IP foi armazenado para esta análise.", body))
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
