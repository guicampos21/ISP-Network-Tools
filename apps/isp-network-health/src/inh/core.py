#!/usr/bin/env python3
#
# Copyright (C) 2026 Guilherme Campos
# SPDX-License-Identifier: GPL-3.0-or-later
#

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import html
import json
import ipaddress
import math
import os
import re
import shutil
import socket
import subprocess
import sys
import textwrap
import time
import webbrowser
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib import request


APP_NAME = "ISP Network Health"

BLACKLISTS = [
    "0spamurl.fusionzero.com",
    "uribl.zeustracker.abuse.ch",
    "uribl.abuse.ro",
    "l1.apews.org",
    "dnsbl.aspnet.hu",
    "bsb.empty.us",
    "bsb.spamlookup.net",
    "ex.dnsbl.org",
    "in.dnsbl.org",
    "dnsbl.othello.ch",
    "ubl.nszones.com",
    "uribl.pofon.foobar.hu",
    "dyndns.rbl.jp",
    "url.rbl.jp",
    "abuse.rfc-clueless.org",
    "bogusmx.rfc-clueless.org",
    "dsn.rfc-clueless.org",
    "elitist.rfc-clueless.org",
    "fulldom.rfc-clueless.org",
    "postmaster.rfc-clueless.org",
    "whois.rfc-clueless.org",
    "rhsbl.rymsho.ru",
    "rhsbl.scientificspam.net",
    "nomail.rhsbl.sorbs.net",
    "badconf.rhsbl.sorbs.net",
    "rhsbl.sorbs.net",
    "fresh.spameatingmonkey.net",
    "fresh10.spameatingmonkey.net",
    "fresh15.spameatingmonkey.net",
    "uribl.spameatingmonkey.net",
    "urired.spameatingmonkey.net",
    "sbl.spamhaus.org",
    "multi.surbl.org",
    "uribl.swinog.ch",
    "dob.sibl.support-intelligence.net",
    "black.uribl.com",
    "grey.uribl.com",
    "multi.uribl.com",
    "red.uribl.com",
    "uri.blacklist.woody.ch",
    "rhsbl.zapbl.net",
    "hostkarma.junkemailfilter.com",
    "reputation-domain.rbl.scrolloutf1.com",
    "reputation-ns.rbl.scrolloutf1.com",
    "nobl.junkemailfilter.com",
    "iddb.isipp.com",
    "_vouch.dwl.spamhaus.org",
    "white.uribl.com",
    "list.anonwhois.net",
    "0spam-killlist.fusionzero.com",
    "0spam.fusionzero.com",
    "access.redhawk.org",
    "all.rbl.jp",
    "all.spam-rbl.fr",
    "all.spamrats.com",
    "aspews.ext.sorbs.net",
    "b.barracudacentral.org",
    "bl.mailspike.net",
    "backscatter.spameatingmonkey.net",
    "badnets.spameatingmonkey.net",
    "bb.barracudacentral.org",
    "bl.drmx.org",
    "bl.konstant.no",
    "bl.nszones.com",
    "bl.spamcannibal.org",
    "bl.spameatingmonkey.net",
    "bl.spamcop.net",
    "bl.spamstinks.com",
    "black.junkemailfilter.com",
    "blackholes.five-ten-sg.com",
    "blacklist.sci.kun.nl",
    "blacklist.woody.ch",
    "bogons.cymru.com",
    "cart00ney.surriel.com",
    "cbl.abuseat.org",
    "cbl.anti-spam.org.cn",
    "cblless.anti-spam.org.cn",
    "cblplus.anti-spam.org.cn",
    "cdl.anti-spam.org.cn",
    "cidr.bl.mcafee.com",
    "combined.rbl.msrbl.net",
    "db.wpbl.info",
    "dev.null.dk",
    "dialups.visi.com",
    "dnsbl-0.uceprotect.net",
    "dnsbl-1.uceprotect.net",
    "dnsbl-2.uceprotect.net",
    "dnsbl-3.uceprotect.net",
    "dnsbl.anticaptcha.net",
    "dnsbl.inps.de",
    "dnsbl.justspam.org",
    "dnsbl.kempt.net",
    "dnsbl.madavi.de",
    "dnsbl.rizon.net",
    "dnsbl.rv-soft.info",
    "dnsbl.rymsho.ru",
    "dnsbl.sorbs.net",
    "dnsbl.zapbl.net",
    "dnsrbl.swinog.ch",
    "dul.pacifier.net",
    "dyn.nszones.com",
    "dyna.spamrats.com",
    "fnrbl.fast.net",
    "images.rbl.msrbl.net",
    "ips.backscatterer.org",
    "ix.dnsbl.manitu.net",
    "korea.services.net",
    "l2.bbfh.ext.sorbs.net",
    "l3.bbfh.ext.sorbs.net",
    "l4.bbfh.ext.sorbs.net",
    "list.bbfh.org",
    "list.blogspambl.com",
    "mail-abuse.blacklist.jippg.org",
    "netbl.spameatingmonkey.net",
    "netscan.rbl.blockedservers.com",
    "no-more-funn.moensted.dk",
    "noptr.spamrats.com",
    "orvedb.aupads.org",
    "pbl.spamhaus.org",
    "phishing.rbl.msrbl.net",
    "pofon.foobar.hu",
    "psbl.surriel.com",
    "spam.abuse.ch",
    "rbl.abuse.ro",
    "rbl.blockedservers.com",
    "rbl.dns-servicios.com",
    "rbl.efnet.org",
    "rbl.efnetrbl.org",
    "rbl.iprange.net",
    "rbl.schulte.org",
    "rbl.talkactive.net",
    "rbl2.triumf.ca",
    "rsbl.aupads.org",
    "sbl-xbl.spamhaus.org",
    "sbl.nszones.com",
    "short.rbl.jp",
    "spam.dnsbl.anonmails.de",
    "spam.pedantic.org",
    "spam.rbl.blockedservers.com",
    "spam.rbl.msrbl.net",
    "spam.spamrats.com",
    "spamrbl.imp.ch",
    "spamsources.fabel.dk",
    "st.technovision.dk",
    "tor.dan.me.uk",
    "tor.dnsbl.sectoor.de",
    "tor.efnet.org",
    "torexit.dan.me.uk",
    "truncate.gbudb.net",
    "ubl.unsubscore.com",
    "virbl.dnsbl.bit.nl",
    "virus.rbl.jp",
    "virus.rbl.msrbl.net",
    "vote.drbl.caravan.ru",
    "vote.drbl.gremlin.ru",
    "web.rbl.msrbl.net",
    "work.drbl.caravan.ru",
    "work.drbl.gremlin.ru",
    "wormrbl.imp.ch",
    "xbl.spamhaus.org",
    "zen.spamhaus.org",
]

BLACKLISTS = [entry for entry in BLACKLISTS if re.fullmatch(r"[A-Za-z0-9._-]+", entry)]
BLACKLIST_EXCLUSIONS = {
    "dnsbl.madavi.de": "Desativada e inadequada para reputacao de e-mail; era destinada a spam de formularios/comentarios.",
    "cbl.anti-spam.org.cn": "RBL removida/offline ha anos.",
    "cblless.anti-spam.org.cn": "RBL removida/offline ha anos.",
    "cblplus.anti-spam.org.cn": "RBL removida/offline ha anos.",
    "cdl.anti-spam.org.cn": "RBL removida/offline ha anos.",
}
BLACKLIST_PRIORITY = {
    "zen.spamhaus.org": "muito alta",
    "bl.spamcop.net": "muito alta",
    "b.barracudacentral.org": "alta",
    "bb.barracudacentral.org": "alta",
    "dnsbl-1.uceprotect.net": "alta",
    "dnsbl-2.uceprotect.net": "alta",
    "dnsbl-3.uceprotect.net": "alta",
    "dnsbl.sorbs.net": "media",
    "spam.spamrats.com": "media",
    "all.spamrats.com": "media",
    "dyna.spamrats.com": "media",
    "noptr.spamrats.com": "media",
    "psbl.surriel.com": "media",
}
BLACKLISTS = [entry for entry in BLACKLISTS if entry not in BLACKLIST_EXCLUSIONS]
BLACKLIST_RELEVANCE = {entry: BLACKLIST_PRIORITY.get(entry, "informacional") for entry in BLACKLISTS}
SUPPORTED_INPUT = (
    "dominio, IPv4 unico, bloco CIDR IPv4 ou ASN no formato ASxxxx "
    "(ex.: exemplo.com, 203.0.113.25, 203.0.113.0/28, AS15169)"
)
# Zero means that the suite does not impose a product-level address cap. The
# worker still controls concurrency, cancellation and process resources.
MAX_CIDR_IPS = int(os.getenv("INH_MAX_CIDR_IPS", "0"))
QUERY_TIMEOUT_SECONDS = 4
REFRESH_INTERVAL_SECONDS = 0.10
ASN_DROP_URL = "https://www.spamhaus.org/drop/asndrop.json"
DEFAULT_MAX_WORKERS = 32
MAX_WORKERS_CAP = 96
BOOST_MAX_WORKERS_CAP = 192
DNS_QUERY_TIME = 3
DNS_QUERY_TRIES = 2

ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "cyan": "\033[36m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "blue": "\033[34m",
    "black": "\033[30m",
    "bg_red": "\033[41m",
    "bg_yellow": "\033[43m",
    "bg_blue": "\033[44m",
    "bg_cyan": "\033[46m",
    "bg_white": "\033[47m",
}
ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")
ASN_HOLDER_CACHE: dict[str, str] = {}
ASN_PROFILE_CACHE: dict[str, dict[str, object]] = {}


@dataclass
class CheckTask:
    query_mode: str
    target_kind: str
    target_value: str
    query_name: str
    blacklist: str
    label: str


@dataclass
class CheckResult:
    task: CheckTask
    status: str
    answers: list[str]
    duration_ms: int


@dataclass
class ScanSummary:
    kind: str
    original_input: str
    normalized_input: str
    detected_mode: str
    details: list[str]
    report_path: Path
    asn_drop_listed: bool
    asn_drop_details: list[str]
    total_checks: int
    listed_results: int
    unique_ips_scanned: int
    unique_ips_listed: int
    unique_ips_clean: int
    timeout_results: int
    error_results: int
    whitelist_results: int
    unique_blacklists_hit: int
    top_blacklists: list[tuple[str, int]]
    top_blacklists_by_unique_ips: list[tuple[str, int]]
    prefix_summaries: list[str]
    listed_ip_lines: list[str]
    blacklist_to_ips: list[tuple[str, list[str]]]
    risk_level: str
    critical_findings: list[str]
    methodology_lines: list[str]
    excluded_sources: list[str]
    relevance_legend: list[str]
    suppressed_informational_ips: int
    asn_context_lines: list[str]
    primary_asn: str
    primary_holder: str
    primary_prefix: str
    inventory_rows: list[dict[str, object]]
    blacklist_groups: list[dict[str, object]]
    report_json_path: Path
    asn_box_lines: list[str]


class TerminalUI:
    BOTTOM_BOX_HEIGHT = 8

    def __init__(self) -> None:
        self._last_draw = 0.0
        self._spinner_frames = ["|", "/", "-", "\\"]
        self._spinner_index = 0

    def render(
        self,
        *,
        original_input: str,
        detected_mode: str,
        total_checks: int,
        completed_checks: int,
        hits: list[CheckResult],
        recent_events: list[str],
        details: list[str],
        started_at: float,
        active_workers: int,
        max_workers: int,
        ip_target_count: int,
        asn_box_lines: list[str],
        final: bool = False,
    ) -> None:
        now = time.monotonic()
        if not final and now - self._last_draw < REFRESH_INTERVAL_SECONDS:
            return
        self._last_draw = now
        self._spinner_index = (self._spinner_index + 1) % len(self._spinner_frames)

        term = shutil.get_terminal_size((120, 40))
        width = max(100, term.columns)
        bar_width = min(52, max(28, width - 60))
        progress = completed_checks / total_checks if total_checks else 1.0
        filled = int(bar_width * progress)
        empty = bar_width - filled
        bar = f"{ANSI['cyan']}{'█' * filled}{ANSI['dim']}{'░' * empty}{ANSI['reset']}"
        elapsed = max(time.monotonic() - started_at, 0.001)
        rate = completed_checks / elapsed
        remaining = max(total_checks - completed_checks, 0)
        eta_seconds = (remaining / rate) if rate > 0 else 0
        listed_ips = len({result.task.target_value for result in hits if result.task.target_kind == "ip"})
        clean_ips = max(ip_target_count - listed_ips, 0)
        status_chip = "FINALIZADO" if final else f"EXECUTANDO {self._spinner_frames[self._spinner_index]}"

        header = f"{ANSI['bold']}╭{'─' * (width - 2)}╮{ANSI['reset']}"
        title = APP_NAME
        title_line = (
            f"{ANSI['bold']}│ {ANSI['cyan']}{title}{ANSI['reset']}"
            f"{' ' * max(1, width - len(title) - len(status_chip) - 8)}"
            f"{ANSI['yellow']}{status_chip}{ANSI['reset']} {ANSI['bold']}│{ANSI['reset']}"
        )
        footer = f"{ANSI['bold']}╰{'─' * (width - 2)}╯{ANSI['reset']}"

        display_input = original_input
        if detected_mode.startswith("Bloco CIDR") and "(" in detected_mode and " IPs" in detected_mode:
            match = re.search(r"\(([^,]+),\s*(\d+)\s+IPs\)", detected_mode)
            if match:
                display_input = f"{match.group(1)} ({match.group(2)} IPs)"
                detected_mode = "Bloco CIDR"
        metric_row_1 = (
            f"Entrada: {display_input} | Modo: {detected_mode} | Workers: {active_workers}/{max_workers}"
        )
        listed_chip = (
            f"{ANSI['bg_red']}{ANSI['yellow']}{ANSI['bold']} IPs Listados: {listed_ips} {ANSI['reset']}"
        )
        clean_chip = (
            f"{ANSI['bg_blue']}{ANSI['yellow']}{ANSI['bold']} IPs Limpos: {clean_ips} {ANSI['reset']}"
        )
        metric_row_2 = f"Consultas: {completed_checks}/{total_checks} | Consultas /s: {rate:,.1f} | Tempo Restante: {format_seconds(eta_seconds)}"
        metric_row_3 = f"{listed_chip}   {clean_chip}"

        info_box = self._box(
            "Informações",
            [f"Entrada suportada: {SUPPORTED_INPUT}", metric_row_1, metric_row_2, metric_row_3, *details],
            width,
        )
        upstream_box = self._box("Informações ASN", asn_box_lines, width, nowrap=True)
        progress_box = self._box(
            "Progresso",
            [f"[{bar}] {progress * 100:5.1f}%", f"Pendentes: {remaining}"],
            width,
        )
        hits_lines = (
            [
                f"[LISTADO] {result.task.label} | {result.task.blacklist} | {', '.join(result.answers)}"
                for result in hits[-10:]
            ]
            if hits
            else ["Nenhuma listagem positiva encontrada ate o momento."]
        )
        bottom_width = max(44, (width - 2) // 2)
        hits_box = self._box(
            "Blacklists com Resultado Positivo",
            hits_lines,
            bottom_width,
            height=self.BOTTOM_BOX_HEIGHT,
        )
        events_box = self._box(
            "Atividade Recente",
            recent_events[-8:] if recent_events else ["Aguardando resultados..."],
            bottom_width,
            height=self.BOTTOM_BOX_HEIGHT,
        )
        bottom_row = self._columns(hits_box, events_box, width)
        lines = [
            "\033[2J\033[H",
            header,
            title_line,
            footer,
            "",
            info_box,
            "",
            upstream_box,
            "",
            progress_box,
            "",
            bottom_row,
        ]

        if final:
            final_box = self._box(
                "Resumo Final",
                [
                    f"Resultados positivos: {len(hits)}",
                    f"Consultas executadas: {completed_checks}",
                    f"Tempo total: {format_seconds(elapsed)}",
                ],
                width,
            )
            lines.extend(["", final_box])

        sys.stdout.write("\n".join(lines) + "\n")
        sys.stdout.flush()

    def _box(
        self,
        title: str,
        raw_lines: list[str],
        width: int,
        *,
        height: int | None = None,
        nowrap: bool = False,
    ) -> str:
        inner = width - 4
        wrapped: list[str] = []
        for raw_line in raw_lines:
            stripped = strip_ansi(raw_line)
            if nowrap:
                wrapped.append(raw_line)
                continue
            if len(stripped) <= inner:
                wrapped.append(raw_line)
                continue
            chunks = textwrap.wrap(stripped, width=inner) or [""]
            wrapped.extend(chunks)
        if height is not None:
            wrapped = wrapped[:height]
            if len(wrapped) < height:
                wrapped.extend([""] * (height - len(wrapped)))
        top = f"{ANSI['bold']}┌─ {title} {'─' * max(1, inner - len(title) - 1)}┐{ANSI['reset']}"
        body = [
            f"{ANSI['bold']}│{ANSI['reset']} {fit_ansi_text(line, inner)} {ANSI['bold']}│{ANSI['reset']}"
            for line in wrapped
        ]
        bottom = f"{ANSI['bold']}└{'─' * (width - 2)}┘{ANSI['reset']}"
        return "\n".join([top, *body, bottom])

    def _columns(self, left_box: str, right_box: str, total_width: int) -> str:
        gap = 2
        left_lines = left_box.splitlines()
        right_lines = right_box.splitlines()
        max_lines = max(len(left_lines), len(right_lines))
        left_width = max(visible_len(line) for line in left_lines) if left_lines else 0
        right_width = max(visible_len(line) for line in right_lines) if right_lines else 0
        left_lines.extend([" " * left_width] * (max_lines - len(left_lines)))
        right_lines.extend([" " * right_width] * (max_lines - len(right_lines)))
        merged = []
        for left, right in zip(left_lines, right_lines):
            merged.append(f"{fit_ansi_text(left, left_width)}{' ' * gap}{fit_ansi_text(right, right_width)}")
        return "\n".join(merged)


def parse_args() -> argparse.Namespace:
    script_path = Path(__file__).resolve()
    candidate_paths = [
        script_path.parent.parent / "resources" / "help_text.txt",
        Path.cwd() / "help_text.txt",
    ]
    help_path = next((path for path in candidate_paths if path and path.exists()), None)
    help_text = help_path.read_text(encoding="utf-8") if help_path else "Ajuda detalhada indisponivel."
    parser = argparse.ArgumentParser(
        prog="inh",
        description="Consulta profissional de blacklists para dominio, IPv4, CIDR IPv4 ou ASN.",
        epilog=help_text,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("target", nargs="?", help=SUPPORTED_INPUT)
    parser.add_argument(
        "--workers",
        type=int,
        default=0,
        help="Quantidade maxima de consultas paralelas. 0 = automatico.",
    )
    parser.add_argument(
        "--boost",
        action="store_true",
        default=None,
        help="Ativa o modo turbo com maior paralelismo e consumo de recursos.",
    )
    parser.add_argument(
        "--report-type",
        choices=["1", "2"],
        default=None,
        help="Seleciona o modelo de relatorio: 1=PDF corporativo, 2=HTML enterprise aberto no navegador.",
    )
    return parser.parse_args()


def clear_and_prompt(prompt: str) -> str:
    return input(prompt).strip()


def choose_report_type(configured: str | None) -> str:
    if configured in {"1", "2"}:
        return configured
    answer = clear_and_prompt(
        "Tipo de relatorio [1=completo de analise de risco, 2=simples] [Enter=1]: "
    ).strip().lower()
    if answer in {"", "1", "completo", "analise", "analise de risco", "analise de riscos"}:
        return "2"
    return "1"


def choose_boost_mode(configured: bool | None) -> bool:
    if configured is not None:
        return bool(configured)
    answer = clear_and_prompt(
        "Modo de execucao [1=boost - consome muito mais CPU/RAM/rede, 2=normal] [Enter=1]: "
    ).strip().lower()
    return answer in {"", "1", "boost", "turbo"}


def format_seconds(seconds: float) -> str:
    total_seconds = max(int(seconds), 0)
    minutes, secs = divmod(total_seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def determine_max_workers(task_count: int, requested: int, boost: bool) -> int:
    cap = BOOST_MAX_WORKERS_CAP if boost else MAX_WORKERS_CAP
    if requested > 0:
        return max(1, min(requested, cap, task_count or 1))
    cpu_hint = os.cpu_count() or 4
    if boost:
        automatic = max(24, min(BOOST_MAX_WORKERS_CAP, cpu_hint * 8))
    else:
        automatic = max(8, min(DEFAULT_MAX_WORKERS, cpu_hint * 4))
    return max(1, min(automatic, cap, task_count or 1))


def strip_ansi(text: str) -> str:
    return ANSI_PATTERN.sub("", text)


def visible_len(text: str) -> int:
    return len(strip_ansi(text))


def fit_ansi_text(text: str, width: int) -> str:
    plain = strip_ansi(text)
    if len(plain) <= width:
        return text + (" " * (width - len(plain)))
    trimmed_plain = plain[: max(0, width - 1)] + "…"
    return trimmed_plain


def shorten_label(text: str, width: int) -> str:
    if len(text) <= width:
        return text
    if width <= 1:
        return text[:width]
    return text[: width - 1] + "…"


def detect_target_type(value: str) -> tuple[str, str]:
    value = value.strip()
    if not value:
        raise ValueError("Nenhum valor informado.")

    upper_value = value.upper()
    if re.fullmatch(r"AS\d+", upper_value):
        return "asn", upper_value

    if "/" in value:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError("Bloco CIDR invalido.") from exc
        if network.version != 4:
            raise ValueError("A ferramenta suporta apenas IPv4 e CIDR IPv4.")
        if MAX_CIDR_IPS and network.num_addresses > MAX_CIDR_IPS:
            raise ValueError(
                f"O bloco informado possui {network.num_addresses} IPs. Limite operacional: {MAX_CIDR_IPS}."
            )
        return "cidr", str(network)

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if is_domain(value):
            return "domain", value.lower()
        raise ValueError(
            "Entrada invalida. Informe um dominio, IPv4, bloco CIDR IPv4 ou ASN no formato ASxxxx."
        )

    if address.version != 4:
        raise ValueError("A ferramenta suporta apenas IPv4 e CIDR IPv4.")
    return "ip", str(address)


def is_domain(value: str) -> bool:
    if len(value) > 253:
        return False
    pattern = re.compile(
        r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\.?$"
    )
    return bool(pattern.fullmatch(value))


def resolve_domain_ipv4s(domain: str) -> list[str]:
    addresses = sorted(
        {
            item[4][0]
            for item in socket.getaddrinfo(domain, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        }
    )
    if not addresses:
        raise ValueError(f"Nao foi possivel resolver IPv4 para {domain}.")
    return addresses


def reverse_ipv4(ip_value: str) -> str:
    return ".".join(reversed(ip_value.split(".")))


def run_dig(name: str, *, query_type: str | None = None) -> tuple[list[str], str]:
    command = ["dig", f"+time={DNS_QUERY_TIME}", f"+tries={DNS_QUERY_TRIES}", "+short"]
    if query_type:
        command.extend(["-t", query_type])
    command.append(name)

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=QUERY_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return [], "timeout"

    stdout_lines = [
        line.strip()
        for line in completed.stdout.splitlines()
        if line.strip() and not line.lstrip().startswith(";")
    ]
    stderr_text = completed.stderr.strip().lower()
    if "timed out" in stderr_text:
        return stdout_lines, "timeout"
    if completed.returncode != 0 and not stdout_lines:
        return [], "error"
    return stdout_lines, "ok"


def format_detail_line(label: str, values: list[str], *, limit: int = 6) -> str:
    if not values:
        return f"{label}: -"
    excerpt = ", ".join(values[:limit])
    if len(values) > limit:
        excerpt += f" ... (+{len(values) - limit})"
    return f"{label}: {excerpt}"


def fetch_asn_prefixes(asn: str) -> list[ipaddress.IPv4Network]:
    try:
        completed = subprocess.run(
            ["whois", "-h", "whois.radb.net", "--", f"-i origin {asn}"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("O comando 'whois' nao esta disponivel neste ambiente.") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Consulta de prefixos para {asn} excedeu o tempo limite.") from exc

    if completed.returncode != 0 and not completed.stdout.strip():
        stderr = completed.stderr.strip() or "falha na consulta whois."
        raise RuntimeError(f"Nao foi possivel consultar prefixos de {asn}: {stderr}")

    prefixes: list[ipaddress.IPv4Network] = []
    for line in completed.stdout.splitlines():
        if not line.lower().startswith("route:"):
            continue
        candidate = line.split(":", 1)[1].strip()
        try:
            network = ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            continue
        if network.version == 4:
            prefixes.append(network)

    if not prefixes:
        raise ValueError(f"Nenhum prefixo IPv4 encontrado para {asn}.")

    collapsed = list(ipaddress.collapse_addresses(prefixes))
    return sorted(collapsed, key=lambda network: (int(network.network_address), network.prefixlen))


def fetch_asn_drop_entry(asn: str) -> dict[str, str] | None:
    asn_number = int(asn[2:])
    try:
        with request.urlopen(ASN_DROP_URL, timeout=10) as response:
            for raw_line in response:
                line = raw_line.decode("utf-8").strip()
                if not line:
                    continue
                payload = json.loads(line)
                if payload.get("asn") == asn_number:
                    return payload
    except OSError as exc:
        raise RuntimeError(f"Nao foi possivel consultar reputacao ASN-DROP para {asn}.") from exc
    return None


def fetch_asn_neighbours(asn: str) -> tuple[str, list[dict[str, object]]]:
    url = f"https://stat.ripe.net/data/asn-neighbours/data.json?resource={asn}"
    try:
        with request.urlopen(url, timeout=12) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except OSError as exc:
        raise RuntimeError(f"Nao foi possivel consultar vizinhanca BGP para {asn}.") from exc

    data = payload.get("data", {})
    latest_time = data.get("latest_time", "-")
    neighbours = data.get("neighbours", [])
    if not isinstance(neighbours, list):
        neighbours = []
    return latest_time, neighbours


def fetch_asn_holder(asn: str) -> str:
    normalized = asn.upper()
    if normalized in ASN_HOLDER_CACHE:
        return ASN_HOLDER_CACHE[normalized]

    url = f"https://stat.ripe.net/data/as-overview/data.json?resource={normalized}"
    try:
        with request.urlopen(url, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except OSError:
        ASN_HOLDER_CACHE[normalized] = "-"
        return "-"

    holder = payload.get("data", {}).get("holder") or "-"
    ASN_HOLDER_CACHE[normalized] = str(holder)
    return str(holder)


def fetch_asn_profile(asn: str) -> dict[str, object]:
    normalized = asn.upper()
    if normalized in ASN_PROFILE_CACHE:
        return ASN_PROFILE_CACHE[normalized]

    profile: dict[str, object] = {
        "asn": normalized,
        "holder": fetch_asn_holder(normalized),
        "registered": "-",
        "network_status": "-",
        "originated_prefixes": 0,
        "upstreams": [],
        "website": "-",
    }

    try:
        with request.urlopen(f"https://stat.ripe.net/data/as-overview/data.json?resource={normalized}", timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
        data = payload.get("data", {})
        profile["holder"] = data.get("holder") or profile["holder"]
        profile["registered"] = data.get("query_starttime") or "-"
        profile["network_status"] = "Announced" if data.get("announced") else "Not announced"
    except OSError:
        pass

    try:
        prefixes = fetch_asn_prefixes(normalized)
        profile["originated_prefixes"] = len(prefixes)
    except RuntimeError:
        pass
    except ValueError:
        pass

    try:
        _, neighbours = fetch_asn_neighbours(normalized)
        left = sorted(
            [item for item in neighbours if item.get("type") == "left"],
            key=lambda item: (-int(item.get("power", 0)), int(item.get("asn", 0))),
        )[:5]
        profile["upstreams"] = [
            {
                "asn": f"AS{item['asn']}",
                "name": fetch_asn_holder(f"AS{item['asn']}"),
            }
            for item in left
        ]
    except RuntimeError:
        pass

    try:
        completed = subprocess.run(
            ["whois", normalized],
            capture_output=True,
            text=True,
            timeout=12,
            check=False,
        )
        output = completed.stdout
        website_match = re.search(r"(https?://[^\s]+)", output)
        if website_match:
            profile["website"] = website_match.group(1).rstrip(".,);")
        if profile["registered"] == "-":
            created_match = re.search(r"(?im)^(?:created|created on|registration date)\s*:\s*(.+)$", output)
            if created_match:
                profile["registered"] = created_match.group(1).strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    ASN_PROFILE_CACHE[normalized] = profile
    return profile


def fetch_network_info(resource: str) -> tuple[list[str], str]:
    url = f"https://stat.ripe.net/data/network-info/data.json?resource={resource}"
    try:
        with request.urlopen(url, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except OSError as exc:
        raise RuntimeError(f"Nao foi possivel consultar metadados de rede para {resource}.") from exc

    data = payload.get("data", {})
    asns = [f"AS{asn}" for asn in data.get("asns", [])]
    prefix = data.get("prefix", "-")
    return asns, prefix


def safe_fetch_network_info(resource: str) -> tuple[list[str], str]:
    """Return an empty enrichment when the optional RIPE lookup is unavailable."""
    try:
        return fetch_network_info(resource)
    except RuntimeError:
        return [], "-"


def build_asn_context_lines(resources: list[str]) -> list[str]:
    seen_asns: dict[str, dict[str, str]] = {}
    for resource in resources:
        try:
            asns, prefix = fetch_network_info(resource)
        except RuntimeError:
            continue
        for asn in asns:
            if asn not in seen_asns:
                seen_asns[asn] = {"holder": fetch_asn_holder(asn), "prefix": prefix}

    lines = []
    for asn, data in sorted(seen_asns.items()):
        lines.append(f"{asn} | titular={data['holder']} | prefixo={data['prefix']}")
    return lines


def build_asn_box_lines(primary_asn: str) -> list[str]:
    if not primary_asn or primary_asn == "-":
        return ["ASN principal: -", "Titular: -", "Data de registro: -", "Network status: -", "Prefixos originados: -", "Upstreams: -", "Site: -"]
    profile = fetch_asn_profile(primary_asn)
    upstreams = profile.get("upstreams") or []
    upstream_text = ", ".join(
        f"{item['asn']} ({shorten_label(str(item['name']), 22)})" for item in upstreams
    ) or "-"
    return [
        f"ASN principal: {profile.get('asn', primary_asn)}",
        f"Titular: {profile.get('holder', '-')}",
        f"Data de registro: {profile.get('registered', '-')}",
        f"Network status: {profile.get('network_status', '-')}",
        f"Prefixos originados: {profile.get('originated_prefixes', 0)}",
        f"Upstreams: {upstream_text}",
        f"Site: {profile.get('website', '-')}",
    ]


def build_upstream_map(asn: str, neighbours: list[dict[str, object]]) -> list[str]:
    left = sorted(
        [item for item in neighbours if item.get("type") == "left"],
        key=lambda item: (-int(item.get("power", 0)), int(item.get("asn", 0))),
    )[:8]

    lines = [
        f"{ANSI['bg_cyan']}{ANSI['black']}{ANSI['bold']} ORIGIN {asn} {ANSI['reset']}",
        "",
    ]

    if left:
        lines.append(f"{ANSI['bold']}{ANSI['cyan']}Upstreams Diretos{ANSI['reset']}")
        for index, item in enumerate(left):
            branch = "├─" if index < len(left) - 1 else "└─"
            upstream_asn = f"AS{item['asn']}"
            holder = fetch_asn_holder(upstream_asn)
            metrics = f"power={item.get('power', 0)} v4={item.get('v4_peers', 0)} v6={item.get('v6_peers', 0)}"
            if index == 0:
                lines.append(
                    f"{branch} {ANSI['bg_yellow']}{ANSI['blue']}{ANSI['bold']} Primario {ANSI['reset']} "
                    f"{upstream_asn} | {shorten_label(holder, 42)} | {metrics}"
                )
            else:
                lines.append(f"{branch} {upstream_asn} | {shorten_label(holder, 42)} | {metrics}")
    else:
        lines.append("Sem upstreams diretos identificados nos dados consultados.")

    if len([line for line in lines if strip_ansi(line).strip()]) <= 3:
        lines.append("Sem dados de conectividade BGP para exibir.")
    return lines


def build_tasks(kind: str, value: str) -> tuple[list[CheckTask], list[str], str, dict[str, object]]:
    if kind == "ip":
        asn_context = build_asn_context_lines([value])
        asns, primary_prefix = safe_fetch_network_info(value)
        primary_asn = asns[0] if asns else "-"
        primary_holder = fetch_asn_holder(primary_asn) if primary_asn != "-" else "-"
        asn_box_lines = build_asn_box_lines(primary_asn)
        tasks = [
            CheckTask(
                query_mode="dig",
                target_kind="ip",
                target_value=value,
                query_name=f"{reverse_ipv4(value)}.{blacklist}",
                blacklist=blacklist,
                label=f"IPv4 {value}",
            )
            for blacklist in BLACKLISTS
        ]
        details = asn_context[:4]
        return (
            tasks,
            details,
            "IPv4 unico",
            {
                "ip_targets": [value],
                "asn_context_lines": asn_context,
                "primary_asn": primary_asn,
                "primary_holder": primary_holder,
                "primary_prefix": primary_prefix,
                "asn_box_lines": asn_box_lines,
            },
        )

    if kind == "cidr":
        network = ipaddress.ip_network(value, strict=False)
        asn_context = build_asn_context_lines([value])
        asns, primary_prefix = safe_fetch_network_info(value)
        primary_asn = asns[0] if asns else "-"
        primary_holder = fetch_asn_holder(primary_asn) if primary_asn != "-" else "-"
        asn_box_lines = build_asn_box_lines(primary_asn)
        ips = [str(ip) for ip in network]
        tasks = []
        for ip_value in ips:
            reversed_ip = reverse_ipv4(ip_value)
            for blacklist in BLACKLISTS:
                tasks.append(
                    CheckTask(
                        query_mode="dig",
                        target_kind="ip",
                        target_value=ip_value,
                        query_name=f"{reversed_ip}.{blacklist}",
                        blacklist=blacklist,
                        label=f"IPv4 {ip_value}",
                    )
                )
        details = [f"Total de IPs no bloco: {len(ips)}", *asn_context[:4]]
        return (
            tasks,
            details,
            f"Bloco CIDR ({value}, {len(ips)} IPs)",
            {
                "ip_targets": ips,
                "prefixes": [network],
                "asn_context_lines": asn_context,
                "primary_asn": primary_asn,
                "primary_holder": primary_holder,
                "primary_prefix": primary_prefix,
                "asn_box_lines": asn_box_lines,
            },
        )

    if kind == "domain":
        resolved_ips = resolve_domain_ipv4s(value)
        asn_context = build_asn_context_lines(resolved_ips[:8])
        asns, primary_prefix = safe_fetch_network_info(resolved_ips[0]) if resolved_ips else ([], "-")
        primary_asn = asns[0] if asns else "-"
        primary_holder = fetch_asn_holder(primary_asn) if primary_asn != "-" else "-"
        asn_box_lines = build_asn_box_lines(primary_asn)
        tasks = [
            CheckTask(
                query_mode="dig",
                target_kind="domain",
                target_value=value,
                query_name=f"{value}.{blacklist}",
                blacklist=blacklist,
                label=f"Dominio {value}",
            )
            for blacklist in BLACKLISTS
        ]
        for ip_value in resolved_ips:
            reversed_ip = reverse_ipv4(ip_value)
            for blacklist in BLACKLISTS:
                tasks.append(
                    CheckTask(
                        query_mode="dig",
                        target_kind="ip",
                        target_value=ip_value,
                        query_name=f"{reversed_ip}.{blacklist}",
                        blacklist=blacklist,
                        label=f"IPv4 {ip_value} (resolvido de {value})",
                    )
                )
        details = [format_detail_line("IPs resolvidos", resolved_ips), *asn_context[:4]]
        return (
            tasks,
            details,
            "Dominio",
            {
                "ip_targets": resolved_ips,
                "asn_context_lines": asn_context,
                "primary_asn": primary_asn,
                "primary_holder": primary_holder,
                "primary_prefix": primary_prefix,
                "asn_box_lines": asn_box_lines,
            },
        )

    if kind == "asn":
        prefixes = fetch_asn_prefixes(value)
        total_ips = sum(network.num_addresses for network in prefixes)
        if MAX_CIDR_IPS and total_ips > MAX_CIDR_IPS:
            raise ValueError(
                f"{value} anuncia {total_ips} IPv4s em {len(prefixes)} blocos. "
                f"O limite operacional para varredura integral e {MAX_CIDR_IPS} IPs."
            )

        tasks = [
            CheckTask(
                query_mode="asn_drop",
                target_kind="asn",
                target_value=value,
                query_name=value,
                blacklist="Spamhaus ASN-DROP",
                label=f"ASN {value}",
            )
        ]
        for prefix in prefixes:
            for ip_value in (str(ip) for ip in prefix):
                reversed_ip = reverse_ipv4(ip_value)
                for blacklist in BLACKLISTS:
                    tasks.append(
                        CheckTask(
                            query_mode="dig",
                            target_kind="ip",
                            target_value=ip_value,
                            query_name=f"{reversed_ip}.{blacklist}",
                            blacklist=blacklist,
                            label=f"IPv4 {ip_value} ({value})",
                        )
                    )
        holder = fetch_asn_holder(value)
        asn_box_lines = build_asn_box_lines(value)
        details = [
            f"{ANSI['bg_blue']}{ANSI['yellow']}{ANSI['bold']} ASN analisado: {value} {ANSI['reset']}",
            f"Titular ASN: {holder}",
            f"{ANSI['bg_cyan']}{ANSI['black']}{ANSI['bold']} Prefixos IPv4 do ASN: {len(prefixes)} {ANSI['reset']}",
            f"Total de IPv4s expandidos: {total_ips}",
            f"{ANSI['bold']}Prefixos:{ANSI['reset']} {', '.join(str(prefix) for prefix in prefixes[:6])}"
            + (f" ... (+{len(prefixes) - 6})" if len(prefixes) > 6 else ""),
        ]
        ip_targets = [str(ip) for prefix in prefixes for ip in prefix]
        return (
            tasks,
            details,
            f"ASN ({value})",
            {
                "ip_targets": ip_targets,
                "prefixes": prefixes,
                "asn": value,
                "asn_context_lines": [f"{value} | titular={holder} | prefixos={len(prefixes)}"],
                "primary_asn": value,
                "primary_holder": holder,
                "primary_prefix": str(prefixes[0]) if prefixes else "-",
                "asn_box_lines": asn_box_lines,
            },
        )

    raise ValueError("Modo de verificacao nao suportado.")


def execute_task(task: CheckTask) -> CheckResult:
    started = time.monotonic()
    if task.query_mode == "asn_drop":
        entry = fetch_asn_drop_entry(task.target_value)
        duration_ms = int((time.monotonic() - started) * 1000)
        if entry:
            answers = [
                f"asname={entry.get('asname', '-')}",
                f"cc={entry.get('cc', '-')}",
                f"domain={entry.get('domain', '-')}",
                f"rir={entry.get('rir', '-')}",
            ]
            return CheckResult(task=task, status="listed", answers=answers, duration_ms=duration_ms)
        return CheckResult(task=task, status="not_listed", answers=[], duration_ms=duration_ms)

    answers, status = run_dig(task.query_name)
    duration_ms = int((time.monotonic() - started) * 1000)
    ipv4_answers = [answer for answer in answers if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", answer)]
    if status == "ok" and ipv4_answers:
        first = ipv4_answers[0]
        if task.target_kind == "ip" and first == "127.0.0.1":
            status = "whitelisted"
        else:
            status = "listed"
    elif status == "ok":
        status = "not_listed"
    return CheckResult(task=task, status=status, answers=ipv4_answers, duration_ms=duration_ms)


def render_log_header(original_input: str, detected_mode: str, details: list[str]) -> list[str]:
    stamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
    lines = [
        f"ISP - Network Health",
        f"Gerado em: {stamp}",
        f"Entrada: {original_input}",
        f"Modo detectado: {detected_mode}",
    ]
    lines.extend(details)
    lines.append("")
    return lines


def serialize_result(result: CheckResult) -> str:
    answers = ", ".join(result.answers) if result.answers else "-"
    return (
        f"[{result.status.upper():12}] "
        f"{result.task.label} | zone={result.task.blacklist} | query={result.task.query_name} | "
        f"resposta={answers} | duracao={result.duration_ms}ms"
    )


def build_prefix_map(prefixes: list[ipaddress.IPv4Network], ips: list[str]) -> dict[str, str]:
    if not prefixes:
        return {}
    prefix_map: dict[str, str] = {}
    for ip_value in ips:
        ip_obj = ipaddress.ip_address(ip_value)
        for prefix in prefixes:
            if ip_obj in prefix:
                prefix_map[ip_value] = str(prefix)
                break
    return prefix_map


def assess_risk_level(unique_ips_listed: int, critical_hits: int, high_hits: int) -> str:
    if critical_hits > 0 or unique_ips_listed >= 25:
        return "Alto"
    if high_hits > 0 or unique_ips_listed >= 5:
        return "Moderado"
    if unique_ips_listed > 0:
        return "Baixo"
    return "Sem evidencias relevantes"


def blacklist_relevance(name: str) -> str:
    return BLACKLIST_RELEVANCE.get(name, "informacional")


def build_scan_summary(
    *,
    kind: str,
    original_input: str,
    normalized_input: str,
    detected_mode: str,
    details: list[str],
    metadata: dict[str, object],
    results: list[CheckResult],
) -> ScanSummary:
    ip_targets = list(dict.fromkeys(metadata.get("ip_targets", [])))
    prefixes = metadata.get("prefixes", [])
    prefix_map = build_prefix_map(prefixes, ip_targets) if prefixes else {}
    asn_context_lines = metadata.get("asn_context_lines", [])
    asn_box_lines = metadata.get("asn_box_lines", [])
    primary_asn = str(metadata.get("primary_asn", "-"))
    primary_holder = str(metadata.get("primary_holder", "-"))
    primary_prefix = str(metadata.get("primary_prefix", prefixes[0] if prefixes else "-"))

    listed_results_all = [result for result in results if result.status == "listed"]
    listed_ip_results_all = [result for result in listed_results_all if result.task.target_kind == "ip"]
    listed_ip_results = [
        result for result in listed_ip_results_all if blacklist_relevance(result.task.blacklist) != "informacional"
    ]
    asn_result = next((result for result in results if result.task.target_kind == "asn"), None)

    ip_hits: dict[str, list[CheckResult]] = collections.defaultdict(list)
    for result in listed_ip_results:
        ip_hits[result.task.target_value].append(result)
    informational_only_hits: dict[str, list[CheckResult]] = collections.defaultdict(list)
    for result in listed_ip_results_all:
        if result.task.target_value not in ip_hits:
            informational_only_hits[result.task.target_value].append(result)

    blacklist_counter: collections.Counter[str] = collections.Counter(
        result.task.blacklist for result in listed_ip_results
    )
    blacklist_unique_ips: dict[str, set[str]] = collections.defaultdict(set)
    for result in listed_ip_results:
        blacklist_unique_ips[result.task.blacklist].add(result.task.target_value)
    prefix_counter: collections.Counter[str] = collections.Counter()
    for ip_value in ip_hits:
        prefix_counter[prefix_map.get(ip_value, "sem-prefixo")] += 1

    results_by_ip: dict[str, list[CheckResult]] = collections.defaultdict(list)
    for result in results:
        if result.task.target_kind == "ip":
            results_by_ip[result.task.target_value].append(result)

    listed_ip_lines: list[str] = []
    for ip_value in sorted(ip_hits, key=lambda value: tuple(int(part) for part in value.split("."))):
        all_hits_for_ip = [result for result in listed_ip_results_all if result.task.target_value == ip_value]
        relevant_hits = sorted(
            {result.task.blacklist for result in all_hits_for_ip if blacklist_relevance(result.task.blacklist) != "informacional"}
        )
        informational_hits = sorted(
            {result.task.blacklist for result in all_hits_for_ip if blacklist_relevance(result.task.blacklist) == "informacional"}
        )
        prefix_label = prefix_map.get(ip_value)
        blacklists_text = f"relevantes={', '.join(relevant_hits)}"
        if informational_hits:
            blacklists_text += f" | informacionais={', '.join(informational_hits)}"
        if prefix_label:
            listed_ip_lines.append(
                f"{ip_value} | prefixo={prefix_label} | {blacklists_text}"
            )
        else:
            listed_ip_lines.append(f"{ip_value} | {blacklists_text}")
    inventory_rows: list[dict[str, object]] = []
    for ip_value in sorted(ip_targets, key=lambda value: tuple(int(part) for part in value.split("."))):
        ip_results = results_by_ip.get(ip_value, [])
        all_hits_for_ip = [result for result in listed_ip_results_all if result.task.target_value == ip_value]
        relevant_hits = sorted(
            {result.task.blacklist for result in all_hits_for_ip if blacklist_relevance(result.task.blacklist) != "informacional"}
        )
        informational_hits = sorted(
            {result.task.blacklist for result in all_hits_for_ip if blacklist_relevance(result.task.blacklist) == "informacional"}
        )
        timeout_count = sum(1 for result in ip_results if result.status == "timeout")
        error_count = sum(1 for result in ip_results if result.status == "error")
        highest_relevance = "clean"
        if any(blacklist_relevance(name) == "muito alta" for name in relevant_hits):
            highest_relevance = "very_high"
        elif any(blacklist_relevance(name) == "alta" for name in relevant_hits):
            highest_relevance = "high"
        elif relevant_hits:
            highest_relevance = "medium"
        elif informational_hits:
            highest_relevance = "informational"
        elif timeout_count or error_count:
            highest_relevance = "timeout"
        risk_count = len(relevant_hits)
        inventory_rows.append(
            {
                "ip": ip_value,
                "prefix": prefix_map.get(ip_value, "-"),
                "relevant": relevant_hits,
                "informational": informational_hits,
                "status": highest_relevance,
                "timeout_count": timeout_count,
                "error_count": error_count,
                "risk_count": risk_count,
            }
        )

    prefix_summaries = [
        f"{prefix} | IPs listados={count}"
        for prefix, count in sorted(prefix_counter.items(), key=lambda item: (-item[1], item[0]))
    ]
    blacklist_to_ips = [
        (
            blacklist,
            sorted(ip_values, key=lambda value: tuple(int(part) for part in value.split("."))),
        )
        for blacklist, ip_values in sorted(
            blacklist_unique_ips.items(),
            key=lambda item: (-len(item[1]), item[0]),
        )
    ]
    blacklist_groups = [
        {
            "name": blacklist,
            "relevance": blacklist_relevance(blacklist),
            "ips": ip_values,
        }
        for blacklist, ip_values in blacklist_to_ips
    ]
    critical_findings: list[str] = []
    critical_hits = 0
    high_hits = 0
    for blacklist, ip_values in blacklist_to_ips:
        priority = BLACKLIST_PRIORITY.get(blacklist)
        if not priority:
            continue
        finding = f"{blacklist} ({priority}) listou {len(ip_values)} IP(s)"
        critical_findings.append(finding)
        if priority == "muito alta":
            critical_hits += 1
        elif priority == "alta":
            high_hits += 1

    methodology_lines = [
        "Foram consultadas apenas DNSBLs ativas e consideradas relevantes para reputacao de e-mail/IP.",
        "Listas retiradas por obsolescencia, offline prolongado ou uso inadequado para e-mail foram excluidas da varredura.",
        "Resultados so sao contabilizados como listagem quando a resposta DNS retorna codigo IPv4 valido; timeouts, comentarios e falhas nao contam como hit.",
        "IPs presentes apenas em listas informacionais nao entram como listados no resultado principal; eles so aparecem se houver ao menos uma blacklist relevante para o mesmo IP.",
        "A interpretacao prioriza sinais de Spamhaus ZEN, SpamCop e Barracuda, com UCEProtect e outras listas como evidencias complementares.",
    ]
    excluded_sources = [
        f"{name}: {reason}"
        for name, reason in sorted(BLACKLIST_EXCLUSIONS.items())
    ]
    risk_level = assess_risk_level(len(ip_hits), critical_hits, high_hits)
    relevance_legend = [
        "Muito alta: sinal prioritario e forte para reputacao operacional.",
        "Alta: sinal importante, mas com peso abaixo das listas lideres.",
        "Media: evidencia complementar; exige correlacao com outras listas.",
        "Informacional: contexto adicional; nao qualifica isoladamente um IP como listado.",
    ]

    report_path = default_report_path(kind, normalized_input)
    report_json_path = report_path.with_suffix(".json")
    return ScanSummary(
        kind=kind,
        original_input=original_input,
        normalized_input=normalized_input,
        detected_mode=detected_mode,
        details=details,
        report_path=report_path,
        asn_drop_listed=bool(asn_result and asn_result.status == "listed"),
        asn_drop_details=asn_result.answers if asn_result else [],
        total_checks=len(results),
        listed_results=len(listed_ip_results) + (1 if asn_result and asn_result.status == "listed" else 0),
        unique_ips_scanned=len(ip_targets),
        unique_ips_listed=len(ip_hits),
        unique_ips_clean=max(len(ip_targets) - len(ip_hits), 0),
        timeout_results=sum(1 for result in results if result.status == "timeout"),
        error_results=sum(1 for result in results if result.status == "error"),
        whitelist_results=sum(1 for result in results if result.status == "whitelisted"),
        unique_blacklists_hit=len(blacklist_counter),
        top_blacklists=blacklist_counter.most_common(15),
        top_blacklists_by_unique_ips=sorted(
            ((blacklist, len(ip_values)) for blacklist, ip_values in blacklist_unique_ips.items()),
            key=lambda item: (-item[1], item[0]),
        )[:15],
        prefix_summaries=prefix_summaries,
        listed_ip_lines=listed_ip_lines,
        blacklist_to_ips=blacklist_to_ips,
        risk_level=risk_level,
        critical_findings=critical_findings,
        methodology_lines=methodology_lines,
        excluded_sources=excluded_sources,
        relevance_legend=relevance_legend,
        suppressed_informational_ips=len(informational_only_hits),
        asn_context_lines=asn_context_lines,
        primary_asn=primary_asn,
        primary_holder=primary_holder,
        primary_prefix=primary_prefix,
        inventory_rows=inventory_rows,
        blacklist_groups=blacklist_groups,
        report_json_path=report_json_path,
        asn_box_lines=asn_box_lines,
    )


def sanitize_name(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-").lower()
    return normalized or "scan"


def default_report_path(kind: str, normalized_input: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    downloads_dir = Path.home() / "Downloads"
    filename = f"blacklist-report-{kind}-{sanitize_name(normalized_input)}-{stamp}.pdf"
    return downloads_dir / filename


def compress_pie_segments(entries: list[tuple[str, int]], *, limit: int = 6) -> list[tuple[str, int]]:
    if len(entries) <= limit:
        return entries
    primary = entries[: limit - 1]
    others_total = sum(value for _, value in entries[limit - 1 :])
    if others_total > 0:
        primary.append(("Outras", others_total))
    return primary


class SimplePdfBuilder:
    PAGE_WIDTH = 595
    PAGE_HEIGHT = 842
    MARGIN_X = 50
    MARGIN_Y = 52
    LINE_HEIGHT = 14
    PIE_COLORS = [
        "0.20 0.65 0.33 rg",
        "0.80 0.20 0.20 rg",
        "0.12 0.46 0.85 rg",
        "0.90 0.58 0.12 rg",
        "0.50 0.36 0.78 rg",
        "0.14 0.63 0.63 rg",
        "0.82 0.36 0.58 rg",
        "0.45 0.45 0.45 rg",
    ]

    def __init__(self, title: str) -> None:
        self.title = title
        self.pages: list[str] = []
        self.current_commands: list[str] = []
        self.cursor_y = self.PAGE_HEIGHT - self.MARGIN_Y
        self._new_page()

    def _new_page(self) -> None:
        if self.current_commands:
            self.pages.append("\n".join(self.current_commands))
        self.current_commands = []
        self.cursor_y = self.PAGE_HEIGHT - self.MARGIN_Y

    def _escape(self, text: str) -> str:
        return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    def _text_line(self, x: int, y: float, size: int, text: str) -> str:
        return f"BT /F1 {size} Tf 1 0 0 1 {x} {int(y)} Tm ({self._escape(text)}) Tj ET"

    def _ensure_space(self, lines: int = 1) -> None:
        required = lines * self.LINE_HEIGHT
        if self.cursor_y - required < self.MARGIN_Y:
            self._new_page()

    def add_heading(self, text: str, *, size: int = 18, spacing_before: int = 0) -> None:
        if spacing_before:
            self.cursor_y -= spacing_before
        self._ensure_space(2)
        self.current_commands.append(self._text_line(self.MARGIN_X, self.cursor_y, size, text))
        self.cursor_y -= self.LINE_HEIGHT + 4

    def add_paragraph(self, text: str, *, size: int = 10, indent: int = 0) -> None:
        width = 92 if indent == 0 else 84
        for line in textwrap.wrap(text, width=width) or [""]:
            self._ensure_space(1)
            self.current_commands.append(self._text_line(self.MARGIN_X + indent, self.cursor_y, size, line))
            self.cursor_y -= self.LINE_HEIGHT
        self.cursor_y -= 2

    def add_bullets(self, lines: list[str]) -> None:
        for line in lines:
            self.add_paragraph(f"- {line}", indent=8)

    def add_pie_chart(self, title: str, segments: list[tuple[str, int]]) -> None:
        filtered_segments = [(label, value) for label, value in segments if value > 0]
        total = sum(value for _, value in filtered_segments) or 1
        cx = self.PAGE_WIDTH - 160
        cy = self.cursor_y - 110
        radius = 72
        self._ensure_space(18)
        self.current_commands.append(self._text_line(self.MARGIN_X, self.cursor_y, 13, title))
        self.cursor_y -= 24

        start_angle = 0.0
        for index, (label, value) in enumerate(filtered_segments):
            fraction = value / total
            color = self.PIE_COLORS[index % len(self.PIE_COLORS)]
            end_angle = start_angle + fraction * 2 * math.pi
            points = [(cx, cy)]
            step_count = max(6, int(48 * fraction))
            for step in range(step_count + 1):
                angle = start_angle + (end_angle - start_angle) * (step / step_count)
                points.append((cx + radius * math.cos(angle), cy + radius * math.sin(angle)))
            path = [color, f"{points[0][0]:.2f} {points[0][1]:.2f} m"]
            for px, py in points[1:]:
                path.append(f"{px:.2f} {py:.2f} l")
            path.append("f")
            self.current_commands.append("\n".join(path))
            start_angle = end_angle

        outline_points = []
        for step in range(49):
            angle = (2 * math.pi * step) / 48
            outline_points.append((cx + radius * math.cos(angle), cy + radius * math.sin(angle)))
        outline = ["0 0 0 RG 0.7 w", f"{outline_points[0][0]:.2f} {outline_points[0][1]:.2f} m"]
        for px, py in outline_points[1:]:
            outline.append(f"{px:.2f} {py:.2f} l")
        outline.append("s")
        self.current_commands.append("\n".join(outline))

        legend_x = self.MARGIN_X
        legend_y = cy + 36
        for index, (label, value) in enumerate(filtered_segments):
            color = self.PIE_COLORS[index % len(self.PIE_COLORS)]
            self.current_commands.append(f"{color} {legend_x} {legend_y} 10 10 re f")
            share = (value / total) * 100
            self.current_commands.append(
                self._text_line(legend_x + 18, legend_y + 1, 10, f"{label}: {value} ({share:.1f}%)")
            )
            legend_y -= 18
            if legend_y < cy - 54:
                legend_x += 230
                legend_y = cy + 36
        self.cursor_y = cy - radius - 26

    def build(self) -> bytes:
        if self.current_commands:
            self.pages.append("\n".join(self.current_commands))
            self.current_commands = []

        objects: list[bytes] = []

        def add_object(content: str | bytes) -> int:
            data = content.encode("latin-1") if isinstance(content, str) else content
            objects.append(data)
            return len(objects)

        font_id = add_object("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        page_ids: list[int] = []
        content_ids: list[int] = []
        for page in self.pages:
            stream = page.encode("latin-1", errors="replace")
            content_id = add_object(f"<< /Length {len(stream)} >>\nstream\n".encode("latin-1") + stream + b"\nendstream")
            content_ids.append(content_id)
            page_ids.append(0)

        pages_id = add_object("<< /Type /Pages /Kids [] /Count 0 >>")
        for index, content_id in enumerate(content_ids):
            page_id = add_object(
                f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {self.PAGE_WIDTH} {self.PAGE_HEIGHT}] "
                f"/Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>"
            )
            page_ids[index] = page_id

        kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
        objects[pages_id - 1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("latin-1")
        catalog_id = add_object(f"<< /Type /Catalog /Pages {pages_id} 0 R >>")

        pdf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for index, obj in enumerate(objects, start=1):
            offsets.append(len(pdf))
            pdf.extend(f"{index} 0 obj\n".encode("latin-1"))
            pdf.extend(obj)
            pdf.extend(b"\nendobj\n")

        xref_offset = len(pdf)
        pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("latin-1"))
        pdf.extend(b"0000000000 65535 f \n")
        for offset in offsets[1:]:
            pdf.extend(f"{offset:010d} 00000 n \n".encode("latin-1"))
        pdf.extend(
            (
                f"trailer << /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\n"
                f"startxref\n{xref_offset}\n%%EOF\n"
            ).encode("latin-1")
        )
        return bytes(pdf)


def _render_badge(text: str, tone: str) -> str:
    return f'<span class="badge {tone}">{html.escape(text)}</span>'


def _render_donut(label: str, value: int, total: int, color: str) -> str:
    percent = 0 if total == 0 else round((value / total) * 100, 1)
    return (
        f'<div class="chart-card">'
        f'<div class="donut" style="--pct:{percent};--accent:{color};">'
        f'<div class="donut-inner"><strong>{percent:.1f}%</strong><span>{html.escape(label)}</span></div>'
        f'</div>'
        f'<div class="chart-legend"><div class="legend-dot" style="background:{color};"></div>'
        f'<div><strong>{value}</strong><span>{html.escape(label)}</span></div></div></div>'
    )


def _risk_badge_class(risk_level: str) -> str:
    mapping = {
        "Alto": "risk-high",
        "Moderado": "risk-medium",
        "Baixo": "risk-low",
        "Sem evidencias relevantes": "risk-low",
    }
    return mapping.get(risk_level, "risk-medium")


def _inventory_risk_label(row: dict[str, object]) -> str:
    status = row["status"]
    if status == "very_high":
        return "Alto"
    if status in {"high", "medium"}:
        return "Medio"
    if status == "informational":
        return "Informacional"
    if status == "timeout":
        return "Nao concluido"
    return "Limpo"


def _compress_ip_ranges(rows: list[dict[str, object]]) -> list[str]:
    listed_ips = [row["ip"] for row in rows if row["status"] in {"very_high", "high", "medium"}]
    if not listed_ips:
        return []
    octets = sorted(int(ip.split(".")[-1]) for ip in listed_ips)
    ranges: list[str] = []
    start = prev = octets[0]
    base = ".".join(listed_ips[0].split(".")[:3])
    for value in octets[1:]:
        if value == prev + 1:
            prev = value
            continue
        ranges.append(f"{base}.{start}" if start == prev else f"{base}.{start}–{base}.{prev} -> {prev - start + 1} IPs")
        start = prev = value
    ranges.append(f"{base}.{start}" if start == prev else f"{base}.{start}–{base}.{prev} -> {prev - start + 1} IPs")
    return ranges


def _render_heatmap(rows: list[dict[str, object]]) -> str:
    color_map = {
        "very_high": "#dc2626",
        "high": "#f59e0b",
        "medium": "#fbbf24",
        "informational": "#fde68a",
        "timeout": "#d1d5db",
        "clean": "#16a34a",
    }
    cell = 18
    gap = 4
    size = cell * 16 + gap * 15
    rects = []
    labels = []
    for index, row in enumerate(rows[:256]):
        x = (index % 16) * (cell + gap)
        y = (index // 16) * (cell + gap)
        color = color_map.get(str(row["status"]), "#16a34a")
        title = html.escape(str(row["ip"]))
        rects.append(
            f'<rect x="{x}" y="{y}" width="{cell}" height="{cell}" rx="4" ry="4" fill="{color}">'
            f'<title>{title}</title></rect>'
        )
    for n in range(16):
        pos = n * (cell + gap) + 4
        labels.append(f'<text x="{pos}" y="-6" font-size="9" fill="var(--muted)">{n:X}</text>')
        labels.append(f'<text x="-14" y="{pos + 10}" font-size="9" fill="var(--muted)">{n:X}</text>')
    return (
        f'<svg class="heat-svg" viewBox="-22 -18 {size + 26} {size + 24}" role="img" aria-label="Heatmap do bloco">'
        f'{"".join(labels)}{"".join(rects)}</svg>'
    )


def _render_bar_chart(entries: list[tuple[str, int]]) -> str:
    max_value = max((count for _, count in entries), default=1)
    bars = []
    for name, count in entries:
        width = (count / max_value) * 100 if max_value else 0
        relevance = blacklist_relevance(name)
        color = {
            "muito alta": "#dc2626",
            "alta": "#f59e0b",
            "media": "#fbbf24",
            "informacional": "#9ca3af",
        }.get(relevance, "#9ca3af")
        bars.append(
            f'<div class="bar-row"><div class="bar-label">{html.escape(name)}</div>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{width:.2f}%;background:{color};"></div></div>'
            f'<div class="bar-value">{count}</div></div>'
        )
    return "".join(bars)


def render_report_type2_html(summary: ScanSummary) -> str:
    stamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
    listed_pct = 0 if summary.unique_ips_scanned == 0 else (summary.unique_ips_listed / summary.unique_ips_scanned) * 100
    clean_pct = 0 if summary.unique_ips_scanned == 0 else (summary.unique_ips_clean / summary.unique_ips_scanned) * 100
    risk_class = _risk_badge_class(summary.risk_level)
    range_summary = _compress_ip_ranges(summary.inventory_rows)
    json_file = summary.report_json_path.name

    kpi_cards = "".join(
        [
            f'<div class="kpi-card"><div class="kpi-icon">#</div><div><span>Total de IPs analisados</span><strong>{summary.unique_ips_scanned}</strong></div></div>',
            f'<div class="kpi-card danger"><div class="kpi-icon">!</div><div><span>IPs blacklistados</span><strong>{summary.unique_ips_listed}</strong><small>{listed_pct:.1f}% do total</small></div></div>',
            f'<div class="kpi-card success"><div class="kpi-icon">✓</div><div><span>IPs sem listagem</span><strong>{summary.unique_ips_clean}</strong><small>{clean_pct:.1f}% do total</small></div></div>',
            f'<div class="kpi-card"><div class="kpi-icon">@</div><div><span>Blacklists unicas</span><strong>{summary.unique_blacklists_hit}</strong></div></div>',
        ]
    )
    findings = "".join(
        f'<div class="priority-item"><span>{html.escape(item)}</span></div>'
        for item in (summary.critical_findings or ["Nenhum achado prioritario em listas de relevancia alta ou muito alta."])
    )
    bars_html = _render_bar_chart(summary.top_blacklists)
    heatmap_html = _render_heatmap(summary.inventory_rows)
    blacklist_sections = "".join(
        '<section class="blacklist-section">'
        f'<div class="section-head"><h3>{html.escape(group["name"])}</h3>{_render_badge(group["relevance"].upper(), "spamhaus" if "spamhaus" in group["name"] else "barracuda" if "barracuda" in group["name"] else "neutral")}<strong>{len(group["ips"])}</strong></div>'
        f'<div class="ip-grid">{"".join(f"<span class=\"ip-chip\">{html.escape(ip)}</span>" for ip in group["ips"])}</div>'
        '<div class="section-foot">Remocao/contestacao: verificar politica do mantenedor da blacklist.</div>'
        '</section>'
        for group in summary.blacklist_groups
    )
    inventory_table = "".join(
        "<tr class='{row_class}'>"
        f"<td>{html.escape(str(row['ip']))}</td>"
        f"<td>{''.join(_render_badge(item, 'spamhaus' if 'spamhaus' in item else 'barracuda' if 'barracuda' in item else 'danger') for item in row['relevant']) or '<span class=\"muted\">-</span>'}</td>"
        f"<td>{''.join(_render_badge(item, 'neutral') for item in row['informational']) or '<span class=\"muted\">-</span>'}</td>"
        f"<td>{_render_badge(_inventory_risk_label(row), 'risk-high' if row['status'] == 'very_high' else 'barracuda' if row['status'] in {'high','medium'} else 'neutral' if row['status'] != 'clean' else 'spamhaus')}</td>"
        "</tr>".format(row_class="highrisk" if int(row["risk_count"]) >= 3 else "")
        for row in summary.inventory_rows
    )
    methodology = "".join(
        f'<li><span class="dot"></span><span>{html.escape(line)}</span></li>' for line in summary.methodology_lines
    )
    relevance_table = "".join(
        f'<tr><td><span class="relevance-swatch {cls}"></span></td><td>{html.escape(name)}</td><td>{html.escape(desc)}</td></tr>'
        for cls, name, desc in [
            ("veryhigh", "Muito alta", "Sinal prioritario e forte para reputacao operacional."),
            ("high", "Alta", "Sinal importante, mas abaixo das listas lideres."),
            ("medium", "Media", "Evidencia complementar; exige correlacao."),
            ("info", "Informacional", "Nao qualifica isoladamente um IP como listado."),
        ]
    )

    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <title>Relatório Executivo de Reputação de IP</title>
  <style>
    @page {{
      size: A4;
      margin: 14mm 12mm 16mm 12mm;
    }}
    :root {{
      --primary:#1E3A5F; --accent:#2563EB; --high:#DC2626; --medium:#F59E0B; --low:#16A34A;
      --cards:#F8FAFC; --text:#111827; --muted:#6B7280; --line:#cbd5e1; --bg:#f4f7fb;
      --surface:#ffffff; --surface-soft:#f8fafc;
      --danger-soft:#fff1f2; --success-soft:#ecfdf5; --warning-soft:#fff7ed;
      --table-head:#eff6ff; --table-head-text:#1E3A5F; --zebra:#fafafa; --row-highrisk:#fff1f2;
      --chip-bg:#f8fafc; --chip-text:#111827; --chip-border:#dbe2ea;
      --bar-track:#e5e7eb; --lead:#374151; --footer:#6B7280;
      --priority-divider:#fdba74; --donut-core:#ffffff; --donut-core-text:#111827; --donut-core-muted:#6B7280;
      --line-strong:#94a3b8;
    }}
    :root[data-theme="dark"] {{
        --primary:#93c5fd; --accent:#60a5fa; --high:#f87171; --medium:#fbbf24; --low:#4ade80;
        --cards:#111827; --text:#f3f4f6; --muted:#9ca3af; --line:#475569; --bg:#030712;
        --surface:#0f172a; --surface-soft:#111827;
        --danger-soft:#3a1217; --success-soft:#0f2e21; --warning-soft:#3a2b0f;
        --table-head:#1e293b; --table-head-text:#bfdbfe; --zebra:#162033; --row-highrisk:#3a1217;
        --chip-bg:#1f2937; --chip-text:#f3f4f6; --chip-border:#374151;
        --bar-track:#334155; --lead:#d1d5db; --footer:#94a3b8; --priority-divider:#fbbf24;
        --donut-core:#ffffff; --donut-core-text:#111827; --donut-core-muted:#6B7280;
        --line-strong:#64748b;
    }}
    @media (prefers-color-scheme: dark) {{
      :root:not([data-theme]) {{
        --primary:#93c5fd; --accent:#60a5fa; --high:#f87171; --medium:#fbbf24; --low:#4ade80;
        --cards:#111827; --text:#f3f4f6; --muted:#9ca3af; --line:#475569; --bg:#030712;
        --surface:#0f172a; --surface-soft:#111827;
        --danger-soft:#3a1217; --success-soft:#0f2e21; --warning-soft:#3a2b0f;
        --table-head:#1e293b; --table-head-text:#bfdbfe; --zebra:#162033; --row-highrisk:#3a1217;
        --chip-bg:#1f2937; --chip-text:#f3f4f6; --chip-border:#374151;
        --bar-track:#334155; --lead:#d1d5db; --footer:#94a3b8; --priority-divider:#fbbf24;
        --donut-core:#ffffff; --donut-core-text:#111827; --donut-core-muted:#6B7280;
        --line-strong:#64748b;
      }}
    }}
    * {{ box-sizing:border-box; }}
    * {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    html, body {{ min-height:100%; }}
    body {{ margin:0; font-family:Inter,Helvetica,Arial,sans-serif; background:var(--bg); color:var(--text); }}
    .topbar {{ position:sticky; top:0; z-index:10; background:var(--surface); border-bottom:1px solid var(--line-strong); padding:14px 24px; display:flex; justify-content:space-between; align-items:center; gap:16px; }}
    .top-actions {{ display:flex; gap:12px; }}
    .btn {{ padding:10px 16px; border-radius:12px; border:1px solid var(--line-strong); background:var(--surface); color:var(--primary); font-weight:700; cursor:pointer; text-decoration:none; box-shadow:0 1px 0 rgba(15,23,42,.04); }}
    .btn.primary {{ background:var(--accent); color:#fff; border-color:var(--accent); }}
    .report-shell {{ padding:24px 24px 36px; }}
    .report {{ width:min(238mm, calc(100vw - 48px)); min-height:297mm; margin:0 auto; background:var(--surface); padding:18mm 20mm 20mm 20mm; border-radius:22px; border:1px solid var(--line-strong); box-shadow:0 24px 60px rgba(15, 23, 42, 0.14); }}
    .divider {{ height:4px; background:linear-gradient(90deg,var(--primary),var(--accent)); border-radius:999px; margin:14px 0 18px; }}
    h1 {{ font-size:30px; margin:0 0 6px; }}
    h2 {{ font-size:20px; margin:0 0 14px; color:var(--primary); }}
    h3 {{ font-size:16px; margin:0 0 12px; }}
    p, li, td, th {{ font-size:11px; line-height:1.55; }}
    .header-grid {{ display:grid; grid-template-columns:1fr auto; gap:16px; align-items:start; }}
    .subtitle {{ color:var(--muted); display:flex; flex-wrap:wrap; gap:8px 16px; }}
    .risk-badge {{ padding:14px 20px; border-radius:18px; font-size:22px; font-weight:800; color:#fff; min-width:150px; text-align:center; }}
    .risk-high {{ background:var(--high); }} .risk-medium {{ background:var(--medium); }} .risk-low {{ background:var(--low); }}
    .kpi-row {{ display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin:18px 0 8px; }}
    .kpi-card {{ background:var(--cards); border:1px solid var(--line-strong); border-radius:18px; padding:16px; display:flex; gap:12px; align-items:flex-start; color:var(--text); }}
    .kpi-card span, .kpi-card strong, .kpi-card small {{ color:inherit; }}
    .kpi-card.danger {{ background:var(--danger-soft); color:var(--text); }} .kpi-card.success {{ background:var(--success-soft); color:var(--text); }}
    .kpi-icon {{ width:38px; height:38px; border-radius:12px; background:#dbeafe; display:flex; align-items:center; justify-content:center; font-weight:900; color:var(--accent); flex:0 0 auto; }}
    .kpi-card strong {{ display:block; font-size:28px; line-height:1; margin:6px 0; }}
    .kpi-card small, .muted {{ color:var(--muted); }}
    .section {{ margin-top:22px; }}
    .lead {{ font-size:12px; color:var(--lead); }}
    .highlight-box {{ background:var(--warning-soft); border:1px solid color-mix(in srgb, var(--medium) 45%, var(--surface)); border-left:6px solid var(--medium); border-radius:16px; padding:16px; color:var(--text); box-shadow:inset 0 0 0 1px color-mix(in srgb, var(--medium) 18%, transparent); }}
    .highlight-box * {{ color:inherit; }}
    .priority-item {{ padding:10px 0; border-bottom:1px dashed var(--priority-divider); font-weight:600; }}
    .layout-two {{ display:grid; grid-template-columns:1fr 1fr; gap:18px; }}
    .donut-wrap {{ display:flex; align-items:center; gap:16px; }}
    .donut-graphic {{ width:168px; height:168px; border-radius:50%; background:conic-gradient(var(--high) {listed_pct:.2f}%, var(--low) 0); position:relative; }}
    .donut-graphic::after {{ content:""; position:absolute; inset:18px; background:var(--donut-core); border-radius:50%; border:1px solid var(--line); }}
    .donut-center {{ position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center; z-index:1; text-align:center; color:var(--donut-core-text); }}
    .donut-center strong {{ font-size:24px; }}
    .donut-center span {{ color:var(--donut-core-muted); }}
    .legend-list {{ display:flex; flex-direction:column; gap:10px; }}
    .legend-item {{ display:flex; align-items:center; gap:10px; }}
    .legend-swatch {{ width:12px; height:12px; border-radius:999px; }}
    .bars {{ display:flex; flex-direction:column; gap:10px; }}
    .bar-row {{ display:grid; grid-template-columns:180px 1fr 42px; gap:10px; align-items:center; }}
    .bar-label {{ font-size:10px; color:var(--lead); }}
    .bar-track {{ height:12px; background:var(--bar-track); border-radius:999px; overflow:hidden; }}
    .bar-fill {{ height:100%; border-radius:999px; }}
    .heat-layout {{ display:grid; grid-template-columns:1fr 220px; gap:18px; align-items:start; }}
    .heat-box {{ background:var(--surface-soft); border:1px solid var(--line-strong); border-radius:16px; padding:12px; box-shadow:inset 0 0 0 1px rgba(148,163,184,.12); }}
    .heat-svg {{ width:100%; height:auto; display:block; }}
    .legend-table {{ width:100%; border-collapse:collapse; color:var(--text); }}
    .legend-table td {{ border-bottom:1px solid var(--line); padding:8px 6px; }}
    .blacklist-section {{ border:1px solid var(--line-strong); border-radius:16px; padding:14px; margin-bottom:14px; break-inside:avoid; color:var(--text); box-shadow:inset 0 0 0 1px rgba(148,163,184,.10); }}
    .section-head {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:12px; }}
    .ip-grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:8px; }}
    .ip-chip, .chip {{ display:inline-flex; justify-content:center; padding:8px 10px; border-radius:12px; background:var(--chip-bg); color:var(--chip-text); border:1px solid var(--line-strong); font-weight:600; }}
    .section-foot {{ margin-top:12px; color:var(--muted); font-size:10px; }}
    table {{ width:100%; border-collapse:collapse; }}
    thead {{ display:table-header-group; }}
    th {{ position:sticky; top:0; background:var(--table-head); color:var(--table-head-text); text-transform:uppercase; letter-spacing:.04em; font-size:10px; }}
    tr {{ page-break-inside:avoid; }}
    th, td {{ border-bottom:1px solid var(--line); padding:10px; vertical-align:top; }}
    tbody tr:nth-child(even) {{ background:var(--zebra); }}
    tbody tr.highrisk {{ background:var(--row-highrisk); }}
    table td, table th, table tr {{ color:var(--text); }}
    .badge {{ display:inline-flex; padding:4px 8px; border-radius:999px; font-size:10px; font-weight:700; margin:2px 4px 2px 0; border:1px solid transparent; }}
    .badge.spamhaus {{ background:#ede9fe; color:#6d28d9; border-color:#b8a5ff; }}
    .badge.barracuda {{ background:#ccfbf1; color:#0f766e; border-color:#5eead4; }}
    .badge.danger {{ background:#fee2e2; color:#b91c1c; border-color:#fca5a5; }}
    .badge.risk-high {{ background:#ef4444; color:#ffffff; border-color:#dc2626; }}
    .badge.neutral {{ background:#f3f4f6; color:#6b7280; border-color:#94a3b8; }}
    .method-grid {{ display:grid; grid-template-columns:1.2fr .8fr; gap:18px; }}
    .bullets {{ list-style:none; padding:0; margin:0; display:flex; flex-direction:column; gap:10px; }}
    .bullets li {{ display:grid; grid-template-columns:12px 1fr; gap:10px; }}
    .dot {{ width:8px; height:8px; border-radius:999px; background:var(--accent); margin-top:6px; }}
    .relevance-table {{ width:100%; border-collapse:collapse; color:var(--text); }}
    .relevance-swatch {{ width:14px; height:14px; border-radius:4px; display:inline-block; }}
    .relevance-swatch.veryhigh {{ background:var(--high); }}
    .relevance-swatch.high {{ background:var(--medium); }}
    .relevance-swatch.medium {{ background:#fbbf24; }}
    .relevance-swatch.info {{ background:#9ca3af; }}
    .footer {{ position:fixed; left:20mm; right:20mm; bottom:7mm; color:var(--footer); font-size:9px; display:flex; justify-content:space-between; }}
    .watermark {{ position:fixed; right:10mm; bottom:14mm; opacity:.06; font-size:52px; font-weight:800; color:var(--primary); transform:rotate(-18deg); }}
    @media screen and (max-width: 1180px) {{
      .report-shell {{ padding:16px; }}
      .report {{ width:min(100%, 238mm); padding:16mm 14mm 18mm; border-radius:18px; }}
      .header-grid, .layout-two, .heat-layout, .method-grid, .kpi-row {{ grid-template-columns:1fr; }}
      .topbar {{ flex-wrap:wrap; }}
    }}
    @media print {{
      :root,
      :root[data-theme="dark"],
      :root[data-theme="light"],
      :root:not([data-theme]) {{
        --primary:#1E3A5F; --accent:#2563EB; --high:#DC2626; --medium:#F59E0B; --low:#16A34A;
        --cards:#F8FAFC; --text:#111827; --muted:#6B7280; --line:#cbd5e1; --bg:#ffffff; --surface:#ffffff; --surface-soft:#f8fafc;
        --bar-track:#e5e7eb; --lead:#374151; --footer:#6B7280; --priority-divider:#fdba74;
        --donut-core:#ffffff; --donut-core-text:#111827; --donut-core-muted:#6B7280;
        --line-strong:#94a3b8;
      }}
      html, body {{ background:#ffffff; }}
      .topbar {{ display:none; }}
      .report-shell {{ padding:0; }}
      .report {{ width:100%; min-height:auto; margin:0; padding:0; border:none; border-radius:0; box-shadow:none; }}
      .header-grid {{ grid-template-columns:1fr auto; }}
      .kpi-row {{ grid-template-columns:repeat(4, 1fr); }}
      .layout-two {{ grid-template-columns:1fr 1fr; }}
      .heat-layout {{ grid-template-columns:1fr 220px; }}
      .method-grid {{ grid-template-columns:1.2fr .8fr; }}
      th {{ position:static; }}
      .footer {{ left:12mm; right:12mm; bottom:6mm; }}
      .watermark {{ right:8mm; bottom:12mm; }}
    }}
  </style>
  <script>
    const THEME_STORAGE_KEY = "inh-report-theme";
    let printThemeBackup = null;
    function detectPreferredTheme() {{
      return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    }}
    function updateThemeToggleLabel(theme) {{
      const button = document.getElementById("theme-toggle");
      if (!button) return;
      const effective = theme === "auto" ? detectPreferredTheme() : theme;
      button.textContent = effective === "dark" ? "Tema claro" : "Tema escuro";
    }}
    function applyTheme(theme) {{
      const root = document.documentElement;
      if (theme === "auto") {{
        root.removeAttribute("data-theme");
      }} else {{
        root.setAttribute("data-theme", theme);
      }}
      updateThemeToggleLabel(theme);
    }}
    function getStoredTheme() {{
      return localStorage.getItem(THEME_STORAGE_KEY) || "auto";
    }}
    function toggleTheme() {{
      const current = document.documentElement.getAttribute("data-theme") || detectPreferredTheme();
      const next = current === "dark" ? "light" : "dark";
      localStorage.setItem(THEME_STORAGE_KEY, next);
      applyTheme(next);
    }}
    function preparePrintTheme() {{
      const root = document.documentElement;
      printThemeBackup = root.getAttribute("data-theme");
      root.removeAttribute("data-theme");
      root.setAttribute("data-print-mode", "1");
    }}
    function restorePrintTheme() {{
      const root = document.documentElement;
      root.removeAttribute("data-print-mode");
      if (printThemeBackup) {{
        root.setAttribute("data-theme", printThemeBackup);
      }} else {{
        root.removeAttribute("data-theme");
      }}
      printThemeBackup = null;
      updateThemeToggleLabel(getStoredTheme());
    }}
    document.addEventListener("DOMContentLoaded", () => {{
      applyTheme(getStoredTheme());
      const media = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
      if (media) {{
        const handler = () => {{
          if (getStoredTheme() === "auto") {{
            applyTheme("auto");
          }}
        }};
        if (media.addEventListener) {{
          media.addEventListener("change", handler);
        }} else if (media.addListener) {{
          media.addListener(handler);
        }}
      }}
      window.addEventListener("beforeprint", preparePrintTheme);
      window.addEventListener("afterprint", restorePrintTheme);
    }});
    function exportPdf() {{
      preparePrintTheme();
      window.print();
    }}
  </script>
</head>
<body>
  <div class="topbar">
    <strong>ISP Network Health — Relatório Completo</strong>
    <div class="top-actions">
      <button class="btn" id="theme-toggle" onclick="toggleTheme()">Tema escuro</button>
      <a class="btn" href="{html.escape(json_file)}" download>Baixar JSON summary</a>
      <button class="btn primary" onclick="exportPdf()">Exportar PDF</button>
    </div>
  </div>
  <div class="report-shell">
  <div class="report">
    <section>
      <div class="header-grid">
        <div>
          <h1>Relatório Executivo de Reputação de IP</h1>
          <div class="subtitle">
            <span>Alvo: <strong>{html.escape(summary.normalized_input)}</strong></span>
            <span>ASN: <strong>{html.escape(summary.primary_asn)}</strong></span>
            <span>Titular: <strong>{html.escape(summary.primary_holder)}</strong></span>
            <span>Data/Hora: <strong>{html.escape(stamp)}</strong></span>
          </div>
        </div>
        <div class="risk-badge {risk_class}">{html.escape(summary.risk_level.upper())}</div>
      </div>
      <div class="divider"></div>
      <div class="kpi-row">{kpi_cards}</div>
    </section>

    <section class="section">
      <h2>Resumo Executivo</h2>
      <p class="lead">A análise do alvo {html.escape(summary.normalized_input)} identificou {summary.unique_ips_listed} IPs com evidências relevantes de listagem em blacklists, dentro de um universo de {summary.unique_ips_scanned} IPs avaliados. O contexto ASN associado é {html.escape(summary.primary_asn)} ({html.escape(summary.primary_holder)}), com classificação geral de risco {html.escape(summary.risk_level.lower())}.</p>
      <div class="highlight-box">
        <h3>Achados Prioritários</h3>
        {findings}
      </div>
      {f'<p class="lead"><strong>Visão resumida por faixas:</strong> {" | ".join(html.escape(item) for item in range_summary)}</p>' if len(range_summary) > 0 and summary.unique_ips_listed > 50 else ''}
    </section>

    <section class="section layout-two">
      <div>
        <h2>Distribuição de Reputação</h2>
        <div class="donut-wrap">
          <div class="donut-graphic">
            <div class="donut-center"><strong>{listed_pct:.1f}%</strong><span>IPs blacklistados</span></div>
          </div>
          <div class="legend-list">
            <div class="legend-item"><span class="legend-swatch" style="background:#dc2626"></span><span>Blacklistados: {summary.unique_ips_listed} ({listed_pct:.1f}%)</span></div>
            <div class="legend-item"><span class="legend-swatch" style="background:#16a34a"></span><span>Limpos: {summary.unique_ips_clean} ({clean_pct:.1f}%)</span></div>
          </div>
        </div>
      </div>
      <div>
        <h2>IPs por Blacklist</h2>
        <div class="bars">{bars_html}</div>
      </div>
    </section>

    <section class="section">
      <h2>Heatmap do Bloco /24</h2>
      <div class="heat-layout">
        <div class="heat-box">{heatmap_html}</div>
        <table class="legend-table">
          <tr><td><span class="legend-swatch" style="background:#dc2626"></span></td><td>Muito alta</td><td>{sum(1 for row in summary.inventory_rows if row['status']=='very_high')}</td></tr>
          <tr><td><span class="legend-swatch" style="background:#f59e0b"></span></td><td>Alta</td><td>{sum(1 for row in summary.inventory_rows if row['status']=='high')}</td></tr>
          <tr><td><span class="legend-swatch" style="background:#fbbf24"></span></td><td>Informacional/Média</td><td>{sum(1 for row in summary.inventory_rows if row['status'] in {'medium','informational'})}</td></tr>
          <tr><td><span class="legend-swatch" style="background:#16a34a"></span></td><td>Limpo</td><td>{sum(1 for row in summary.inventory_rows if row['status']=='clean')}</td></tr>
          <tr><td><span class="legend-swatch" style="background:#d1d5db"></span></td><td>Timeout/Erro</td><td>{sum(1 for row in summary.inventory_rows if row['status']=='timeout')}</td></tr>
        </table>
      </div>
    </section>

    <section class="section">
      <h2>Detalhamento por Blacklist</h2>
      {blacklist_sections or '<p class="muted">Nenhuma blacklist relevante acionada.</p>'}
    </section>

    <section class="section">
      <h2>Inventário Completo de IPs</h2>
      <table>
        <thead>
          <tr><th>IP</th><th>Blacklists relevantes</th><th>Listas informacionais</th><th>Nível de risco</th></tr>
        </thead>
        <tbody>{inventory_table}</tbody>
      </table>
    </section>

    <section class="section method-grid">
      <div>
        <h2>Metodologia</h2>
        <ul class="bullets">{methodology}</ul>
      </div>
      <div>
        <h2>Legenda de Relevância</h2>
        <table class="relevance-table">{relevance_table}</table>
      </div>
    </section>
  </div>
  </div>
  <div class="footer"><span>{html.escape(summary.normalized_input)}</span><span>{html.escape(stamp)}</span><span>ISP Network Health — Relatório Completo</span></div>
  <div class="watermark">REPUTAÇÃO IP</div>
</body>
</html>"""


def write_json_summary(summary: ScanSummary) -> None:
    payload = {
        "target": summary.normalized_input,
        "asn": summary.primary_asn,
        "holder": summary.primary_holder,
        "primary_prefix": summary.primary_prefix,
        "risk_level": summary.risk_level,
        "ips_scanned": summary.unique_ips_scanned,
        "ips_listed": summary.unique_ips_listed,
        "ips_clean": summary.unique_ips_clean,
        "blacklists": [{"name": name, "count": count, "relevance": blacklist_relevance(name)} for name, count in summary.top_blacklists],
        "critical_findings": summary.critical_findings,
    }
    summary.report_json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def open_report_in_browser(path: Path) -> None:
    uri = path.resolve().as_uri()
    opener = shutil.which("xdg-open") or shutil.which("gio") or shutil.which("open")
    try:
        if webbrowser.open(uri, new=2, autoraise=True):
            return
    except webbrowser.Error:
        pass

    if not opener:
        raise RuntimeError(f"Nao foi encontrado um abridor de navegador para {path}.")
    command = [opener, str(path)]
    if Path(opener).name == "gio":
        command = [opener, "open", str(path)]
    subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def render_report_html(summary: ScanSummary) -> str:
    stamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
    total_ips = max(summary.unique_ips_scanned, 1)
    participation_total = sum(count for _, count in summary.top_blacklists) or 1
    risk_class = "risk-high" if summary.risk_level == "Alto" else "risk-medium" if summary.risk_level == "Moderado" else "risk-low"

    cards_html = "".join(
        [
            f'<div class="metric-card"><span>Total de IPs</span><strong>{summary.unique_ips_scanned}</strong></div>',
            f'<div class="metric-card success"><span>IPs Limpos</span><strong>{summary.unique_ips_clean}</strong></div>',
            f'<div class="metric-card danger"><span>IPs em Blacklist</span><strong>{summary.unique_ips_listed}</strong></div>',
            f'<div class="metric-card {risk_class}"><span>Risco Geral</span><strong>{html.escape(summary.risk_level.upper())}</strong></div>',
        ]
    )
    participation_charts = "".join(
        _render_donut(name, count, participation_total, "#7c3aed" if "spamhaus" in name else "#0f766e" if "barracuda" in name else "#2563eb")
        for name, count in summary.top_blacklists[:4]
    )

    findings_html = "".join(
        f'<div class="alert-box"><strong>{html.escape(item)}</strong></div>'
        for item in (summary.critical_findings or ["Nenhuma listagem em blacklists de relevancia alta ou muito alta."])
    )

    methodology_html = "".join(
        f'<li><span class="icon">•</span><span>{html.escape(line)}</span></li>' for line in summary.methodology_lines
    )
    legend_html = "".join(
        f'<li><span class="icon">•</span><span>{html.escape(line)}</span></li>' for line in summary.relevance_legend
    )

    blacklist_list_html = "".join(
        "<li>"
        f"<span>{html.escape(name)}</span>"
        f"<span>{count} IPs</span>"
        f"{_render_badge(blacklist_relevance(name).upper(), 'spamhaus' if 'spamhaus' in name else 'barracuda' if 'barracuda' in name else 'neutral')}"
        "</li>"
        for name, count in summary.top_blacklists
    )

    inventory_rows_html = "".join(
        "<tr>"
        f"<td>{html.escape(str(row['ip']))}</td>"
        f"<td>{''.join(_render_badge(item, 'spamhaus' if 'spamhaus' in item else 'barracuda' if 'barracuda' in item else 'danger') for item in row['relevant']) or '<span class=\"muted\">-</span>'}</td>"
        f"<td>{''.join(_render_badge(item, 'neutral') for item in row['informational']) or '<span class=\"muted\">-</span>'}</td>"
        "</tr>"
        for row in summary.inventory_rows
    )

    appendix_html = "".join(
        '<section class="appendix-group">'
        f'<div class="appendix-head"><h4>{html.escape(group["name"])}</h4>{_render_badge(str(group["relevance"]).upper(), "spamhaus" if "spamhaus" in group["name"] else "barracuda" if "barracuda" in group["name"] else "neutral")}</div>'
        f'<div class="chip-cloud">{"".join(f"<span class=\"chip\">{html.escape(ip)}</span>" for ip in group["ips"])}</div>'
        '</section>'
        for group in summary.blacklist_groups
    )

    asn_context_html = "".join(f"<li>{html.escape(line)}</li>" for line in summary.asn_context_lines)
    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <title>Relatório Executivo de Reputação de Bloco IP</title>
  <style>
    @page {{
      size: A4;
      margin: 16mm 14mm 18mm 14mm;
    }}
    :root {{
      --bg: #f7f8fb;
      --surface: #ffffff;
      --ink: #0f172a;
      --muted: #475569;
      --line: #dbe2ea;
      --green: #059669;
      --red: #dc2626;
      --amber: #d97706;
      --blue: #2563eb;
      --slate: #64748b;
      --spamhaus: #7c3aed;
      --barracuda: #0f766e;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Inter, Roboto, Arial, sans-serif;
      color: var(--ink);
      background: var(--bg);
      font-size: 11px;
      line-height: 1.45;
    }}
    .page-break {{ break-before: page; page-break-before: always; }}
    .report {{
      display: flex;
      flex-direction: column;
      gap: 18px;
    }}
    .hero, .panel {{
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 18px 20px;
      box-shadow: 0 10px 28px rgba(15, 23, 42, 0.06);
    }}
    .hero {{
      background: linear-gradient(135deg, #ffffff 0%, #f5f9ff 100%);
    }}
    .eyebrow {{
      color: var(--blue);
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      font-size: 10px;
    }}
    h1, h2, h3, h4 {{ margin: 0; }}
    h1 {{ font-size: 25px; margin-top: 6px; }}
    h2 {{ font-size: 18px; margin-bottom: 12px; }}
    h3 {{ font-size: 14px; margin-bottom: 8px; }}
    .subhead {{
      margin-top: 10px;
      color: var(--muted);
      display: flex;
      flex-wrap: wrap;
      gap: 10px 16px;
    }}
    .pill {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 6px 10px;
      border-radius: 999px;
      background: #eff6ff;
      color: #1d4ed8;
      font-weight: 600;
    }}
    .metric-grid {{
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      margin-top: 18px;
    }}
    .metric-card {{
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 16px;
      background: #fcfdff;
    }}
    .metric-card span {{
      display: block;
      color: var(--muted);
      margin-bottom: 8px;
      font-weight: 600;
    }}
    .metric-card strong {{
      font-size: 28px;
      line-height: 1;
    }}
    .metric-card.success strong {{ color: var(--green); }}
    .metric-card.danger strong {{ color: var(--red); }}
    .metric-card.risk-high strong {{ color: var(--red); }}
    .metric-card.risk-medium strong {{ color: var(--amber); }}
    .metric-card.risk-low strong {{ color: var(--green); }}
    .two-col {{
      display: grid;
      grid-template-columns: 1.3fr 1fr;
      gap: 14px;
    }}
    .chart-row {{
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 12px;
      align-items: center;
    }}
    .chart-card {{
      display: flex;
      align-items: center;
      gap: 14px;
      padding: 8px 0;
    }}
    .donut {{
      --pct: 0;
      --accent: var(--blue);
      width: 138px;
      height: 138px;
      border-radius: 50%;
      background: conic-gradient(var(--accent) calc(var(--pct) * 1%), #e5e7eb 0);
      position: relative;
      flex: 0 0 auto;
    }}
    .donut::after {{
      content: "";
      position: absolute;
      inset: 14px;
      border-radius: 50%;
      background: white;
      box-shadow: inset 0 0 0 1px #edf2f7;
    }}
    .donut-inner {{
      position: absolute;
      inset: 0;
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: center;
      z-index: 1;
      text-align: center;
    }}
    .donut-inner strong {{ font-size: 24px; }}
    .donut-inner span {{ color: var(--muted); font-size: 10px; max-width: 88px; }}
    .chart-legend {{
      display: flex;
      align-items: center;
      gap: 10px;
    }}
    .legend-dot {{
      width: 12px;
      height: 12px;
      border-radius: 999px;
    }}
    .stack-list {{
      list-style: none;
      padding: 0;
      margin: 0;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }}
    .stack-list li {{
      display: grid;
      grid-template-columns: 1fr auto auto;
      gap: 10px;
      align-items: center;
      padding: 10px 12px;
      border: 1px solid var(--line);
      border-radius: 12px;
      background: #fbfcfe;
    }}
    .badge {{
      display: inline-flex;
      align-items: center;
      padding: 4px 8px;
      border-radius: 999px;
      font-size: 10px;
      font-weight: 700;
      margin: 2px 4px 2px 0;
      border: 1px solid transparent;
      white-space: nowrap;
    }}
    .badge.spamhaus {{ background: #f3e8ff; color: var(--spamhaus); border-color: #ddd6fe; }}
    .badge.barracuda {{ background: #dff7f3; color: var(--barracuda); border-color: #99f6e4; }}
    .badge.danger {{ background: #fee2e2; color: var(--red); border-color: #fecaca; }}
    .badge.neutral {{ background: #f1f5f9; color: var(--slate); border-color: #cbd5e1; }}
    .alert-grid {{
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 12px;
    }}
    .alert-box {{
      padding: 14px 16px;
      border-left: 5px solid var(--red);
      background: #fff5f5;
      border-radius: 12px;
      border: 1px solid #fecaca;
    }}
    .icon-list {{
      list-style: none;
      margin: 0;
      padding: 0;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }}
    .icon-list li {{
      display: grid;
      grid-template-columns: 18px 1fr;
      gap: 10px;
      align-items: start;
    }}
    .icon {{ color: var(--blue); font-weight: 900; }}
    .meta-grid {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 10px;
    }}
    thead {{ display: table-header-group; }}
    tr {{ page-break-inside: avoid; }}
    th, td {{
      padding: 10px 12px;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
      text-align: left;
    }}
    th {{
      background: #eff6ff;
      color: #1e3a8a;
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }}
    tbody tr:nth-child(even) {{ background: #fafcff; }}
    .muted {{ color: var(--muted); }}
    .appendix-group {{
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 14px;
      margin-bottom: 12px;
      page-break-inside: avoid;
      background: white;
    }}
    .appendix-head {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 10px;
      margin-bottom: 10px;
    }}
    .chip-cloud {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }}
    .chip {{
      display: inline-flex;
      padding: 6px 10px;
      border-radius: 999px;
      background: #eef2ff;
      color: #3730a3;
      font-weight: 600;
      border: 1px solid #c7d2fe;
    }}
    .footer-note {{
      color: var(--muted);
      font-size: 10px;
    }}
  </style>
</head>
<body>
  <main class="report">
    <section class="hero">
      <div class="eyebrow">Cyber Threat & Reputation Intelligence</div>
      <h1>Relatório Executivo de Reputação de Bloco IP</h1>
      <div class="subhead">
        <span class="pill">Alvo: {html.escape(summary.normalized_input)}</span>
        <span class="pill">Data/Hora: {html.escape(stamp)}</span>
        <span class="pill">{html.escape(summary.primary_asn)} - {html.escape(summary.primary_holder)}</span>
      </div>
      <div class="metric-grid">{cards_html}</div>
    </section>

    <section class="panel two-col">
      <div>
        <h2>Distribuição de Exposição</h2>
        <div class="chart-row">
          {_render_donut("IPs Limpos", summary.unique_ips_clean, total_ips, "#059669")}
          {_render_donut("IPs em Blacklist", summary.unique_ips_listed, total_ips, "#dc2626")}
        </div>
      </div>
      <div>
        <h2>Participação por Blacklist</h2>
        <div class="chart-row">{participation_charts}</div>
        <ul class="stack-list">{blacklist_list_html}</ul>
      </div>
    </section>

    <section class="page-break panel">
      <h2>Achados Prioritários</h2>
      <div class="alert-grid">{findings_html}</div>
      <div class="meta-grid" style="margin-top:16px;">
        <div>
          <h3>Metodologia e Política de Fontes</h3>
          <ul class="icon-list">{methodology_html}</ul>
        </div>
        <div>
          <h3>Legenda de Relevância</h3>
          <ul class="icon-list">{legend_html}</ul>
          <p class="footer-note">IPs suprimidos por hits apenas informacionais: {summary.suppressed_informational_ips}</p>
          <h3 style="margin-top:14px;">Contexto ASN</h3>
          <ul class="icon-list">{''.join(f'<li><span class="icon">•</span><span>{html.escape(line)}</span></li>' for line in summary.asn_context_lines)}</ul>
        </div>
      </div>
    </section>

    <section class="page-break panel">
      <h2>Inventário Completo de IPs Listados</h2>
      <p class="footer-note">Todos os IPs classificados como listados por ao menos uma blacklist relevante estão exibidos integralmente abaixo.</p>
      <table>
        <thead>
          <tr>
            <th>Endereço IP</th>
            <th>Blacklists Relevantes</th>
            <th>Blacklists Informacionais</th>
          </tr>
        </thead>
        <tbody>
          {inventory_rows_html or '<tr><td colspan="3" class="muted">Nenhum IP listado por blacklist relevante.</td></tr>'}
        </tbody>
      </table>
    </section>

    <section class="page-break panel">
      <h2>Apêndice Técnico</h2>
      <h3>Resumo por Prefixo</h3>
      <ul class="icon-list">{''.join(f'<li><span class="icon">•</span><span>{html.escape(item)}</span></li>' for item in summary.prefix_summaries) or '<li><span class="icon">•</span><span>Nenhum prefixo com IPs relevantes listados.</span></li>'}</ul>
      <h3 style="margin-top:16px;">IPs Agrupados por Blacklist</h3>
      {appendix_html or '<p class="muted">Nenhum agrupamento técnico a apresentar.</p>'}
    </section>
  </main>
</body>
</html>"""


def create_pdf_report(summary: ScanSummary) -> None:
    html_report = render_report_html(summary)
    summary.report_path.parent.mkdir(parents=True, exist_ok=True)
    html_path = summary.report_path.with_suffix(".html")
    html_path.write_text(html_report, encoding="utf-8")
    try:
        subprocess.run(
            [
                "chromium",
                "--headless=new",
                "--disable-gpu",
                "--no-sandbox",
                f"--print-to-pdf={summary.report_path}",
                "--no-pdf-header-footer",
                html_path.as_uri(),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"Falha ao converter o relatorio HTML em PDF com Chromium. HTML preservado em {html_path}."
        ) from exc


def create_report_type2(summary: ScanSummary) -> Path:
    html_path = summary.report_path.with_name(summary.report_path.stem + "-tipo2.html")
    summary.report_json_path = html_path.with_suffix(".json")
    html_path.write_text(render_report_type2_html(summary), encoding="utf-8")
    write_json_summary(summary)
    open_report_in_browser(html_path)
    return html_path


def save_log(log_lines: list[str]) -> None:
    answer = clear_and_prompt("Deseja salvar o log completo? [s/N]: ").lower()
    if answer not in {"s", "sim", "y", "yes"}:
        print("Log nao salvo.")
        return

    default_name = f"blacklist-log-{datetime.now().strftime('%Y%m%d-%H%M%S')}.log"
    destination = clear_and_prompt(f"Caminho do arquivo ou diretorio [{default_name}]: ")
    target = Path(destination or default_name).expanduser()
    if target.exists() and target.is_dir():
        target = target / default_name
    elif not target.suffix:
        target = target / default_name

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(log_lines) + "\n", encoding="utf-8")
    print(f"Log salvo em: {target}")


def run_scan(original_input: str, requested_workers: int, boost: bool, report_type: str) -> int:
    kind, normalized = detect_target_type(original_input)
    tasks, details, detected_mode, metadata = build_tasks(kind, normalized)
    ui = TerminalUI()
    hits: list[CheckResult] = []
    all_results: list[CheckResult] = []
    logs = render_log_header(normalized, detected_mode, details)
    recent_events: list[str] = []

    total = len(tasks)
    completed = 0
    started_at = time.monotonic()
    max_workers = determine_max_workers(total, requested_workers, boost)
    ip_target_count = len(metadata.get("ip_targets", []))
    asn_box_lines = metadata.get("asn_box_lines", [])
    ui.render(
        original_input=normalized,
        detected_mode=detected_mode,
        total_checks=total,
        completed_checks=completed,
        hits=hits,
        recent_events=recent_events,
        details=details,
        started_at=started_at,
        active_workers=0,
        max_workers=max_workers,
        ip_target_count=ip_target_count,
        asn_box_lines=asn_box_lines,
    )

    task_iterator = iter(tasks)
    pending: dict[concurrent.futures.Future[CheckResult], CheckTask] = {}

    def submit_next(executor: concurrent.futures.ThreadPoolExecutor) -> bool:
        try:
            task = next(task_iterator)
        except StopIteration:
            return False
        future = executor.submit(execute_task, task)
        pending[future] = task
        return True

    queue_depth = max_workers * (6 if boost else 3)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for _ in range(min(queue_depth, total)):
            if not submit_next(executor):
                break

        while pending:
            done, _ = concurrent.futures.wait(
                pending,
                timeout=REFRESH_INTERVAL_SECONDS,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            if not done:
                ui.render(
                    original_input=normalized,
                    detected_mode=detected_mode,
                    total_checks=total,
                    completed_checks=completed,
                    hits=hits,
                    recent_events=recent_events,
                    details=details,
                    started_at=started_at,
                    active_workers=len(pending),
                    max_workers=max_workers,
                    ip_target_count=ip_target_count,
                    asn_box_lines=asn_box_lines,
                )
                continue

            for future in done:
                task = pending.pop(future)
                result = future.result()
                completed += 1
                all_results.append(result)
                logs.append(serialize_result(result))
                is_relevant_hit = result.status == "listed" and blacklist_relevance(result.task.blacklist) != "informacional"
                if is_relevant_hit:
                    hits.append(result)
                    recent_events.append(f"Positivo: {task.target_value} em {task.blacklist}")
                elif result.status == "listed":
                    recent_events.append(f"Info: {task.target_value} em {task.blacklist}")
                elif result.status == "timeout":
                    recent_events.append(f"Timeout: {task.blacklist} para {task.target_value}")
                elif result.status == "error":
                    recent_events.append(f"Erro: {task.blacklist} para {task.target_value}")
                else:
                    recent_events.append(f"OK: {task.target_value} em {task.blacklist}")
                recent_events = recent_events[-30:]

                while len(pending) < queue_depth and submit_next(executor):
                    pass

            ui.render(
                original_input=normalized,
                detected_mode=detected_mode,
                total_checks=total,
                completed_checks=completed,
                hits=hits,
                recent_events=recent_events,
                details=details,
                started_at=started_at,
                active_workers=len(pending),
                max_workers=max_workers,
                ip_target_count=ip_target_count,
                asn_box_lines=asn_box_lines,
            )

    ui.render(
        original_input=normalized,
        detected_mode=detected_mode,
        total_checks=total,
        completed_checks=completed,
        hits=hits,
        recent_events=recent_events,
        details=details,
        started_at=started_at,
        active_workers=0,
        max_workers=max_workers,
        ip_target_count=ip_target_count,
        asn_box_lines=asn_box_lines,
        final=True,
    )
    summary = build_scan_summary(
        kind=kind,
        original_input=original_input,
        normalized_input=normalized,
        detected_mode=detected_mode,
        details=details,
        metadata=metadata,
        results=all_results,
    )
    if report_type == "2":
        html_path = create_report_type2(summary)
        print(f"Relatorio tipo 2 salvo em: {html_path}")
        print(f"JSON summary salvo em: {summary.report_json_path}")
    else:
        create_pdf_report(summary)
        print(f"Relatorio PDF salvo em: {summary.report_path}")
    save_log(logs)
    return 0


def ensure_dependencies() -> None:
    if shutil.which("dig"):
        return
    raise RuntimeError("O comando 'dig' nao esta disponivel neste ambiente.")


def main() -> int:
    ensure_dependencies()
    try:
        args = parse_args()
        target = args.target or clear_and_prompt(f"Informe o alvo para analise ({SUPPORTED_INPUT}): ")
        report_type = choose_report_type(args.report_type)
        boost_mode = choose_boost_mode(args.boost)
        return run_scan(target, args.workers, boost_mode, report_type)
    except KeyboardInterrupt:
        print("\nOperacao cancelada pelo usuario.")
        return 130
    except (RuntimeError, ValueError, socket.gaierror) as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
