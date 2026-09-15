from __future__ import annotations

import csv
import difflib
import fcntl
import hashlib
import io
import ipaddress
import json
import os
import re
import shutil
import tempfile
import unicodedata
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pycountry

from .models import Company, NetworkBlock, Publication


FILENAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,122}\.csv$")
COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
REGION_RE = re.compile(r"^[A-Z]{2}-[A-Z0-9]{1,3}$")
ASN_MAX = 4_294_967_295


def _public_contact() -> str:
    try:
        from flask import current_app

        return str(current_app.config.get("PUBLIC_CONTACT_EMAIL", "") or "").strip()
    except RuntimeError:
        return ""


def _suite_name() -> str:
    try:
        from flask import current_app

        return str(current_app.config.get("SUITE_NAME", "ISP Network Tools") or "ISP Network Tools").strip()
    except RuntimeError:
        return "ISP Network Tools"


@dataclass
class ValidationResult:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    entry_count: int = 0

    @property
    def valid(self) -> bool:
        return not self.errors


def canonical_json(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def snapshot_hash(data: dict) -> str:
    return hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest()


def _valid_country(code: str) -> bool:
    return bool(code and pycountry.countries.get(alpha_2=code.upper()))


def _valid_region(code: str, country: str = "") -> bool:
    subdivision = pycountry.subdivisions.get(code=code.upper()) if code else None
    return bool(subdivision and (not country or subdivision.country_code == country.upper()))


def _unsafe_text(value: str) -> bool:
    return any(ord(character) < 32 and character not in {"\t"} for character in value)


def validate_geofeed_content(
    content: bytes,
    *,
    expected_block: dict | None = None,
) -> ValidationResult:
    """Validate a published feed using RFC 8805 and RFC 4180 publisher rules."""
    result = ValidationResult()
    if content.startswith(b"\xef\xbb\xbf"):
        result.warnings.append("O arquivo contém BOM UTF-8; prefira UTF-8 sem BOM.")
        content = content[3:]
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        result.errors.append(f"O arquivo não está em UTF-8 (byte {exc.start}).")
        return result
    if "\x00" in text:
        result.errors.append("O arquivo contém byte NUL, que não é permitido em CSV de texto.")
    if re.search(r"(?<!\r)\n|\r(?!\n)", text):
        result.errors.append("As linhas devem ser separadas por CRLF, conforme a RFC 8805.")

    records: list[tuple[int, list[str]]] = []
    for line_number, physical_line in enumerate(text.split("\r\n"), start=1):
        if not physical_line.strip() or physical_line.startswith("#"):
            continue
        try:
            row = next(csv.reader([physical_line], strict=True))
        except csv.Error as exc:
            result.errors.append(f"Linha {line_number}: CSV inválido ({exc}).")
            continue
        records.append((line_number, row))

    seen: set[str] = set()
    parent = None
    if expected_block:
        try:
            parent = ipaddress.ip_network(str(expected_block.get("cidr", "")), strict=True)
        except ValueError:
            result.errors.append("O bloco esperado possui CIDR inválido.")
    for line_number, row in records:
        label = f"Linha {line_number}"
        if len(row) < 5:
            result.warnings.append(
                f"{label}: são recomendados cinco campos e quatro vírgulas; encontrados {len(row)} campos."
            )
            row += [""] * (5 - len(row))
        elif len(row) > 5:
            result.warnings.append(
                f"{label}: campos adicionais serão ignorados pelos consumidores compatíveis."
            )
        prefix_raw, country_raw, region_raw, city, postal = row[:5]
        prefix = prefix_raw.strip()
        country = country_raw.strip().upper()
        region = region_raw.strip().upper()
        if any(value != value.strip() for value in (prefix_raw, country_raw, region_raw)):
            result.errors.append(f"{label}: campos estruturados não podem ter espaços nas extremidades.")
        try:
            network = ipaddress.ip_network(prefix, strict=True)
        except ValueError as exc:
            result.errors.append(f"{label}: IP ou prefixo CIDR inválido ({exc}).")
            continue
        canonical = str(network)
        if canonical in seen:
            result.errors.append(f"{label}: prefixo duplicado {canonical}.")
        seen.add(canonical)
        if parent and (network.version != parent.version or not network.subnet_of(parent)):
            result.errors.append(f"{label}: {canonical} não pertence ao bloco {parent}.")
        if country and not _valid_country(country):
            result.errors.append(f"{label}: código de país ISO 3166-1 alpha-2 inválido ({country}).")
        if region and not _valid_region(region, country):
            result.errors.append(f"{label}: código de região ISO 3166-2 inválido ou incompatível ({region}).")
        for field_name, value in (("cidade", city), ("código postal", postal)):
            if "," in value or "#" in value or "\r" in value or "\n" in value or _unsafe_text(value):
                result.errors.append(f"{label}: {field_name} contém caractere inválido.")
            if value.startswith(("=", "+", "-", "@")):
                result.errors.append(f"{label}: {field_name} iniciado por operador de planilha não é permitido.")
        if postal:
            result.warnings.append(f"{label}: postal_code é obsoleto na RFC 8805 e deve ficar vazio em novos feeds.")
        result.entry_count += 1

    if not records:
        result.errors.append("O CSV não contém entradas de geofeed.")
    if expected_block:
        expected_prefixes = set()
        for item in expected_block.get("entries", []):
            try:
                expected_prefixes.add(
                    str(ipaddress.ip_network(str(item.get("prefix", "")), strict=True))
                )
            except ValueError:
                result.errors.append("A publicação aprovada contém um prefixo esperado inválido.")
        missing = sorted(expected_prefixes - seen)
        extra = sorted(seen - expected_prefixes)
        if missing:
            result.errors.append("Prefixos ausentes em relação à publicação: " + ", ".join(missing[:10]) + ".")
        if extra:
            result.errors.append("Prefixos inesperados em relação à publicação: " + ", ".join(extra[:10]) + ".")
    return result


def build_snapshot() -> dict:
    companies = []
    for company in Company.query.order_by(Company.name).all():
        companies.append(
            {
                "id": company.id,
                "name": company.name,
                "default_asn": company.default_asn,
                "contact_email": company.contact_email,
                "active": company.active,
            }
        )

    blocks = []
    for block in NetworkBlock.query.order_by(
        NetworkBlock.ip_version, NetworkBlock.cidr
    ).all():
        entries = [
            {
                "prefix": entry.prefix,
                "alpha2code": entry.alpha2code,
                "region": entry.region,
                "city": entry.city,
                "postal_code": entry.postal_code,
                "sort_order": entry.sort_order,
            }
            for entry in block.entries
        ]
        blocks.append(
            {
                "id": block.id,
                "cidr": block.cidr,
                "ip_version": block.ip_version,
                "company_id": block.company_id,
                "company_name": block.company.name,
                "asn": block.asn,
                "filename": block.filename,
                "description": block.description,
                "active": block.active,
                "entries": entries,
            }
        )
    return {"schema": 1, "companies": companies, "blocks": blocks}


def validate_snapshot(snapshot: dict) -> ValidationResult:
    result = ValidationResult()
    company_ids = {item["id"] for item in snapshot.get("companies", []) if item["active"]}
    filenames: set[str] = set()
    parent_networks: list[tuple[dict, ipaddress._BaseNetwork]] = []

    for company in snapshot.get("companies", []):
        if not company["name"].strip():
            result.errors.append("Existe uma empresa sem nome.")
        if not 1 <= int(company["default_asn"]) <= ASN_MAX:
            result.errors.append(f"ASN inválido na empresa {company['name']}.")

    for block in snapshot.get("blocks", []):
        label = block.get("cidr", "bloco sem identificação")
        if not block.get("active"):
            continue
        try:
            parent = ipaddress.ip_network(label, strict=True)
        except ValueError as exc:
            result.errors.append(f"Bloco {label}: CIDR inválido ({exc}).")
            continue
        parent_networks.append((block, parent))
        if parent.version != int(block.get("ip_version", 0)):
            result.errors.append(f"Bloco {label}: família IP divergente.")
        if block.get("company_id") not in company_ids:
            result.errors.append(f"Bloco {label}: empresa ausente ou inativa.")
        if not 1 <= int(block.get("asn", 0)) <= ASN_MAX:
            result.errors.append(f"Bloco {label}: ASN inválido.")
        filename = str(block.get("filename", ""))
        if not FILENAME_RE.fullmatch(filename):
            result.errors.append(
                f"Bloco {label}: nome de arquivo inválido; use letras minúsculas, "
                "números, ponto, hífen ou sublinhado e termine em .csv."
            )
        if filename in filenames:
            result.errors.append(f"Arquivo duplicado: {filename}.")
        filenames.add(filename)

        entries = block.get("entries", [])
        if not entries:
            result.errors.append(f"Bloco {label}: nenhuma entrada de geolocalização.")
            continue
        seen: set[str] = set()
        for position, entry in enumerate(entries, start=1):
            prefix_text = str(entry.get("prefix", "")).strip()
            item_label = f"{label}, linha {position}"
            try:
                child = ipaddress.ip_network(prefix_text, strict=True)
            except ValueError as exc:
                result.errors.append(f"{item_label}: prefixo inválido ({exc}).")
                continue
            canonical = str(child)
            if child.version != parent.version or not child.subnet_of(parent):
                result.errors.append(
                    f"{item_label}: {canonical} não pertence ao bloco {parent}."
                )
            if canonical in seen:
                result.errors.append(f"{item_label}: prefixo duplicado {canonical}.")
            seen.add(canonical)

            country = str(entry.get("alpha2code", "")).strip().upper()
            region = str(entry.get("region", "")).strip().upper()
            city = str(entry.get("city", "")).strip()
            postal = str(entry.get("postal_code", "")).strip()
            if country and (not COUNTRY_RE.fullmatch(country) or not _valid_country(country)):
                result.errors.append(f"{item_label}: país deve usar um código ISO 3166-1 alpha-2 válido.")
            if region and (not REGION_RE.fullmatch(region) or not _valid_region(region, country)):
                result.errors.append(f"{item_label}: região deve usar um código ISO 3166-2 válido e compatível com o país.")
            if "," in city or "#" in city or "\r" in city or "\n" in city:
                result.errors.append(f"{item_label}: cidade contém caractere inválido.")
            if "," in postal or "#" in postal or "\r" in postal or "\n" in postal:
                result.errors.append(f"{item_label}: código postal contém caractere inválido.")
            if city.startswith(("=", "+", "-", "@")) or postal.startswith(
                ("=", "+", "-", "@")
            ):
                result.errors.append(
                    f"{item_label}: texto iniciado por operador de planilha não é permitido."
                )
            if postal:
                result.warnings.append(
                    f"{item_label}: postal_code é desaconselhado pela RFC 8805."
                )

    for index, (left_block, left) in enumerate(parent_networks):
        for right_block, right in parent_networks[index + 1 :]:
            if left.version == right.version and left.overlaps(right):
                result.warnings.append(
                    f"Os blocos {left_block['cidr']} e {right_block['cidr']} se sobrepõem."
                )
    return result


def _csv_value(value: object) -> str:
    return "" if value is None else str(value).strip()


def generate_csv(block: dict, published_at: datetime | None = None) -> bytes:
    timestamp = (published_at or datetime.now(ZoneInfo("America/Sao_Paulo"))).astimezone(
        ZoneInfo("America/Sao_Paulo")
    )
    output = io.StringIO(newline="")
    comments = [
        "#",
        f"# {_public_contact()}" if _public_contact() else "#",
        f"# {_suite_name()} last updated (rfc3339): {timestamp.isoformat(timespec='seconds')}",
        "# Self-published geofeed as defined in https://www.rfc-editor.org/rfc/rfc8805",
        "#",
        "#ip_prefix,#alpha2code,#region,#city,#postal_code",
        "#",
        f"# REDE {block['cidr']} - {block['company_name']} - AS{block['asn']}",
    ]
    for comment in comments:
        output.write(comment + "\r\n")
    writer = csv.writer(output, lineterminator="\r\n")
    entries = sorted(
        block.get("entries", []),
        key=lambda item: (int(item.get("sort_order", 0)), item.get("prefix", "")),
    )
    for entry in entries:
        writer.writerow(
            [
                _csv_value(entry.get("prefix")),
                _csv_value(entry.get("alpha2code")).upper(),
                _csv_value(entry.get("region")).upper(),
                _csv_value(entry.get("city")),
                _csv_value(entry.get("postal_code")),
            ]
        )
    return output.getvalue().encode("utf-8")


def snapshot_as_text(snapshot: dict) -> str:
    lines: list[str] = []
    for block in snapshot.get("blocks", []):
        if not block.get("active"):
            continue
        lines.append(
            f"{block['filename']} | {block['cidr']} | {block['company_name']} | AS{block['asn']}"
        )
        for entry in block.get("entries", []):
            lines.append(
                "  "
                + ",".join(
                    [
                        _csv_value(entry.get("prefix")),
                        _csv_value(entry.get("alpha2code")),
                        _csv_value(entry.get("region")),
                        _csv_value(entry.get("city")),
                        _csv_value(entry.get("postal_code")),
                    ]
                )
            )
    return "\n".join(lines) + ("\n" if lines else "")


def diff_snapshots(old: dict | None, new: dict) -> str:
    old_lines = snapshot_as_text(old or {"blocks": []}).splitlines(keepends=True)
    new_lines = snapshot_as_text(new).splitlines(keepends=True)
    return "".join(
        difflib.unified_diff(
            old_lines, new_lines, fromfile="publicado", tofile="proposto", n=3
        )
    )


def parse_csv(content: bytes) -> list[dict]:
    if content.startswith(b"\xef\xbb\xbf"):
        content = content[3:]
    text = content.decode("utf-8")
    entries: list[dict] = []
    reader = csv.reader(io.StringIO(text, newline=""))
    for line_number, row in enumerate(reader, start=1):
        if not row or not any(cell.strip() for cell in row):
            continue
        if row[0].lstrip().startswith("#"):
            continue
        if len(row) < 5:
            row += [""] * (5 - len(row))
        if len(row) > 5:
            raise ValueError(f"Linha {line_number}: mais de cinco colunas.")
        entries.append(
            {
                "prefix": row[0].strip(),
                "alpha2code": row[1].strip().upper(),
                "region": row[2].strip().upper(),
                "city": row[3].strip(),
                "postal_code": row[4].strip(),
                "sort_order": len(entries),
            }
        )
    if not entries:
        raise ValueError("O CSV não contém entradas de geofeed.")
    return entries


def _company_filename(name: str, company_id: object, used: set[str]) -> str:
    slug = unicodedata.normalize("NFKD", str(name)).encode("ascii", "ignore").decode("ascii").lower()
    slug = re.sub(r"[^a-z0-9]+", "-", slug).strip("-") or f"empresa-{company_id}"
    filename = f"geofeed-{slug[:110]}.csv"
    if filename in used:
        filename = f"geofeed-{slug[:95]}-{company_id}.csv"
    return filename


def generate_company_csv(company: dict, blocks: list[dict], published_at: datetime | None = None) -> bytes:
    """Generate one RFC 8805-compatible CSV containing every active block of a company."""
    timestamp = (published_at or datetime.now(ZoneInfo("America/Sao_Paulo"))).astimezone(
        ZoneInfo("America/Sao_Paulo")
    )
    output = io.StringIO(newline="")
    for line in (
        "#",
        f"# {_public_contact()}" if _public_contact() else "#",
        f"# {_suite_name()} last updated (rfc3339): {timestamp.isoformat(timespec='seconds')}",
        "# Consolidated company geofeed as defined in https://www.rfc-editor.org/rfc/rfc8805",
        "#",
        "#ip_prefix,#alpha2code,#region,#city,#postal_code",
    ):
        output.write(line + "\r\n")
    writer = csv.writer(output, lineterminator="\r\n")
    for block in sorted(blocks, key=lambda item: (int(item.get("ip_version", 0)), item.get("cidr", ""))):
        output.write(f"# REDE {block['cidr']} - {company['name']} - AS{block['asn']}\r\n")
        for entry in sorted(block.get("entries", []), key=lambda item: (int(item.get("sort_order", 0)), item.get("prefix", ""))):
            writer.writerow([
                _csv_value(entry.get("prefix")), _csv_value(entry.get("alpha2code")).upper(),
                _csv_value(entry.get("region")).upper(), _csv_value(entry.get("city")),
                _csv_value(entry.get("postal_code")),
            ])
    return output.getvalue().encode("utf-8")


def _manifest(snapshot: dict, public_base_url: str, published_at: datetime, company_feeds: list[dict] | None = None) -> bytes:
    data = {
        "schema": 1,
        "generated_at": published_at.isoformat(),
        "feeds": [
            {
                "block": block["cidr"],
                "ip_version": block["ip_version"],
                "company": block["company_name"],
                "asn": block["asn"],
                "filename": block["filename"],
                "csv_url": f"{public_base_url}/{block['filename']}",
                "entry_count": len(block.get("entries", [])),
            }
            for block in snapshot.get("blocks", [])
            if block.get("active")
        ],
        "companies": company_feeds or [],
    }
    return (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _group_active_company_blocks(blocks: list[dict]) -> list[tuple[object, list[dict]]]:
    grouped: dict[object, list[dict]] = {}
    for block in blocks:
        grouped.setdefault(block.get("company_id"), []).append(block)
    return sorted(grouped.items(), key=lambda item: str(item[0]))


def publish_snapshot(
    snapshot: dict,
    public_root: str,
    backup_root: str,
    public_base_url: str,
) -> str:
    validation = validate_snapshot(snapshot)
    if not validation.valid:
        raise ValueError("Publicação recusada: " + " ".join(validation.errors))

    destination = Path(public_root).resolve()
    backups = Path(backup_root).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    backups.mkdir(parents=True, exist_ok=True)
    now = datetime.now(ZoneInfo("America/Sao_Paulo"))
    stamp = now.strftime("%Y%m%d-%H%M%S")
    archive = backups / f"publication-{stamp}.zip"
    lock_path = backups / ".publish.lock"

    active_blocks = [block for block in snapshot["blocks"] if block.get("active")]
    generated = {block["filename"]: generate_csv(block, now) for block in active_blocks}
    for block in active_blocks:
        file_validation = validate_geofeed_content(
            generated[block["filename"]], expected_block=block
        )
        if not file_validation.valid:
            raise ValueError(
                f"Arquivo {block['filename']} fora da RFC 8805: "
                + " ".join(file_validation.errors)
            )
    used_names = set(generated)
    company_feeds = []
    companies_by_id = {company["id"]: company for company in snapshot.get("companies", []) if company.get("active")}
    for company_id, company_blocks in _group_active_company_blocks(active_blocks):
        company = companies_by_id.get(company_id)
        if not company:
            continue
        filename = _company_filename(company["name"], company_id, used_names)
        used_names.add(filename)
        generated[filename] = generate_company_csv(company, company_blocks, now)
        company_feeds.append({
            "company": company["name"], "filename": filename,
            "csv_url": f"{public_base_url}/{filename}",
            "block_count": len(company_blocks),
            "entry_count": sum(len(block.get("entries", [])) for block in company_blocks),
            "blocks": [block["cidr"] for block in company_blocks],
        })
    generated["geofeed-manifest.json"] = _manifest(snapshot, public_base_url, now, company_feeds)

    managed_path = destination / ".geofeed-managed-files.json"
    previous_managed: set[str] = set()
    if managed_path.is_file():
        try:
            previous_managed = set(json.loads(managed_path.read_text(encoding="utf-8")))
        except (ValueError, OSError):
            previous_managed = set()
    new_managed = set(generated)

    with lock_path.open("a+b") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
            for name in sorted(previous_managed | new_managed):
                current = destination / name
                if current.is_file():
                    bundle.write(current, arcname=name)
            if managed_path.is_file():
                bundle.write(managed_path, arcname=managed_path.name)

        stage = Path(tempfile.mkdtemp(prefix=".geofeed-stage-", dir=destination))
        try:
            for name, content in generated.items():
                target = stage / name
                target.write_bytes(content)
                os.chmod(target, 0o644)
            for name in sorted(generated):
                os.replace(stage / name, destination / name)
            for retired in sorted(previous_managed - new_managed):
                retired_path = destination / retired
                if retired_path.is_file():
                    retired_path.unlink()
            managed_tmp = stage / ".managed.tmp"
            managed_tmp.write_text(
                json.dumps(sorted(new_managed), indent=2) + "\n", encoding="utf-8"
            )
            os.chmod(managed_tmp, 0o644)
            os.replace(managed_tmp, managed_path)
        finally:
            shutil.rmtree(stage, ignore_errors=True)
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
    return str(archive)


def latest_published_snapshot() -> dict | None:
    publication = Publication.query.order_by(Publication.version.desc()).first()
    return json.loads(publication.snapshot_json) if publication else None
