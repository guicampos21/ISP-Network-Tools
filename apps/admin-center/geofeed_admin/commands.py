from __future__ import annotations

import json
import time
from pathlib import Path

import click
from apscheduler.schedulers.background import BackgroundScheduler
from flask import current_app

from .geofeed import build_snapshot, parse_csv, validate_snapshot
from .models import Company, FeedEntry, NetworkBlock, User, db
from .operations import periodic_healthcheck_due, process_scheduled, publish, run_healthchecks
from .settings import get_setting


SEED_BLOCKS = [
    ("168.90.48.0/22", "primary", 265264, "geofeed168.csv"),
    ("187.95.128.0/22", "primary", 265264, "geofeed187.csv"),
    ("2804:2d28::/32", "primary", 265264, "geofeed2d28.csv"),
    ("200.169.64.0/21", "primary", 52976, "geofeed200.csv"),
    ("2804:420::/32", "primary", 52976, "geofeed420.csv"),
    ("2804:865c::/32", "primary", 272638, "geofeed865c.csv"),
]


def _bootstrap_admin() -> None:
    email = current_app.config.get("ENTRA_INITIAL_ADMIN_EMAIL", "").strip().casefold()
    existing = User.query.filter_by(email=email).first() if email else None
    if existing and existing.role != "super_admin":
        existing.role = "super_admin"
        existing.active = True
        db.session.commit()
    elif email and not existing:
        db.session.add(
            User(email=email, display_name="Administrador inicial", role="super_admin", active=True)
        )
        db.session.commit()


def register_commands(app) -> None:
    @app.cli.command("init-db")
    def init_db():
        """Cria o banco e o administrador inicial, sem publicar arquivos."""
        db.create_all()
        _bootstrap_admin()
        click.echo("Banco inicializado.")

    @app.cli.command("seed-current")
    @click.option("--csv-dir", required=True, type=click.Path(file_okay=False, path_type=Path))
    def seed_current(csv_dir: Path):
        """Importa os seis geofeeds existentes para uma base vazia."""
        db.create_all()
        _bootstrap_admin()
        if Company.query.count() or NetworkBlock.query.count():
            raise click.ClickException("A base já possui empresas ou blocos; seed recusado.")
        company_name = current_app.config.get("COMPANY_NAME", "Sua empresa").strip()[:120]
        companies: dict[str, Company] = {}
        for _cidr, name, asn, _filename in SEED_BLOCKS:
            if name not in companies:
                company = Company(
                    name=company_name if name == "primary" else name,
                    default_asn=asn,
                    contact_email=current_app.config.get("PUBLIC_CONTACT_EMAIL", ""),
                    active=True,
                )
                db.session.add(company)
                db.session.flush()
                companies[name] = company
        for cidr, name, asn, filename in SEED_BLOCKS:
            source = csv_dir / filename
            if not source.is_file():
                db.session.rollback()
                raise click.ClickException(f"Arquivo ausente: {source}")
            import ipaddress

            network = ipaddress.ip_network(cidr, strict=True)
            block = NetworkBlock(
                cidr=str(network),
                ip_version=network.version,
                company_id=companies[name].id,
                asn=asn,
                filename=filename,
                active=True,
            )
            db.session.add(block)
            db.session.flush()
            for item in parse_csv(source.read_bytes()):
                db.session.add(FeedEntry(block_id=block.id, **item))
        db.session.flush()
        validation = validate_snapshot(build_snapshot())
        if not validation.valid:
            db.session.rollback()
            raise click.ClickException("Seed inválido: " + " ".join(validation.errors))
        db.session.commit()
        click.echo(
            f"Importação concluída: {len(SEED_BLOCKS)} blocos; "
            f"{FeedEntry.query.count()} entradas."
        )

    @app.cli.command("validate-working")
    def validate_working():
        """Valida o estado de trabalho segundo RFC 8805 e regras internas."""
        validation = validate_snapshot(build_snapshot())
        for warning in validation.warnings:
            click.echo(f"AVISO: {warning}")
        for error in validation.errors:
            click.echo(f"ERRO: {error}")
        if not validation.valid:
            raise click.ClickException(f"{len(validation.errors)} erro(s) encontrado(s).")
        click.echo("Validação concluída sem erros.")

    @app.cli.command("publish-working")
    def publish_working():
        """Publica o estado de trabalho usando o primeiro administrador ativo."""
        db.create_all()
        publisher = User.query.filter(User.role.in_(["super_admin", "admin"]), User.active.is_(True)).order_by(User.id).first()
        if not publisher:
            raise click.ClickException("Nenhum administrador ativo cadastrado.")
        snapshot = build_snapshot()
        validation = validate_snapshot(snapshot)
        if not validation.valid:
            raise click.ClickException("Publicação recusada: " + " ".join(validation.errors))
        publication = publish(snapshot, publisher, "Importação inicial dos geofeeds atuais")
        db.session.commit()
        click.echo(f"Publicação v{publication.version} concluída.")

    @app.cli.command("run-worker")
    def run_worker():
        """Executa agendamentos e monitoramento em processo separado."""
        db.create_all()
        scheduler = BackgroundScheduler(timezone="UTC")

        def scheduled_job():
            with app.app_context():
                process_scheduled()

        def health_job():
            with app.app_context():
                if periodic_healthcheck_due():
                    run_healthchecks(trigger="periodic")

        scheduler.add_job(
            scheduled_job,
            "interval",
            minutes=1,
            id="scheduled-publications",
            max_instances=1,
            coalesce=True,
        )
        scheduler.add_job(
            health_job,
            "interval",
            minutes=1,
            id="public-healthchecks",
            max_instances=1,
            coalesce=True,
        )
        scheduler.start()
        click.echo("Worker iniciado.")
        try:
            while True:
                time.sleep(30)
        except (KeyboardInterrupt, SystemExit):
            scheduler.shutdown(wait=False)
