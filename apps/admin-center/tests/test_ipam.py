from unittest.mock import Mock

from .conftest import login_as

from geofeed_admin.geofeed import build_snapshot
from geofeed_admin.routes import _audit_application, _public_ipam_metrics
from geofeed_admin.models import (
    AuditLog,
    Company,
    IpamAllocation,
    IpamApprovalRequest,
    IpamCustomer,
    IpamEquipment,
    IpamPop,
    ServiceCatalogItem,
    Publication,
    customer_service_items,
    User,
    db,
)
import geofeed_admin.routes as ipam_routes


def publish_ipam_fixture(app, entries):
    with app.app_context():
        user = User.query.filter_by(email="admin@example.test").one()
        snapshot = build_snapshot()
        snapshot["blocks"][0]["entries"] = [
            {
                "prefix": prefix,
                "alpha2code": "BR",
                "region": "BR-PR",
                "city": "Curitiba",
                "postal_code": "",
            }
            for prefix in entries
        ]
        db.session.add(Publication(
            version=1,
            snapshot_json=__import__("json").dumps(snapshot),
            snapshot_hash="test-snapshot",
            published_by_id=user.id,
        ))
        db.session.commit()


def grant_ipam(app, email="admin@example.test"):
    with app.app_context():
        user = User.query.filter_by(email=email).one()
        db.session.commit()
        return user.id


def test_geofeed_inventory_import_is_idempotent_and_preserves_publication(app):
    with app.app_context():
        before = build_snapshot()
    runner = app.test_cli_runner()
    first = runner.invoke(args=["import-geofeed-inventory"])
    assert first.exit_code == 0, first.output
    assert "1 bloco(s)" in first.output
    second = runner.invoke(args=["import-geofeed-inventory"])
    assert second.exit_code == 0, second.output
    assert "0 bloco(s)" in second.output
    with app.app_context():
        assert build_snapshot() == before
        allocation = IpamAllocation.query.one()
        assert allocation.source_block_id is not None
        assert allocation.approval_status == "approved"
        assert _public_ipam_metrics()["public_ipv4"] == 1024


def test_dashboard_public_address_total_includes_allocated_blocks_without_double_counting(app):
    with app.app_context():
        db.session.add_all([
            IpamAllocation(prefix="168.90.48.0/22", scope="public", status="allocated", approval_status="approved"),
            IpamAllocation(prefix="168.90.48.0/24", scope="public", status="allocated", approval_status="approved"),
            IpamAllocation(prefix="10.0.0.0/8", scope="private", status="available", approval_status="approved"),
        ])
        db.session.commit()
        metrics = _public_ipam_metrics()
        assert metrics["public_ipv4"] == 1024
        assert metrics["public_24s"] == 4
        assert metrics["available_ips"] == 0


def test_ipam_is_protected_by_its_application_entitlement(client, app):
    login_as(client, app, "viewer@example.test")
    assert client.get("/ipam").status_code == 403

    grant_ipam(app)
    login_as(client, app, "admin@example.test")
    assert client.get("/ipam").status_code == 200


def test_master_registries_follow_their_profile_permissions(client, app):
    login_as(client, app, "viewer@example.test")

    customers = client.get("/customers")
    pops_dcs = client.get("/pops-dcs")
    ipam_inventory = client.get("/ipam")
    ipam_blocks = client.get("/blocks")

    assert customers.status_code == 200
    assert pops_dcs.status_code == 200
    assert ipam_inventory.status_code == 403
    assert ipam_blocks.status_code == 403

    login_as(client, app, "admin@example.test")
    assert client.get("/customers").status_code == 200
    assert client.get("/pops-dcs").status_code == 200


def test_audit_labels_moved_geofeed_workflows_as_ipam():
    assert _audit_application(type("Log", (), {"action": "company.created"})()) == "admin_center"
    assert _audit_application(type("Log", (), {"action": "service.created"})()) == "admin_center"
    assert _audit_application(type("Log", (), {"action": "change.approved"})()) == "ipam_geofeed"
    assert _audit_application(type("Log", (), {"action": "scan.created"})()) == "isp_network_health"


def test_ipam_keeps_geofeed_snapshot_and_rejects_overlaps(client, app):
    grant_ipam(app)
    login_as(client, app, "admin@example.test")
    with app.app_context():
        before = build_snapshot()
    customer = pop = allocation = child = None
    try:
        assert client.post(
            "/customers/new",
            data={"name": "IPAM Customer", "cnpj": "04.252.011/0001-10", "contact_email": "noc@example.com", "active": "on"},
        ).status_code == 302
        assert client.post(
            "/pops-dcs/new",
            data={"name": "IPAM POP", "code": "IPAM-01", "latitude": "-25", "longitude": "-49", "active": "on"},
        ).status_code == 302
        with app.app_context():
            customer = IpamCustomer.query.filter_by(name="IPAM Customer").one()
            pop = IpamPop.query.filter_by(code="IPAM-01").one()
            from geofeed_admin.models import Company
            company_id = Company.query.filter_by(name="Example ISP").one().id
            router = IpamEquipment(name="IPAM Router", code="RTR-IPAM-01", equipment_type="router", pop_id=pop.id, active=True)
            db.session.add(router)
            db.session.commit()
            router_id = router.id
            customer_id = customer.id
            pop_id = pop.id
        assert client.post(
            "/ipam/allocations/new",
            data={
                "resource_kind": "block",
                "prefix": "10.99.0.0/24",
                "scope": "private",
                "status": "allocated",
                "company_id": str(company_id),
                "allocation_address": "Rua IPAM, 1",
                "latitude": "-25",
                "longitude": "-49",
                "customer_id": str(customer_id),
                "pop_id": str(pop_id),
                "router_id": str(router_id),
            },
        ).status_code == 302
        with app.app_context():
            allocation = IpamAllocation.query.filter_by(prefix="10.99.0.0/24").one()
            assert allocation.customer.name == "IPAM Customer"
            assert allocation.scope == "private"
            assert allocation.pop.battery_autonomy == "Não possui autonomia"
            assert build_snapshot() == before
        assert client.post(
            "/ipam/allocations/new",
            data={
                "resource_kind": "block", "prefix": "10.99.0.0/25", "status": "available",
                "parent_id": str(allocation.id), "company_id": str(company_id),
            },
        ).status_code == 302
        with app.app_context():
            child = IpamAllocation.query.filter_by(prefix="10.99.0.0/25").one()
        overlap = client.post(
            "/ipam/allocations/new",
            data={"resource_kind": "block", "prefix": "10.99.0.0/25", "status": "available", "parent_id": str(allocation.id), "company_id": str(company_id)},
        )
        assert overlap.status_code == 200
        assert "se sobrepõe" in overlap.get_data(as_text=True)
    finally:
        with app.app_context():
            if child:
                db.session.delete(db.session.get(IpamAllocation, child.id))
            if allocation:
                db.session.delete(db.session.get(IpamAllocation, allocation.id))
            if customer:
                AuditLog.query.filter_by(entity_id=str(customer_id)).delete(synchronize_session=False)
                db.session.delete(db.session.get(IpamCustomer, customer_id))
            if pop:
                AuditLog.query.filter_by(entity_id=str(pop_id)).delete(synchronize_session=False)
                db.session.delete(db.session.get(IpamPop, pop_id))
            db.session.commit()


def test_customer_service_picker_persists_each_service_status(client, app):
    login_as(client, app, "admin@example.test")
    with app.app_context():
        service = ServiceCatalogItem.query.filter_by(name="Link IP 50 Mb/s").one()

    form = client.get("/customers/new")
    assert form.status_code == 200
    assert "data-no-selected-services" in form.get_data(as_text=True)

    response = client.post(
        "/customers/new",
        data={
            "name": "Status Customer",
            "cnpj": "04.252.011/0001-10",
            "service_ids": str(service.id),
            f"service_status_{service.id}": "suspended",
            "active": "on",
        },
    )
    assert response.status_code == 302
    with app.app_context():
        customer = IpamCustomer.query.filter_by(name="Status Customer").one()
        status = db.session.execute(
            customer_service_items.select().where(
                customer_service_items.c.customer_id == customer.id,
                customer_service_items.c.service_id == service.id,
            )
        ).mappings().one_or_none()
        assert status is not None
        assert status["status"] == "suspended"
        AuditLog.query.filter_by(entity_id=str(customer.id)).delete(synchronize_session=False)
        db.session.delete(customer)
        db.session.commit()


def test_public_ipam_resource_waits_for_independent_approval(client, app):
    login_as(client, app, "editor@example.test")
    with app.app_context():
        from geofeed_admin.models import Company

        company_id = Company.query.filter_by(name="Example ISP").one().id
    response = client.post(
        "/ipam/allocations/new",
        data={
            "resource_kind": "block",
            "prefix": "9.9.9.0/24",
            "status": "available",
            "company_id": str(company_id),
            "notes": "Solicito validação do bloco público com o registro de alocação.",
        },
    )
    assert response.status_code == 302
    with app.app_context():
        allocation = IpamAllocation.query.filter_by(prefix="9.9.9.0/24").one()
        approval = IpamApprovalRequest.query.filter_by(allocation_id=allocation.id).one()
        assert allocation.approval_status == "pending"
        approval_id = approval.id
        allocation_id = allocation.id

    login_as(client, app, "admin@example.test")
    response = client.post(
        f"/ipam/approvals/{approval_id}/approve",
        data={"review_notes": "Conferido pela equipe de infraestrutura."},
    )
    assert response.status_code == 302
    with app.app_context():
        allocation = db.session.get(IpamAllocation, allocation_id)
        approval = db.session.get(IpamApprovalRequest, approval_id)
        assert allocation.approval_status == "approved"
        assert approval.status == "approved"
        db.session.delete(allocation)
        db.session.commit()


def test_ipam_tree_uses_latest_geofeed_for_subnet_hierarchy(client, app):
    publish_ipam_fixture(app, [
        "168.90.48.0/29",
        "168.90.48.8/30",
        "168.90.48.12/32",
        "168.90.49.0/24",
    ])
    runner = app.test_cli_runner()
    assert runner.invoke(args=["import-geofeed-inventory"]).exit_code == 0
    grant_ipam(app)
    login_as(client, app, "admin@example.test")
    with app.app_context():
        owner = IpamAllocation.query.filter_by(prefix="168.90.48.0/22").one()
        owner_id = owner.id

    root_children = client.get(
        f"/ipam/tree/children?owner_id={owner_id}&parent_prefix=168.90.48.0/22"
    )
    assert root_children.status_code == 200
    root_html = root_children.get_data(as_text=True)
    assert "168.90.48.0/24" in root_html
    assert "168.90.51.0/24" in root_html

    subnet_children = client.get(
        f"/ipam/tree/children?owner_id={owner_id}&parent_prefix=168.90.48.0/24"
    )
    assert subnet_children.status_code == 200
    subnet_html = subnet_children.get_data(as_text=True)
    assert "168.90.48.0/29" in subnet_html
    assert "Agrupado /29" in subnet_html
    assert "168.90.48.8/30" in subnet_html
    assert "168.90.48.12" in subnet_html


def test_ipam_subnet_planner_skips_prefixes_from_latest_geofeed(client, app):
    publish_ipam_fixture(app, ["168.90.48.0/29", "168.90.48.16/30"])
    runner = app.test_cli_runner()
    assert runner.invoke(args=["import-geofeed-inventory"]).exit_code == 0
    grant_ipam(app)
    login_as(client, app, "admin@example.test")
    with app.app_context():
        owner_id = IpamAllocation.query.filter_by(prefix="168.90.48.0/22").one().id

    response = client.get(
        f"/ipam/subnet-suggestions?owner_id={owner_id}&parent_prefix=168.90.48.0/24&prefixlen=29"
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert "168.90.48.0/29" not in payload["suggestions"]
    assert payload["suggestions"][0] == "168.90.48.8/29"


def test_ipam_geocode_uses_same_origin_server_proxy(client, app, monkeypatch):
    grant_ipam(app)
    login_as(client, app, "admin@example.test")
    upstream = Mock()
    upstream.return_value.json.return_value = [
        {"lat": "-25.4284", "lon": "-49.2733", "display_name": "Curitiba, Paraná, Brasil"},
        {"lat": "999", "lon": "999", "display_name": "inválido"},
    ]
    monkeypatch.setattr(ipam_routes.requests, "get", upstream)

    response = client.get("/ipam/geocode?q=Rua%20XV%20de%20Novembro%2C%20Curitiba")

    assert response.status_code == 200
    assert response.get_json() == {
        "results": [{
            "lat": -25.4284,
            "lon": -49.2733,
            "display_name": "Curitiba, Paraná, Brasil",
        }],
    }
    upstream.assert_called_once()
    assert upstream.call_args.kwargs["headers"]["User-Agent"].startswith("Mozilla/5.0 (compatible; ISP Network Tools/1.0;")


def test_ipam_geocode_reports_upstream_failure_without_exposing_exception(client, app, monkeypatch):
    grant_ipam(app)
    login_as(client, app, "admin@example.test")
    monkeypatch.setattr(ipam_routes.requests, "get", Mock(side_effect=ipam_routes.requests.RequestException("offline")))

    response = client.get("/ipam/geocode?q=Curitiba")

    assert response.status_code == 502
    assert response.get_json()["error"] == "O serviço de localização está indisponível no momento."


def test_location_picker_is_available_on_all_address_forms_and_persists_coordinates(client, app, monkeypatch):
    login_as(client, app, "admin@example.test")
    for path in ("/companies/new", "/customers/new", "/pops-dcs/new"):
        response = client.get(path)
        assert response.status_code == 200
        assert "data-location-picker-trigger" in response.get_data(as_text=True)

    upstream = Mock()
    upstream.return_value.json.return_value = [{"lat": "-25.4", "lon": "-49.2", "display_name": "Curitiba"}]
    monkeypatch.setattr(ipam_routes.requests, "get", upstream)
    response = client.get("/geocode?q=Curitiba")
    assert response.status_code == 200
    assert response.get_json()["results"][0]["lat"] == -25.4

    assert client.post(
        "/companies/new",
        data={
            "name": "Mapped ISP",
            "cnpj": "04.252.011/0001-10",
            "default_asn": "265264",
            "address": "Rua Mapeada, 1",
            "latitude": "-25.4",
            "longitude": "-49.2",
            "active": "on",
        },
    ).status_code == 302
    assert client.post(
        "/customers/new",
        data={
            "name": "Mapped Customer",
            "cnpj": "04.252.011/0001-10",
            "address": "Rua Mapeada, 2",
            "latitude": "-25.41",
            "longitude": "-49.21",
            "active": "on",
        },
    ).status_code == 302
    with app.app_context():
        assert str(Company.query.filter_by(name="Mapped ISP").one().latitude) == "-25.4000000"
        assert str(IpamCustomer.query.filter_by(name="Mapped Customer").one().longitude) == "-49.2100000"


def test_ipam_rejects_unaligned_child_with_canonical_suggestion(client, app):
    grant_ipam(app)
    login_as(client, app, "admin@example.test")
    with app.app_context():
        company_id = Company.query.filter_by(name="Example ISP").one().id
        parent = IpamAllocation(
            resource_kind="block", prefix="10.40.0.0/24", scope="private",
            status="available", approval_status="approved", company_id=company_id,
        )
        db.session.add(parent)
        db.session.commit()
        parent_id = parent.id

    response = client.post("/ipam/allocations/new", data={
        "resource_kind": "block",
        "prefix": "10.40.0.3/29",
        "status": "available",
        "parent_id": str(parent_id),
        "company_id": str(company_id),
    })
    assert response.status_code == 200
    assert "Use 10.40.0.0/29" in response.get_data(as_text=True)


def test_ipam_rejects_ipv4_32_directly_under_broad_parent(client, app):
    grant_ipam(app)
    login_as(client, app, "admin@example.test")
    with app.app_context():
        company_id = Company.query.filter_by(name="Example ISP").one().id
        parent = IpamAllocation(
            resource_kind="block", prefix="10.41.0.0/22", scope="private",
            status="available", approval_status="approved", company_id=company_id,
        )
        db.session.add(parent)
        db.session.commit()
        parent_id = parent.id

    response = client.post("/ipam/allocations/new", data={
        "resource_kind": "ip", "prefix": "10.41.0.1", "status": "available",
        "parent_id": str(parent_id), "company_id": str(company_id),
    })
    assert response.status_code == 200
    assert "deve ter como pai um /24" in response.get_data(as_text=True)


def test_ipam_can_group_existing_individual_addresses(client, app):
    grant_ipam(app)
    login_as(client, app, "admin@example.test")
    with app.app_context():
        company_id = Company.query.filter_by(name="Example ISP").one().id
        parent = IpamAllocation(
            resource_kind="block", prefix="10.50.0.0/24", scope="private",
            status="available", approval_status="approved", company_id=company_id,
        )
        db.session.add(parent)
        db.session.flush()
        db.session.add(IpamAllocation(
            resource_kind="ip", prefix="10.50.0.1", scope="private",
            status="allocated", approval_status="approved", company_id=company_id,
            parent_id=parent.id, parent_prefix=parent.prefix,
        ))
        db.session.commit()
        parent_id = parent.id

    response = client.post("/ipam/allocations/new", data={
        "resource_kind": "block", "prefix": "10.50.0.0/29", "status": "allocated",
        "parent_id": str(parent_id), "company_id": str(company_id),
    })
    assert response.status_code == 302
    with app.app_context():
        assert IpamAllocation.query.filter_by(prefix="10.50.0.0/29").one()


def test_ipam_supports_child_32_with_inherited_operational_links_and_open_location(client, app):
    grant_ipam(app)
    login_as(client, app, "admin@example.test")
    with app.app_context():
        company_id = Company.query.filter_by(name="Example ISP").one().id
        customer = IpamCustomer(name="Cliente herdado", cnpj="04.252.011/0001-10", active=True)
        pop = IpamPop(name="POP herdado", code="POP-HERDADO", active=True)
        router = IpamEquipment(name="Roteador pai", code="RTR-PAI", equipment_type="router", active=True)
        cpe = IpamEquipment(name="CPE pai", code="CPE-PAI", equipment_type="cpe", active=True)
        db.session.add_all([customer, pop, router, cpe])
        db.session.flush()
        parent = IpamAllocation(
            resource_kind="block", prefix="10.60.0.0/30", scope="private",
            status="allocated", approval_status="approved", company_id=company_id,
            allocation_address="Rua do POP, 100", latitude="-25.4000000", longitude="-49.2000000",
            vlan="600", vrf="CLIENTES", customer_id=customer.id, pop_id=pop.id,
            router_id=router.id, cpe_id=cpe.id,
        )
        db.session.add(parent)
        db.session.commit()
        parent_id = parent.id

    response = client.post("/ipam/allocations/new", data={
        "resource_kind": "block", "prefix": "10.60.0.1/32", "status": "allocated",
        "parent_id": str(parent_id), "company_id": str(company_id),
        "allocation_address": "tentativa de sobrescrever",
    })
    assert response.status_code == 302
    with app.app_context():
        child = IpamAllocation.query.filter_by(prefix="10.60.0.1/32").one()
        assert child.resource_kind == "block"
        assert child.allocation_address == "tentativa de sobrescrever"
        assert child.customer.name == "Cliente herdado"
        assert child.pop.code == "POP-HERDADO"
        assert child.router.code == "RTR-PAI"
        assert child.cpe.code == "CPE-PAI"
        child_id = child.id

    form = client.get(f"/ipam/allocations/{child_id}/edit")
    html = form.get_data(as_text=True)
    assert form.status_code == 200
    assert "Herdado de 10.60.0.0/30" in html
    assert 'name="company_id"' in html and 'name="company_id" required' in html
    assert 'name="company_id" required disabled' in html
    assert 'name="customer_id" disabled' in html
    assert 'name="pop_id" disabled' in html
    assert 'name="router_id" disabled' in html
    assert 'name="cpe_id" disabled' in html
    assert 'value="tentativa de sobrescrever"' in html
    assert 'name="latitude"' in html and 'name="latitude" value=""' in html
    assert 'name="longitude"' in html and 'name="longitude" value=""' in html
    assert 'value="600"' in html
    assert "Resumo e destino das informações" in html
    assert "nunca são incluídos nos arquivos públicos" in html


def test_ipam_second_approach_requires_scoped_equipment_and_radio_links(client, app):
    grant_ipam(app)
    login_as(client, app, "admin@example.test")
    with app.app_context():
        company_id = Company.query.filter_by(name="Example ISP").one().id
        second_service = ServiceCatalogItem.query.filter_by(
            name="Link IP 100 Mb/s · Segunda abordagem"
        ).one()
        customer = IpamCustomer(name="Cliente dual", cnpj="04.252.011/0001-10", active=True)
        customer.services = [second_service]
        pop_one = IpamPop(name="POP dual 1", code="POP-DUAL-1", active=True)
        pop_two = IpamPop(name="POP dual 2", code="POP-DUAL-2", active=True)
        db.session.add_all([customer, pop_one, pop_two])
        db.session.flush()
        router_one = IpamEquipment(name="Router dual 1", code="RTR-DUAL-1", equipment_type="router", pop_id=pop_one.id, active=True)
        router_two = IpamEquipment(name="Router dual 2", code="RTR-DUAL-2", equipment_type="router", pop_id=pop_two.id, active=True)
        cpe = IpamEquipment(name="CPE dual", code="CPE-DUAL", equipment_type="cpe", customer_id=customer.id, pop_id=pop_one.id, secondary_pop_id=pop_two.id, router_id=router_one.id, secondary_router_id=router_two.id, active=True)
        db.session.add_all([router_one, router_two, cpe])
        db.session.flush()
        ap = IpamEquipment(name="AP dual", code="AP-DUAL", equipment_type="radio_ap", pop_id=pop_two.id, customer_id=customer.id, active=True)
        db.session.add(ap)
        db.session.flush()
        st = IpamEquipment(name="ST dual", code="ST-DUAL", equipment_type="radio_st", pop_id=pop_two.id, customer_id=customer.id, cpe_id=cpe.id, access_point_id=ap.id, active=True)
        db.session.add(st)
        db.session.commit()
        ids = {"customer": customer.id, "pop_one": pop_one.id, "pop_two": pop_two.id, "router_one": router_one.id, "router_two": router_two.id, "cpe": cpe.id, "ap": ap.id, "st": st.id}

    missing_second = client.post("/ipam/allocations/new", data={
        "resource_kind": "block", "prefix": "10.200.0.0/24", "status": "allocated",
        "company_id": str(company_id), "customer_id": str(ids["customer"]),
        "pop_id": str(ids["pop_one"]), "router_id": str(ids["router_one"]),
        "access_type": "fiber", "access_type_2": "fiber",
    })
    assert missing_second.status_code == 200
    assert "segundo POP/DC" in missing_second.get_data(as_text=True)

    created = client.post("/ipam/allocations/new", data={
        "resource_kind": "block", "prefix": "10.200.0.0/24", "status": "allocated",
        "company_id": str(company_id), "customer_id": str(ids["customer"]),
        "pop_id": str(ids["pop_one"]), "router_id": str(ids["router_one"]),
        "access_type": "fiber", "access_type_2": "radio",
        "pop_2_id": str(ids["pop_two"]), "router_2_id": str(ids["router_two"]),
        "cpe_id": str(ids["cpe"]), "access_point_2_id": str(ids["ap"]),
        "st_2_id": str(ids["st"]),
    })
    assert created.status_code == 302
    with app.app_context():
        allocation = IpamAllocation.query.filter_by(prefix="10.200.0.0/24").one()
        assert allocation.pop_2_id == ids["pop_two"]
        assert allocation.router_2_id == ids["router_two"]
        assert allocation.access_type_2 == "radio"
        assert allocation.access_point_2_id == ids["ap"]
        assert allocation.st_2_id == ids["st"]
