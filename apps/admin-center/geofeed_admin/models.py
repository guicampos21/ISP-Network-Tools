from __future__ import annotations

import json
from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


user_group_members = db.Table(
    "user_group_members",
    db.Column("user_id", db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    db.Column("group_id", db.Integer, db.ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True),
    db.UniqueConstraint("user_id", name="uq_user_group_members_user"),
)


class TimestampMixin:
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class User(TimestampMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    username = db.Column(db.String(80), unique=True, nullable=True, index=True)
    display_name = db.Column(db.String(160), nullable=False, default="")
    first_name = db.Column(db.String(80), nullable=False, default="")
    last_name = db.Column(db.String(80), nullable=False, default="")
    nickname = db.Column(db.String(80), nullable=False, default="")
    department = db.Column(db.String(120), nullable=False, default="")
    job_title = db.Column(db.String(120), nullable=False, default="")
    auth_provider = db.Column(db.String(16), nullable=False, default="m365")
    entra_oid = db.Column(db.String(64), unique=True, nullable=True, index=True)
    google_sub = db.Column(db.String(128), unique=True, nullable=True, index=True)
    tenant_id = db.Column(db.String(64), nullable=True)
    role = db.Column(db.String(16), nullable=False, default="ipam_operator")
    password_hash = db.Column(db.String(255), nullable=True)
    password_change_required = db.Column(db.Boolean, nullable=False, default=False)
    totp_secret = db.Column(db.String(64), nullable=True)
    totp_enabled = db.Column(db.Boolean, nullable=False, default=False)
    totp_grace_until = db.Column(db.DateTime(timezone=True), nullable=True)
    recovery_codes = db.Column(db.Text, nullable=False, default="")
    avatar_kind = db.Column(db.String(32), nullable=False, default="initials")
    avatar_path = db.Column(db.String(255), nullable=False, default="")
    avatar_config = db.Column(db.Text, nullable=False, default="{}")
    active = db.Column(db.Boolean, nullable=False, default=True)
    deleted_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)
    deleted_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    last_login_at = db.Column(db.DateTime(timezone=True), nullable=True)
    last_seen_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    groups = db.relationship("Group", secondary=user_group_members, back_populates="users")

    def can_edit(self) -> bool:
        return self.active and self.has_permission("content.edit")

    def is_admin(self) -> bool:
        return self.active and (self.role in {"super_admin", "admin"} or self.has_permission("admin.access"))

    def is_super_admin(self) -> bool:
        return self.active and self.role == "super_admin"

    @property
    def profile(self):
        return Role.query.filter_by(code=self.role, active=True).first()

    def has_permission(self, permission: str) -> bool:
        if not self.active:
            return False
        if self.role == "super_admin":
            return True
        role = Role.query.filter_by(code=self.role, active=True).first()
        if not role:
            return False
        try:
            permissions = json.loads(role.permissions or "[]")
        except json.JSONDecodeError:
            permissions = []
        return "*" in permissions or permission in permissions

    def has_application_access(self, application_code: str) -> bool:
        """Evaluate application access using only the user's profile."""
        if not self.active or self.deleted_at is not None:
            return False
        application = Application.query.filter_by(code=application_code, active=True).first()
        if not application:
            return False
        if application.public:
            return True
        return self.has_permission(f"app.{application_code}.access")


class Role(TimestampMixin, db.Model):
    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(255), nullable=False, default="")
    permissions = db.Column(db.Text, nullable=False, default="[]")
    system = db.Column(db.Boolean, nullable=False, default=False)
    active = db.Column(db.Boolean, nullable=False, default=True)


# The database keeps the legacy table name during the staged migration. The
# domain term exposed by the application is Profile/Perfil.
Profile = Role


class Group(TimestampMixin, db.Model):
    __tablename__ = "groups"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False, index=True)
    description = db.Column(db.String(255), nullable=False, default="")
    active = db.Column(db.Boolean, nullable=False, default=True)
    users = db.relationship("User", secondary=user_group_members, back_populates="groups")


class Application(TimestampMixin, db.Model):
    __tablename__ = "applications"

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.String(255), nullable=False, default="")
    url = db.Column(db.String(512), nullable=False, default="")
    public = db.Column(db.Boolean, nullable=False, default=False)
    active = db.Column(db.Boolean, nullable=False, default=True)
    sort_order = db.Column(db.Integer, nullable=False, default=0)


class Sector(TimestampMixin, db.Model):
    __tablename__ = "sectors"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=True)


class JobFunction(TimestampMixin, db.Model):
    __tablename__ = "job_functions"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=True)


class SessionToken(db.Model):
    __tablename__ = "session_tokens"

    id = db.Column(db.Integer, primary_key=True)
    token_digest = db.Column(db.String(64), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    last_used_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=True)
    user_agent = db.Column(db.String(512), nullable=False, default="")
    user = db.relationship("User", backref=db.backref("session_tokens", cascade="all, delete-orphan"))


class PortalSetting(TimestampMixin, db.Model):
    __tablename__ = "portal_settings"

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(120), unique=True, nullable=False, index=True)
    value = db.Column(db.Text, nullable=False, default="")
    is_secret = db.Column(db.Boolean, nullable=False, default=False)
    changed_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    changed_by = db.relationship("User", foreign_keys=[changed_by_id])


class PortalTheme(TimestampMixin, db.Model):
    __tablename__ = "portal_themes"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    config = db.Column(db.Text, nullable=False, default="{}")
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    created_by = db.relationship("User", foreign_keys=[created_by_id])


class Company(TimestampMixin, db.Model):
    __tablename__ = "companies"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    cnpj = db.Column(db.String(18), nullable=False, default="", index=True)
    address = db.Column(db.String(255), nullable=False, default="")
    latitude = db.Column(db.Numeric(10, 7), nullable=True)
    longitude = db.Column(db.Numeric(10, 7), nullable=True)
    contact_phone = db.Column(db.String(64), nullable=False, default="")
    default_asn = db.Column(db.Integer, nullable=False)
    contact_email = db.Column(db.String(254), nullable=False, default="")
    active = db.Column(db.Boolean, nullable=False, default=True)
    blocks = db.relationship(
        "NetworkBlock", back_populates="company", cascade="all, delete-orphan"
    )


class NetworkBlock(TimestampMixin, db.Model):
    __tablename__ = "network_blocks"

    id = db.Column(db.Integer, primary_key=True)
    cidr = db.Column(db.String(64), unique=True, nullable=False, index=True)
    ip_version = db.Column(db.Integer, nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey("companies.id"), nullable=False)
    asn = db.Column(db.Integer, nullable=False)
    filename = db.Column(db.String(128), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=False, default="")
    active = db.Column(db.Boolean, nullable=False, default=True)
    company = db.relationship("Company", back_populates="blocks")
    entries = db.relationship(
        "FeedEntry",
        back_populates="block",
        cascade="all, delete-orphan",
        order_by="FeedEntry.sort_order, FeedEntry.id",
    )


class FeedEntry(TimestampMixin, db.Model):
    __tablename__ = "feed_entries"
    __table_args__ = (
        db.UniqueConstraint("block_id", "prefix", name="uq_entry_block_prefix"),
    )

    id = db.Column(db.Integer, primary_key=True)
    block_id = db.Column(
        db.Integer, db.ForeignKey("network_blocks.id"), nullable=False, index=True
    )
    prefix = db.Column(db.String(64), nullable=False)
    alpha2code = db.Column(db.String(2), nullable=False, default="BR")
    region = db.Column(db.String(16), nullable=False, default="BR-PR")
    city = db.Column(db.String(160), nullable=False, default="")
    postal_code = db.Column(db.String(32), nullable=False, default="")
    sort_order = db.Column(db.Integer, nullable=False, default=0)
    block = db.relationship("NetworkBlock", back_populates="entries")


class Customer(TimestampMixin, db.Model):
    """Master customer registry consumed by IPAM and other applications.

    This registry is deliberately separate from the Geofeed snapshot. Customer
    and commercial data are operational metadata and must never leak into the
    public five-column RFC 8805 feed.
    """

    __tablename__ = "customers"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False, index=True)
    cnpj = db.Column(db.String(18), nullable=False, default="", index=True)
    # Kept for compatibility with the first IPAM migration. New forms use cnpj.
    document = db.Column(db.String(64), nullable=False, default="")
    address = db.Column(db.String(255), nullable=False, default="")
    city = db.Column(db.String(120), nullable=False, default="")
    state = db.Column(db.String(80), nullable=False, default="")
    postal_code = db.Column(db.String(32), nullable=False, default="")
    latitude = db.Column(db.Numeric(10, 7), nullable=True)
    longitude = db.Column(db.Numeric(10, 7), nullable=True)
    contact_name = db.Column(db.String(160), nullable=False, default="")
    contact_email = db.Column(db.String(254), nullable=False, default="")
    contact_phone = db.Column(db.String(64), nullable=False, default="")
    # Kept for compatibility with existing installations. New assignments use
    # customer_service_items and never expose these legacy text fields.
    contracted_bandwidth = db.Column(db.String(120), nullable=False, default="")
    contracted_services = db.Column(db.Text, nullable=False, default="")
    notes = db.Column(db.Text, nullable=False, default="")
    active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    allocations = db.relationship("IpamAllocation", back_populates="customer")
    services = db.relationship(
        "ServiceCatalogItem",
        secondary="customer_service_items",
        back_populates="customers",
        order_by="ServiceCatalogItem.name",
    )


customer_service_items = db.Table(
    "customer_service_items",
    db.Column("customer_id", db.Integer, db.ForeignKey("customers.id", ondelete="CASCADE"), primary_key=True),
    db.Column("service_id", db.Integer, db.ForeignKey("service_catalog_items.id", ondelete="RESTRICT"), primary_key=True),
    db.Column("status", db.String(16), nullable=False, default="active"),
)


class ServiceCatalogItem(TimestampMixin, db.Model):
    """A selectable service/product offered by the ISP."""

    __tablename__ = "service_catalog_items"

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(80), unique=True, nullable=False, index=True)
    name = db.Column(db.String(180), unique=True, nullable=False, index=True)
    service_type = db.Column(db.String(80), nullable=False, default="Serviço")
    specification = db.Column(db.String(120), nullable=False, default="")
    description = db.Column(db.String(255), nullable=False, default="")
    active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    customers = db.relationship(
        "Customer",
        secondary=customer_service_items,
        back_populates="services",
    )


class PopDc(TimestampMixin, db.Model):
    """Master point-of-presence and data-center registry."""

    __tablename__ = "pops_dcs"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False, index=True)
    code = db.Column(db.String(64), nullable=False, unique=True, index=True)
    address = db.Column(db.String(255), nullable=False, default="")
    city = db.Column(db.String(120), nullable=False, default="")
    state = db.Column(db.String(80), nullable=False, default="")
    postal_code = db.Column(db.String(32), nullable=False, default="")
    latitude = db.Column(db.Numeric(10, 7), nullable=True)
    longitude = db.Column(db.Numeric(10, 7), nullable=True)
    contact_name = db.Column(db.String(160), nullable=False, default="")
    contact_email = db.Column(db.String(254), nullable=False, default="")
    contact_phone = db.Column(db.String(64), nullable=False, default="")
    # Legacy text columns remain readable for old records, while all new data
    # uses the structured weekly policy below.
    access_hours = db.Column(db.String(160), nullable=False, default="")
    battery_autonomy = db.Column(db.String(120), nullable=False, default="")
    access_24h = db.Column(db.Boolean, nullable=False, default=False, index=True)
    battery_autonomy_minutes = db.Column(db.Integer, nullable=False, default=0)
    primary_edge_router_id = db.Column(
        db.Integer, db.ForeignKey("ipam_equipments.id", ondelete="SET NULL"), nullable=True, index=True
    )
    notes = db.Column(db.Text, nullable=False, default="")
    active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    primary_edge_router = db.relationship(
        "IpamEquipment", foreign_keys=[primary_edge_router_id], post_update=True
    )
    allocations = db.relationship(
        "IpamAllocation", foreign_keys="IpamAllocation.pop_id", back_populates="pop"
    )
    access_windows = db.relationship(
        "PopAccessWindow",
        back_populates="pop",
        cascade="all, delete-orphan",
        order_by="PopAccessWindow.id",
    )


class PopAccessWindow(TimestampMixin, db.Model):
    """Recurring weekly physical access window for a POP/DC."""

    __tablename__ = "pop_access_windows"

    id = db.Column(db.Integer, primary_key=True)
    pop_id = db.Column(db.Integer, db.ForeignKey("pops_dcs.id", ondelete="CASCADE"), nullable=False, index=True)
    weekdays = db.Column(db.String(32), nullable=False, default="")
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    pop = db.relationship("PopDc", back_populates="access_windows")


class IpamEquipment(TimestampMixin, db.Model):
    """Operational equipment that can host an IPAM allocation."""

    __tablename__ = "ipam_equipments"

    id = db.Column(db.Integer, primary_key=True)
    equipment_type = db.Column(db.String(16), nullable=False, default="other", index=True)
    name = db.Column(db.String(160), nullable=False, index=True)
    code = db.Column(db.String(80), nullable=False, unique=True, index=True)
    pop_id = db.Column(
        db.Integer, db.ForeignKey("pops_dcs.id", ondelete="SET NULL"), nullable=True, index=True
    )
    secondary_pop_id = db.Column(
        db.Integer, db.ForeignKey("pops_dcs.id", ondelete="SET NULL"), nullable=True, index=True
    )
    customer_id = db.Column(
        db.Integer, db.ForeignKey("customers.id", ondelete="SET NULL"), nullable=True, index=True
    )
    router_id = db.Column(
        db.Integer, db.ForeignKey("ipam_equipments.id", ondelete="SET NULL"), nullable=True, index=True
    )
    secondary_router_id = db.Column(
        db.Integer, db.ForeignKey("ipam_equipments.id", ondelete="SET NULL"), nullable=True, index=True
    )
    cpe_id = db.Column(
        db.Integer, db.ForeignKey("ipam_equipments.id", ondelete="SET NULL"), nullable=True, index=True
    )
    access_point_id = db.Column(
        db.Integer, db.ForeignKey("ipam_equipments.id", ondelete="SET NULL"), nullable=True, index=True
    )
    vendor = db.Column(db.String(120), nullable=False, default="")
    model = db.Column(db.String(120), nullable=False, default="")
    serial_number = db.Column(db.String(120), nullable=False, default="")
    location = db.Column(db.String(255), nullable=False, default="")
    notes = db.Column(db.Text, nullable=False, default="")
    active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    pop = db.relationship("PopDc", foreign_keys=[pop_id])
    secondary_pop = db.relationship("PopDc", foreign_keys=[secondary_pop_id])
    customer = db.relationship("Customer", foreign_keys=[customer_id])
    linked_router = db.relationship("IpamEquipment", foreign_keys=[router_id], remote_side=[id])
    linked_secondary_router = db.relationship("IpamEquipment", foreign_keys=[secondary_router_id], remote_side=[id])
    linked_cpe = db.relationship("IpamEquipment", foreign_keys=[cpe_id], remote_side=[id])
    linked_access_point = db.relationship("IpamEquipment", foreign_keys=[access_point_id], remote_side=[id])
    allocations = db.relationship(
        "IpamAllocation", foreign_keys="IpamAllocation.equipment_id", back_populates="equipment"
    )
    router_allocations = db.relationship(
        "IpamAllocation", foreign_keys="IpamAllocation.router_id", back_populates="router"
    )
    cpe_allocations = db.relationship(
        "IpamAllocation", foreign_keys="IpamAllocation.cpe_id", back_populates="cpe"
    )


class IpamAllocation(TimestampMixin, db.Model):
    """IPAM inventory record for a block or an individual address."""

    __tablename__ = "ipam_allocations"
    __table_args__ = (
        db.UniqueConstraint("resource_kind", "prefix", name="uq_ipam_resource_prefix"),
    )

    id = db.Column(db.Integer, primary_key=True)
    resource_kind = db.Column(db.String(16), nullable=False, default="block")
    prefix = db.Column(db.String(64), nullable=False, index=True)
    scope = db.Column(db.String(16), nullable=False, default="public", index=True)
    status = db.Column(db.String(24), nullable=False, default="available", index=True)
    # Public resources can be visible in the inventory while their requested
    # change is pending, but they are not considered approved for operation or
    # dashboard availability until a reviewer accepts it.
    approval_status = db.Column(db.String(16), nullable=False, default="approved", index=True)
    parent_prefix = db.Column(db.String(64), nullable=False, default="")
    parent_id = db.Column(
        db.Integer,
        db.ForeignKey("ipam_allocations.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    company_id = db.Column(
        db.Integer,
        db.ForeignKey("companies.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    # Public Geofeed data is summarized by Brazilian state/region only. The
    # city and exact address remain operational data and are never inherited
    # from a parent allocation.
    geofeed_region = db.Column(db.String(16), nullable=False, default="", index=True)
    allocation_address = db.Column(db.String(255), nullable=False, default="")
    latitude = db.Column(db.Numeric(10, 7), nullable=True)
    longitude = db.Column(db.Numeric(10, 7), nullable=True)
    vlan = db.Column(db.String(64), nullable=False, default="")
    vrf = db.Column(db.String(80), nullable=False, default="")
    description = db.Column(db.String(255), nullable=False, default="")
    notes = db.Column(db.Text, nullable=False, default="")
    metadata_incomplete = db.Column(db.Boolean, nullable=False, default=False, index=True)
    metadata_warning = db.Column(db.String(255), nullable=False, default="")
    source_block_id = db.Column(
        db.Integer, db.ForeignKey("network_blocks.id", ondelete="SET NULL"), nullable=True, index=True
    )
    customer_id = db.Column(
        db.Integer, db.ForeignKey("customers.id", ondelete="SET NULL"), nullable=True, index=True
    )
    pop_id = db.Column(
        db.Integer, db.ForeignKey("pops_dcs.id", ondelete="SET NULL"), nullable=True, index=True
    )
    equipment_id = db.Column(
        db.Integer, db.ForeignKey("ipam_equipments.id", ondelete="SET NULL"), nullable=True, index=True
    )
    router_id = db.Column(
        db.Integer, db.ForeignKey("ipam_equipments.id", ondelete="SET NULL"), nullable=True, index=True
    )
    cpe_id = db.Column(
        db.Integer, db.ForeignKey("ipam_equipments.id", ondelete="SET NULL"), nullable=True, index=True
    )
    access_type = db.Column(db.String(16), nullable=False, default="fiber")
    access_type_2 = db.Column(db.String(16), nullable=False, default="fiber")
    pop_2_id = db.Column(
        db.Integer, db.ForeignKey("pops_dcs.id", ondelete="SET NULL"), nullable=True, index=True
    )
    router_2_id = db.Column(
        db.Integer, db.ForeignKey("ipam_equipments.id", ondelete="SET NULL"), nullable=True, index=True
    )
    switch_id = db.Column(
        db.Integer, db.ForeignKey("ipam_equipments.id", ondelete="SET NULL"), nullable=True, index=True
    )
    switch_2_id = db.Column(
        db.Integer, db.ForeignKey("ipam_equipments.id", ondelete="SET NULL"), nullable=True, index=True
    )
    access_point_id = db.Column(
        db.Integer, db.ForeignKey("ipam_equipments.id", ondelete="SET NULL"), nullable=True, index=True
    )
    access_point_2_id = db.Column(
        db.Integer, db.ForeignKey("ipam_equipments.id", ondelete="SET NULL"), nullable=True, index=True
    )
    st_id = db.Column(
        db.Integer, db.ForeignKey("ipam_equipments.id", ondelete="SET NULL"), nullable=True, index=True
    )
    st_2_id = db.Column(
        db.Integer, db.ForeignKey("ipam_equipments.id", ondelete="SET NULL"), nullable=True, index=True
    )
    source_block = db.relationship("NetworkBlock", backref=db.backref("ipam_allocations", lazy=True))
    customer = db.relationship("Customer", back_populates="allocations")
    pop = db.relationship("PopDc", foreign_keys=[pop_id], back_populates="allocations")
    secondary_pop = db.relationship("PopDc", foreign_keys=[pop_2_id])
    equipment = db.relationship("IpamEquipment", foreign_keys=[equipment_id], back_populates="allocations")
    router = db.relationship("IpamEquipment", foreign_keys=[router_id], back_populates="router_allocations")
    secondary_router = db.relationship("IpamEquipment", foreign_keys=[router_2_id])
    switch = db.relationship("IpamEquipment", foreign_keys=[switch_id])
    secondary_switch = db.relationship("IpamEquipment", foreign_keys=[switch_2_id])
    access_point = db.relationship("IpamEquipment", foreign_keys=[access_point_id])
    secondary_access_point = db.relationship("IpamEquipment", foreign_keys=[access_point_2_id])
    radio_st = db.relationship("IpamEquipment", foreign_keys=[st_id])
    secondary_radio_st = db.relationship("IpamEquipment", foreign_keys=[st_2_id])
    cpe = db.relationship("IpamEquipment", foreign_keys=[cpe_id], back_populates="cpe_allocations")
    parent = db.relationship("IpamAllocation", remote_side=[id], back_populates="children")
    children = db.relationship("IpamAllocation", back_populates="parent")
    company = db.relationship("Company")
    approval_requests = db.relationship(
        "IpamApprovalRequest",
        back_populates="allocation",
        cascade="all, delete-orphan",
        order_by="IpamApprovalRequest.created_at.desc()",
    )


class IpamApprovalRequest(TimestampMixin, db.Model):
    """Approval record for changes to public IPAM resources."""

    __tablename__ = "ipam_approval_requests"

    id = db.Column(db.Integer, primary_key=True)
    allocation_id = db.Column(
        db.Integer,
        db.ForeignKey("ipam_allocations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    operation = db.Column(db.String(16), nullable=False, default="create")
    status = db.Column(db.String(16), nullable=False, default="pending", index=True)
    title = db.Column(db.String(180), nullable=False, default="")
    snapshot_json = db.Column(db.Text, nullable=False, default="{}")
    notes = db.Column(db.Text, nullable=False, default="")
    review_notes = db.Column(db.Text, nullable=False, default="")
    requested_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    reviewed_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    reviewed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    allocation = db.relationship("IpamAllocation", back_populates="approval_requests")
    requested_by = db.relationship("User", foreign_keys=[requested_by_id])
    reviewed_by = db.relationship("User", foreign_keys=[reviewed_by_id])


# Compatibility aliases keep integrations and old migrations readable while
# the canonical domain names are Customer and PopDc.
IpamCustomer = Customer
IpamPop = PopDc


class ChangeRequest(TimestampMixin, db.Model):
    __tablename__ = "change_requests"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(180), nullable=False)
    notes = db.Column(db.Text, nullable=False, default="")
    status = db.Column(db.String(24), nullable=False, default="pending", index=True)
    snapshot_json = db.Column(db.Text, nullable=False)
    snapshot_hash = db.Column(db.String(64), nullable=False)
    diff_text = db.Column(db.Text, nullable=False, default="")
    requested_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    reviewed_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    reviewed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    review_notes = db.Column(db.Text, nullable=False, default="")
    scheduled_for = db.Column(db.DateTime(timezone=True), nullable=True)
    requested_by = db.relationship("User", foreign_keys=[requested_by_id])
    reviewed_by = db.relationship("User", foreign_keys=[reviewed_by_id])


class Publication(TimestampMixin, db.Model):
    __tablename__ = "publications"

    id = db.Column(db.Integer, primary_key=True)
    version = db.Column(db.Integer, unique=True, nullable=False)
    snapshot_json = db.Column(db.Text, nullable=False)
    snapshot_hash = db.Column(db.String(64), nullable=False)
    summary = db.Column(db.String(255), nullable=False, default="")
    archive_path = db.Column(db.String(512), nullable=False, default="")
    published_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    change_request_id = db.Column(
        db.Integer, db.ForeignKey("change_requests.id"), nullable=True
    )
    published_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    published_by = db.relationship("User", foreign_keys=[published_by_id])
    change_request = db.relationship("ChangeRequest")


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    action = db.Column(db.String(80), nullable=False, index=True)
    entity_type = db.Column(db.String(80), nullable=False, default="")
    entity_id = db.Column(db.String(80), nullable=False, default="")
    details = db.Column(db.Text, nullable=False, default="")
    source_ip = db.Column(db.String(64), nullable=False, default="")
    user = db.relationship("User")


class HealthCheck(db.Model):
    __tablename__ = "health_checks"

    id = db.Column(db.Integer, primary_key=True)
    checked_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    target = db.Column(db.String(512), nullable=False)
    ok = db.Column(db.Boolean, nullable=False)
    http_status = db.Column(db.Integer, nullable=True)
    response_ms = db.Column(db.Integer, nullable=True)
    content_hash = db.Column(db.String(64), nullable=False, default="")
    details = db.Column(db.Text, nullable=False, default="")
    entry_count = db.Column(db.Integer, nullable=True)
    failure_streak = db.Column(db.Integer, nullable=False, default=0)
    incident_open = db.Column(db.Boolean, nullable=False, default=False)
    last_alert_at = db.Column(db.DateTime(timezone=True), nullable=True)


class NotificationLog(db.Model):
    __tablename__ = "notification_logs"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    recipient = db.Column(db.String(254), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(24), nullable=False)
    details = db.Column(db.Text, nullable=False, default="")


class InAppNotification(db.Model):
    __tablename__ = "in_app_notifications"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    title = db.Column(db.String(180), nullable=False)
    message = db.Column(db.String(2000), nullable=False, default="")
    link = db.Column(db.String(512), nullable=False, default="")
    read_at = db.Column(db.DateTime(timezone=True), nullable=True, index=True)
    user = db.relationship("User")
