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
    role = db.Column(db.String(16), nullable=False, default="editor")
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
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    groups = db.relationship("Group", secondary=user_group_members, back_populates="users")
    application_grants = db.relationship(
        "UserApplicationGrant", back_populates="user", cascade="all, delete-orphan"
    )

    def can_edit(self) -> bool:
        return self.active and (self.is_admin() or self.role == "editor" or self.has_permission("content.edit"))

    def is_admin(self) -> bool:
        return self.active and (self.role in {"super_admin", "admin"} or self.has_permission("admin.access"))

    def is_super_admin(self) -> bool:
        return self.active and self.role == "super_admin"

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
        """Evaluate an application entitlement independently from portal roles."""
        if not self.active or self.deleted_at is not None:
            return False
        application = Application.query.filter_by(code=application_code, active=True).first()
        if not application:
            return False
        if application.public or application.code == "admin_center" or self.is_super_admin():
            return True
        direct = UserApplicationGrant.query.filter_by(
            user_id=self.id, application_id=application.id
        ).first()
        if direct:
            return direct.allowed
        return any(
            grant.allowed
            for group in self.groups
            for grant in group.application_grants
            if grant.application_id == application.id and group.active
        )


class Role(TimestampMixin, db.Model):
    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(255), nullable=False, default="")
    permissions = db.Column(db.Text, nullable=False, default="[]")
    system = db.Column(db.Boolean, nullable=False, default=False)
    active = db.Column(db.Boolean, nullable=False, default=True)


class Group(TimestampMixin, db.Model):
    __tablename__ = "groups"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False, index=True)
    description = db.Column(db.String(255), nullable=False, default="")
    active = db.Column(db.Boolean, nullable=False, default=True)
    users = db.relationship("User", secondary=user_group_members, back_populates="groups")
    application_grants = db.relationship(
        "GroupApplicationGrant", back_populates="group", cascade="all, delete-orphan"
    )


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
    user_grants = db.relationship(
        "UserApplicationGrant", back_populates="application", cascade="all, delete-orphan"
    )
    group_grants = db.relationship(
        "GroupApplicationGrant", back_populates="application", cascade="all, delete-orphan"
    )


class UserApplicationGrant(TimestampMixin, db.Model):
    __tablename__ = "user_application_grants"
    __table_args__ = (
        db.UniqueConstraint("user_id", "application_id", name="uq_user_application_grant"),
    )

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    application_id = db.Column(db.Integer, db.ForeignKey("applications.id", ondelete="CASCADE"), nullable=False, index=True)
    allowed = db.Column(db.Boolean, nullable=False, default=True)
    user = db.relationship("User", back_populates="application_grants")
    application = db.relationship("Application", back_populates="user_grants")


class GroupApplicationGrant(TimestampMixin, db.Model):
    __tablename__ = "group_application_grants"
    __table_args__ = (
        db.UniqueConstraint("group_id", "application_id", name="uq_group_application_grant"),
    )

    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey("groups.id", ondelete="CASCADE"), nullable=False, index=True)
    application_id = db.Column(db.Integer, db.ForeignKey("applications.id", ondelete="CASCADE"), nullable=False, index=True)
    allowed = db.Column(db.Boolean, nullable=False, default=True)
    group = db.relationship("Group", back_populates="application_grants")
    application = db.relationship("Application", back_populates="group_grants")


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
