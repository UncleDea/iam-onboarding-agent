"""The web app: a small, server-rendered interface over IAMService.

Standard library only (http.server + ThreadingHTTPServer), so it
runs anywhere Python 3.10+ runs with no installs:

    python run_app.py

Pages: login, dashboard, requests (submit/list/detail), approvals
(approve/reject on the detail page), access review, reports, audit
log, health, metrics.

Security, in proportion to a small internal app:

- Sessions are random server-side tokens in an HttpOnly cookie;
  the cookie holds no identity or roles.
- Every state-changing form carries a CSRF token tied to the session.
- All user-supplied values are HTML-escaped before rendering.
- The app binds 127.0.0.1 by default (IAM_APP_HOST to change it);
  put it behind TLS and a reverse proxy before exposing it beyond
  one machine.
- Approvals enforce the service rules: approver/admin role only,
  and never your own request.
"""

import html
import json
import os
import re
import secrets
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .audit_store import SqliteAuditStore
from .auth import AuthStore
from .config import Settings
from .db import Database
from .migrations import migrate
from .models import AuditEntry
from .notifiers import SmtpNotifier
from .observability import (AlertManager, Metrics, check_health,
                            request_id_var, setup_logging)
from .providers import MockProvider
from .reporting import (access_report, activity_report, approval_report,
                        summary_report, to_csv, to_json)
from .requests import RequestStore
from .service import IAMService
from .sqlite_provider import SqliteProvider

TEMPLATES = Path(__file__).parent / "templates"


def render(template_name: str, **context) -> str:
    text = (TEMPLATES / template_name).read_text(encoding="utf-8")
    for key, value in context.items():
        text = text.replace("{{" + key + "}}", str(value))
    return text


def esc(value) -> str:
    return html.escape(str(value if value is not None else ""))


class LoginThrottle:
    """Per-IP failed-login throttle: at most max_attempts failures
    per window. Separate from per-account lockout -- this one stops
    a single source hammering many accounts."""

    def __init__(self, max_attempts: int = 20, window_seconds: int = 900):
        self.max_attempts = max_attempts
        self.window = window_seconds
        self._lock = threading.Lock()
        self._attempts = {}

    def allow(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            recent = [t for t in self._attempts.get(ip, [])
                      if now - t < self.window]
            self._attempts[ip] = recent
            return len(recent) < self.max_attempts

    def record(self, ip: str) -> None:
        with self._lock:
            self._attempts.setdefault(ip, []).append(time.time())


def new_request_fields(kind: str, csrf: str) -> str:
    """The input fields for one request kind. No JavaScript: the
    kind is chosen by links (?kind=onboard|move|offboard) and the
    server renders the matching form."""
    hidden = (f"<input type='hidden' name='kind' value='{kind}'>"
              f"<input type='hidden' name='csrf_token' value='{csrf}'>")
    if kind == "move":
        return hidden + """
            <label>Username <input name="username" required></label>
            <label>New role <input name="new_role" required></label>
            <label>New department <input name="new_department"></label>"""
    if kind == "offboard":
        return hidden + """
            <label>Username <input name="username" required></label>"""
    return hidden + """
        <label>First name <input name="first_name" required></label>
        <label>Last name <input name="last_name" required></label>
        <label>Username <input name="username" required></label>
        <label>Department <input name="department" required></label>
        <label>Role <input name="role" required></label>
        <label>Manager <input name="manager"></label>
        <label>Start date <input name="start_date"></label>
        <label>Email (for the welcome email; optional) <input name="email" type="email"></label>"""


def build_app(settings: Settings):
    """Build every layer and return (server_factory_context, service,
    auth, db, audit_store, provider). The caller starts the server."""
    db = Database(settings.db_path)
    migrate(db)
    if settings.provider == "sqlite":
        provider = SqliteProvider(db=db)
    elif settings.provider == "entra":
        from .entra_provider import EntraProvider
        import json as _json
        license_map = {}
        raw = settings.entra.get("IAM_ENTRA_LICENSE_MAP") or ""
        if raw:
            license_map = _json.loads(raw)
        provider = EntraProvider(
            tenant_id=settings.entra["IAM_ENTRA_TENANT_ID"],
            client_id=settings.entra["IAM_ENTRA_CLIENT_ID"],
            client_secret=settings.entra["IAM_ENTRA_CLIENT_SECRET"],
            domain=settings.entra["IAM_ENTRA_DOMAIN"],
            temp_password=settings.entra["IAM_ENTRA_TEMP_PASSWORD"],
            license_map=license_map)
    else:
        provider = MockProvider()
    audit_store = SqliteAuditStore(db=db)
    auth = AuthStore(db, session_hours=settings.session_hours,
                     lockout_threshold=settings.lockout_threshold,
                     lockout_minutes=settings.lockout_minutes)
    # Email alerts only when SMTP is fully configured; otherwise
    # alerts are still recorded and counted on the dashboard.
    notifier = None
    if all(os.environ.get(name) for name in (
            "IAM_SMTP_HOST", "IAM_SMTP_USER", "IAM_SMTP_PASSWORD",
            "IAM_NOTIFY_FROM", "IAM_NOTIFY_TO")):
        notifier = SmtpNotifier()
    from .emailing import email_sender_from_env
    service = IAMService(
        provider, audit_store=audit_store,
        audit_file=settings.audit_file,
        request_store=RequestStore(db),
        notifier=notifier,
        metrics=Metrics(), alerts=AlertManager(notifier),
        email_sender=email_sender_from_env())
    return {
        "db": db, "provider": provider, "audit_store": audit_store,
        "auth": auth, "service": service, "settings": settings,
        "throttle": LoginThrottle(),
    }


class Handler(BaseHTTPRequestHandler):
    app = None  # set by make_server

    # -- plumbing ---------------------------------------------------------

    def log_message(self, fmt, *args):  # keep stdout clean; logging used
        pass

    def _security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; "
                         "style-src 'self' 'unsafe-inline'")

    def _send_html(self, body: str, status: int = 200, cookie: str = None):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self._security_headers()
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, payload, status: int = 200):
        data = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, location: str, cookie: str = None):
        self.send_response(303)
        self.send_header("Location", location)
        self._security_headers()
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def _cookies(self) -> dict:
        raw = self.headers.get("Cookie", "")
        out = {}
        for part in raw.split(";"):
            if "=" in part:
                key, value = part.strip().split("=", 1)
                out[key] = value
        return out

    def _session(self):
        token = self._cookies().get("session")
        if not token:
            return None
        return self.app["auth"].get_session(token)

    def _require_login(self):
        session = self._session()
        if session is None:
            self._redirect("/login")
            return None
        return session

    def _form(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        parsed = urllib.parse.parse_qs(raw)
        return {key: values[0] for key, values in parsed.items()}

    def _check_csrf(self, session, form) -> bool:
        return bool(session and form.get("csrf_token")
                    and secrets.compare_digest(
                        form["csrf_token"], session["csrf_token"]))

    def _page(self, session, title: str, body: str) -> str:
        nav = ""
        if session:
            users_link = (" | <a href='/users'>Users</a>"
                          if session["role"] == "admin" else "")
            nav = (f"Logged in as <b>{esc(session['username'])}</b> "
                   f"({esc(session['role'])}) | "
                   "<a href='/dashboard'>Dashboard</a> | "
                   "<a href='/requests'>Requests</a> | "
                   "<a href='/requests/new'>New request</a> | "
                   "<a href='/review'>Access review</a> | "
                   "<a href='/reports'>Reports</a> | "
                   "<a href='/audit'>Audit</a>"
                   f"{users_link} | "
                   "<a href='/profile'>Profile</a> | "
                   "<form method='post' action='/logout' "
                   "style='display:inline'>"
                   f"<input type='hidden' name='csrf_token' "
                   f"value='{esc(session['csrf_token'])}'>"
                   "<button type='submit'>Log out</button></form>")
        return render("base.html", title=esc(title), nav=nav, body=body)

    def _audit_app_action(self, session, action: str, target: str,
                          note: str) -> None:
        """Record an app-administration action in the same audit
        store as directory changes, so admin activity is traceable
        in exactly one place."""
        entry = AuditEntry(
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            action, target, "done",
            f"by {session['username']}: {note}")
        self.app["audit_store"].append(entry)

    def _require_admin(self, session):
        if session["role"] != "admin":
            self._send_html(self._page(
                session, "Forbidden",
                "<p>Admin role required for this page.</p>"), status=403)
            return False
        return True

    def _user_rows(self, session) -> str:
        rows = ""
        for user in self.app["auth"].list_users():
            active = bool(user["active"])
            toggle = ("Deactivate" if active else "Activate")
            rows += (
                f"<tr><td>{esc(user['username'])}</td>"
                f"<td>{esc(user['role'])}</td>"
                f"<td>{'active' if active else 'inactive'}</td>"
                f"<td>{esc(user.get('locked_until') or '—')}</td>"
                "<td><form method='post' action='/users/"
                f"{urllib.parse.quote(user['username'])}"
                "/toggle-active' style='display:inline'>"
                f"<input type='hidden' name='csrf_token' "
                f"value='{esc(session['csrf_token'])}'>"
                f"<button type='submit'>{toggle}</button></form>"
                " <form method='post' action='/users/"
                f"{urllib.parse.quote(user['username'])}"
                "/reset-password' style='display:inline'>"
                f"<input type='hidden' name='csrf_token' "
                f"value='{esc(session['csrf_token'])}'>"
                "<input name='new_password' type='password' "
                "placeholder='new password' required>"
                "<button type='submit'>Reset password</button>"
                "</form></td></tr>")
        return rows

    # -- routing ------------------------------------------------------------

    def do_GET(self):
        request_id_var.set(secrets.token_hex(4))
        parsed = urllib.parse.urlparse(self.path)
        path, query = parsed.path, urllib.parse.parse_qs(parsed.query)
        service = self.app["service"]
        try:
            if path == "/health":
                health = check_health(self.app["db"],
                                      self.app["audit_store"],
                                      self.app["provider"])
                self._send_json(
                    health, 200 if health["status"] == "healthy" else 503)
                return
            if path == "/login":
                self._send_html(render("login.html", error=""))
                return
            session = self._require_login()
            if session is None:
                return
            if path in ("/", "/dashboard"):
                stats = service.dashboard_stats()
                recent = service.list_requests()[:10]
                rows = "".join(
                    f"<tr><td><a href='/requests/{r['id']}'>{r['id']}</a>"
                    f"</td><td>{esc(r['kind'])}</td>"
                    f"<td>{esc(r['payload'].get('username', ''))}</td>"
                    f"<td>{esc(r['status'])}</td>"
                    f"<td>{esc(r['requester'])}</td></tr>"
                    for r in recent)
                self._send_html(self._page(
                    session, "Dashboard",
                    render("dashboard.html",
                           pending=stats["pending_approval"],
                           total_requests=stats["total_requests"],
                           total_users=stats["total_users"],
                           active_users=stats["active_users"],
                           alerts=stats["alerts"], rows=rows)))
            elif path == "/requests":
                status = query.get("status", [""])[0]
                rows = "".join(
                    f"<tr><td><a href='/requests/{r['id']}'>{r['id']}</a>"
                    f"</td><td>{esc(r['kind'])}</td>"
                    f"<td>{esc(r['payload'].get('username', ''))}</td>"
                    f"<td>{esc(r['status'])}</td>"
                    f"<td>{esc(r['requester'])}</td>"
                    f"<td>{esc(r.get('approver') or '')}</td></tr>"
                    for r in service.list_requests(
                        status=status or None))
                self._send_html(self._page(
                    session, "Requests",
                    render("requests.html", rows=rows, status=esc(status))))
            elif path == "/requests/new":
                kind = query.get("kind", ["onboard"])[0]
                if kind not in ("onboard", "move", "offboard"):
                    kind = "onboard"
                self._send_html(self._page(
                    session, "New request",
                    render("request_new.html", kind=kind,
                           fields=new_request_fields(
                               kind, esc(session["csrf_token"])),
                           error="")))
            elif (match := re.fullmatch(r"/requests/(\d+)", path)):
                request = service.get_request(int(match.group(1)))
                if request is None:
                    self._send_html(self._page(
                        session, "Not found", "<p>No such request.</p>"),
                        status=404)
                    return
                can_decide = (session["role"] in ("admin", "approver")
                              and session["username"]
                              != request["requester"])
                forms = ""
                if request["status"] == "pending_approval" and can_decide:
                    forms = render(
                        "decision_forms.html", id=request["id"],
                        csrf=esc(session["csrf_token"]))
                elif request["status"] == "pending_approval":
                    forms = ("<p>You cannot decide this request "
                             "(approver role required, and never your "
                             "own request).</p>")
                payload_rows = "".join(
                    f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>"
                    for k, v in request["payload"].items())
                result = esc(json.dumps(request.get("result"), indent=2)
                             ) if request.get("result") else "—"
                self._send_html(self._page(
                    session, f"Request {request['id']}",
                    render("request_detail.html", id=request["id"],
                           kind=esc(request["kind"]),
                           status=esc(request["status"]),
                           requester=esc(request["requester"]),
                           approver=esc(request.get("approver") or "—"),
                           reason=esc(request.get("decision_reason") or "—"),
                           payload_rows=payload_rows, result=result,
                           forms=forms)))
            elif path == "/review":
                users = self.app["provider"].list_users()
                rows = "".join(
                    f"<tr><td>{esc(u['username'])}</td>"
                    f"<td>{esc(u.get('display_name', ''))}</td>"
                    f"<td>{esc(u.get('department', ''))}</td>"
                    f"<td>{esc(u.get('role', ''))}</td>"
                    f"<td>{'active' if u.get('active') else 'disabled'}</td>"
                    f"<td>{esc(', '.join(u.get('groups', [])))}</td>"
                    f"<td>{esc(', '.join(u.get('licenses', [])))}</td></tr>"
                    for u in users)
                self._send_html(self._page(
                    session, "Access review",
                    render("review.html", rows=rows)))
            elif path == "/reports":
                fmt = query.get("format", ["html"])[0]
                kind = query.get("kind", ["summary"])[0]
                audit_entries = self.app["audit_store"].list_entries(10000)
                requests = service.list_requests()
                provider = self.app["provider"]
                reports = {
                    "access": access_report(provider),
                    "activity": activity_report(audit_entries),
                    "approvals": approval_report(requests),
                    "summary": summary_report(provider, audit_entries,
                                              requests),
                }
                if kind not in reports:
                    kind = "summary"
                if fmt == "csv":
                    data = to_csv(reports[kind], kind).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/csv")
                    self.send_header(
                        "Content-Disposition",
                        f"attachment; filename={kind}-report.csv")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                if fmt == "json":
                    self._send_json(reports[kind])
                    return
                pretty = esc(to_json(reports[kind]))
                self._send_html(self._page(
                    session, "Reports",
                    render("reports.html", kind=kind, pretty=pretty)))
            elif path == "/audit":
                rows = "".join(
                    f"<tr><td>{esc(e['timestamp'])}</td>"
                    f"<td>{esc(e['action'])}</td>"
                    f"<td>{esc(e['target'])}</td>"
                    f"<td>{esc(e['status'])}</td>"
                    f"<td>{esc(e['note'])}</td></tr>"
                    for e in self.app["audit_store"].list_entries(200))
                self._send_html(self._page(
                    session, "Audit log", render("audit.html", rows=rows)))
            elif path == "/users":
                if not self._require_admin(session):
                    return
                self._send_html(self._page(
                    session, "App users",
                    render("users.html", rows=self._user_rows(session),
                           csrf=esc(session["csrf_token"]), error="")))
            elif path == "/profile":
                self._send_html(self._page(
                    session, "Profile",
                    render("profile.html",
                           csrf=esc(session["csrf_token"]), error="",
                           message="")))
            elif path == "/metrics":
                self._send_json(service.metrics.snapshot())
            else:
                self._send_html(self._page(
                    session, "Not found", "<p>Unknown page.</p>"),
                    status=404)
        except Exception as exc:  # noqa: BLE001 -- app shows, not crashes
            self._send_html(self._page(
                self._session(), "Error",
                f"<p>Something went wrong: {esc(exc)}</p>"), status=500)

    def do_POST(self):
        request_id_var.set(secrets.token_hex(4))
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        try:
            if path == "/login":
                form = self._form()
                ip = self.client_address[0]
                throttle = self.app["throttle"]
                if not throttle.allow(ip):
                    self._send_html(render(
                        "login.html",
                        error="Too many login attempts from this address. "
                              "Try again later."), status=429)
                    return
                token = self.app["auth"].authenticate(
                    form.get("username", ""), form.get("password", ""))
                if token is None:
                    throttle.record(ip)
                    self._send_html(render(
                        "login.html",
                        error="Invalid username or password."))
                    return
                cookie = (f"session={token}; HttpOnly; Path=/; "
                          "SameSite=Lax")
                if self.app["settings"].cookie_secure:
                    cookie += "; Secure"
                self._redirect("/dashboard", cookie=cookie)
                return
            session = self._require_login()
            if session is None:
                return
            form = self._form()
            # Every state-changing POST, including logout, requires a
            # valid CSRF token for the session.
            if not self._check_csrf(session, form):
                self._send_html(self._page(
                    session, "Error",
                    "<p>Security check failed. Please try again.</p>"),
                    status=403)
                return
            if path == "/logout":
                token = self._cookies().get("session")
                if token:
                    self.app["auth"].logout(token)
                self._redirect("/login")
                return
            if path == "/users/new":
                if not self._require_admin(session):
                    return
                try:
                    self.app["auth"].create_user(
                        form["username"], form["new_password"],
                        form["role"])
                    self._audit_app_action(
                        session, "app_user_create", form["username"],
                        f"role {form['role']}")
                except (ValueError, KeyError) as exc:
                    self._send_html(self._page(
                        session, "App users",
                        render("users.html", rows=self._user_rows(session),
                               csrf=esc(session["csrf_token"]),
                               error=f"Could not create user: {esc(exc)}")),
                        status=400)
                    return
                self._redirect("/users")
                return
            if (match := re.fullmatch(
                    r"/users/([^/]+)/(toggle-active|reset-password)",
                    path)):
                if not self._require_admin(session):
                    return
                username = urllib.parse.unquote(match.group(1))
                action = match.group(2)
                try:
                    if action == "toggle-active":
                        user = self.app["auth"].get_user(username)
                        if user is None:
                            raise ValueError("unknown app user")
                        new_state = not bool(user["active"])
                        self.app["auth"].set_active(username, new_state)
                        self._audit_app_action(
                            session, "app_user_toggle_active", username,
                            "active" if new_state else "inactive")
                    else:
                        self.app["auth"].set_password(
                            username, form["new_password"])
                        self._audit_app_action(
                            session, "app_user_password_reset", username,
                            "password reset by admin")
                except (ValueError, KeyError) as exc:
                    self._send_html(self._page(
                        session, "Error", f"<p>{esc(exc)}</p>"), status=400)
                    return
                self._redirect("/users")
                return
            if path == "/profile/password":
                new = form.get("new_password", "")
                if new != form.get("confirm_password", ""):
                    self._send_html(self._page(
                        session, "Profile",
                        render("profile.html",
                               csrf=esc(session["csrf_token"]),
                               error="New passwords do not match.",
                               message="")), status=400)
                    return
                try:
                    ok = self.app["auth"].change_password(
                        session["username"], form.get("current_password",
                                                      ""), new)
                except ValueError as exc:
                    ok = False
                    error = str(exc)
                else:
                    error = "" if ok else "Current password is incorrect."
                if not ok:
                    self._send_html(self._page(
                        session, "Profile",
                        render("profile.html",
                               csrf=esc(session["csrf_token"]),
                               error=error, message="")), status=400)
                    return
                self._audit_app_action(session, "app_user_password_change",
                                       session["username"], "self-service")
                self._send_html(self._page(
                    session, "Profile",
                    render("profile.html",
                           csrf=esc(session["csrf_token"]), error="",
                           message="Password changed. All sessions, "
                                   "including this one, were signed out — "
                                   "please log in again.")))
                return
            service = self.app["service"]
            if path == "/requests/new":
                kind = form.get("kind", "onboard")
                try:
                    if kind == "onboard":
                        request = service.submit_onboard({
                            "first_name": form["first_name"],
                            "last_name": form["last_name"],
                            "username": form["username"],
                            "department": form["department"],
                            "role": form["role"],
                            "manager": form.get("manager", ""),
                            "start_date": form.get("start_date", ""),
                            "email": form.get("email", ""),
                        }, session["username"])
                    elif kind == "move":
                        request = service.submit_move(
                            form["username"], form["new_role"],
                            session["username"],
                            form.get("new_department") or None)
                    elif kind == "offboard":
                        request = service.submit_offboard(
                            form["username"], session["username"])
                    else:
                        raise ValueError("unknown kind")
                except (ValueError, KeyError) as exc:
                    self._send_html(self._page(
                        session, "New request",
                        render("request_new.html", kind=kind,
                               fields=new_request_fields(
                                   kind, esc(session["csrf_token"])),
                               error=f"Could not submit: {esc(exc)}")),
                        status=400)
                    return
                self._redirect(f"/requests/{request['id']}")
                return
            if (match := re.fullmatch(r"/requests/(\d+)/(approve|reject)",
                                      path)):
                request_id, action = int(match.group(1)), match.group(2)
                try:
                    if action == "approve":
                        service.approve(request_id, session["username"],
                                        session["role"])
                    else:
                        service.reject(request_id, session["username"],
                                       session["role"],
                                       form.get("reason", ""))
                except ValueError as exc:
                    self._send_html(self._page(
                        session, "Error", f"<p>{esc(exc)}</p>"), status=400)
                    return
                self._redirect(f"/requests/{request_id}")
                return
            self._send_html(self._page(session, "Not found",
                                       "<p>Unknown action.</p>"),
                            status=404)
        except Exception as exc:  # noqa: BLE001
            self._send_html(self._page(
                self._session(), "Error",
                f"<p>Something went wrong: {esc(exc)}</p>"), status=500)


def make_server(settings: Settings, app_context: dict):
    Handler.app = app_context
    server = ThreadingHTTPServer((settings.app_host, settings.app_port),
                                 Handler)
    server.daemon_threads = True
    return server


def main():
    settings = Settings.from_env()
    settings.validate()
    setup_logging(json_format=settings.log_json)
    app_context = build_app(settings)
    auth = app_context["auth"]
    generated_password = None
    if settings.app_admin_user and settings.app_admin_password:
        if auth.ensure_admin(settings.app_admin_user,
                             settings.app_admin_password):
            print(f"Created admin user {settings.app_admin_user!r} "
                  "from environment.")
    else:
        generated_password = secrets.token_urlsafe(12)
        if auth.ensure_admin("admin", generated_password):
            print("No app users existed: created bootstrap admin 'admin'.")
            print(f"  Password (shown once): {generated_password}")
            print("  Set IAM_APP_ADMIN_USER / IAM_APP_ADMIN_PASSWORD "
                  "to control this, and change the password after first "
                  "login in a future release.")
        else:
            generated_password = None
    server = make_server(settings, app_context)
    print(f"IAM app running at http://{settings.app_host}:"
          f"{settings.app_port}/  (provider: {settings.provider})")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
