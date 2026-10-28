"""Welcome emails: the last step of on-boarding, done for real.

Until now the engine's `send_welcome` step only wrote an audit
entry. This module makes it send an actual email to the new hire.

Design decisions, stated plainly:

- The email contains no password and no secret. It tells the hire
  their account exists, what team and role they start in, who their
  manager is, and when they start -- and to contact their manager
  or IT if sign-in fails. Temporary passwords travel through
  whatever channel the organisation already uses for them, never
  in a welcome email.
- The sender is configured purely from the environment, reusing
  the SMTP settings: IAM_SMTP_HOST, IAM_SMTP_PORT (default 587),
  IAM_SMTP_USER, IAM_SMTP_PASSWORD, and IAM_WELCOME_FROM (falling
  back to IAM_NOTIFY_FROM). Set IAM_EMAIL_CONSOLE=1 instead to
  print emails to the console -- useful for demos and tests, never
  for production.
- If no sender is configured, the engine skips the step and says
  so in the audit log. A missing mail configuration must never
  fail an on-boarding: the account matters more than the email.
"""

import logging
import os
import smtplib
from email.message import EmailMessage

logger = logging.getLogger(__name__)


def welcome_subject(hire) -> str:
    return f"Welcome to the team, {hire.first_name}!"


def welcome_body(hire) -> str:
    lines = [
        f"Hi {hire.display_name},",
        "",
        "Welcome! Your account has been created.",
        "",
        f"  Username:   {hire.username}",
        f"  Department: {hire.department}",
        f"  Role:       {hire.role}",
    ]
    if hire.manager:
        lines.append(f"  Manager:    {hire.manager}")
    if hire.start_date:
        lines.append(f"  Start date: {hire.start_date}")
    lines += [
        "",
        "You can sign in with your username. If you have any trouble",
        "signing in, please contact your manager or IT support.",
        "",
        "Welcome aboard!",
    ]
    return "\n".join(lines)


class ConsoleEmailSender:
    """Print emails instead of sending them. Demos and tests only."""

    def send(self, to: str, subject: str, body: str) -> None:
        print(f"[welcome email] To: {to}\nSubject: {subject}\n{body}")


class SmtpEmailSender:
    """Send email via SMTP with STARTTLS."""

    def __init__(self, host: str, port: int, user: str, password: str,
                 sender: str):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.sender = sender

    @classmethod
    def from_env(cls):
        """Build from the environment, or raise ValueError listing
        what is missing."""
        missing = [name for name in (
            "IAM_SMTP_HOST", "IAM_SMTP_USER", "IAM_SMTP_PASSWORD")
            if not os.environ.get(name)]
        sender = (os.environ.get("IAM_WELCOME_FROM")
                  or os.environ.get("IAM_NOTIFY_FROM"))
        if not sender:
            missing.append("IAM_WELCOME_FROM or IAM_NOTIFY_FROM")
        if missing:
            raise ValueError(
                "email sender missing environment variables: "
                + ", ".join(missing))
        return cls(
            host=os.environ["IAM_SMTP_HOST"],
            port=int(os.environ.get("IAM_SMTP_PORT", "587")),
            user=os.environ["IAM_SMTP_USER"],
            password=os.environ["IAM_SMTP_PASSWORD"],
            sender=sender)

    def send(self, to: str, subject: str, body: str) -> None:
        message = EmailMessage()
        message["From"] = self.sender
        message["To"] = to
        message["Subject"] = subject
        message.set_content(body)
        with smtplib.SMTP(self.host, self.port) as server:
            server.starttls()
            server.login(self.user, self.password)
            server.send_message(message)


def email_sender_from_env():
    """Return a configured sender, or None if email is not set up.
    A partial SMTP configuration logs a warning and returns None
    rather than failing at import time -- the engine treats that
    as 'skip the welcome email', which is the safe default."""
    if os.environ.get("IAM_EMAIL_CONSOLE") == "1":
        return ConsoleEmailSender()
    try:
        return SmtpEmailSender.from_env()
    except ValueError as exc:
        logger.warning("welcome emails disabled: %s", exc)
        return None
