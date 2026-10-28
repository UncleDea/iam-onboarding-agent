"""Notifiers: tell someone what happened.

The engine never assumes how you want to be told. It calls
notify(username, status, summary) and this module provides the
transports. Notification failure never breaks a run -- the engine
catches it and logs a warning, because the outcome matters more than
the message about the outcome.
"""

import os
import smtplib
from email.message import EmailMessage


class ConsoleNotifier:
    """Print notifications. The default: visible, no configuration."""

    def notify(self, username: str, status: str, summary: str) -> None:
        print(f"  [notify] {username}: {status} -- {summary}")


class SmtpNotifier:
    """Send notifications by email, configured purely by environment:

    IAM_SMTP_HOST, IAM_SMTP_PORT (default 587), IAM_SMTP_USER,
    IAM_SMTP_PASSWORD, IAM_NOTIFY_FROM, IAM_NOTIFY_TO (comma-separated).

    Secrets come from the environment, never from code. Missing
    configuration is an error at construction, not at send time, so a
    misconfigured notifier fails fast instead of silently dropping
    notifications.
    """

    def __init__(self):
        missing = [name for name in
                   ("IAM_SMTP_HOST", "IAM_SMTP_USER", "IAM_SMTP_PASSWORD",
                    "IAM_NOTIFY_FROM", "IAM_NOTIFY_TO")
                   if not os.environ.get(name)]
        if missing:
            raise ValueError(
                "SmtpNotifier missing environment variables: "
                + ", ".join(missing))
        self.host = os.environ["IAM_SMTP_HOST"]
        self.port = int(os.environ.get("IAM_SMTP_PORT", "587"))
        self.user = os.environ["IAM_SMTP_USER"]
        self.password = os.environ["IAM_SMTP_PASSWORD"]
        self.sender = os.environ["IAM_NOTIFY_FROM"]
        self.recipients = [addr.strip() for addr in
                           os.environ["IAM_NOTIFY_TO"].split(",")]

    def notify(self, username: str, status: str, summary: str) -> None:
        message = EmailMessage()
        message["From"] = self.sender
        message["To"] = ", ".join(self.recipients)
        message["Subject"] = f"IAM: {username} on-boarding {status}"
        message.set_content(
            f"User: {username}\nStatus: {status}\nSummary: {summary}\n")
        with smtplib.SMTP(self.host, self.port) as server:
            server.starttls()
            server.login(self.user, self.password)
            server.send_message(message)
