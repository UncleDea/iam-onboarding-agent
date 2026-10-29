"""IAM Onboarding: plan, approve, execute, audit."""

__version__ = "1.0.0"

from .approval import classify, make_approver, terminal_human_approver
from .audit_store import SqliteAuditStore
from .auth import AuthStore
from .config import Settings
from .db import Database
from .emailing import (ConsoleEmailSender, SmtpEmailSender,
                       email_sender_from_env, welcome_body,
                       welcome_subject)
from .engine import OnboardingAgent
from .entra_provider import EntraProvider, GraphClient
from .migrations import migrate
from .models import AuditEntry, NewHire, PlanStep
from .notifiers import ConsoleNotifier, SmtpNotifier
from .observability import AlertManager, Metrics, check_health
from .providers import IdentityProvider, MockProvider
from .reporting import (access_report, activity_report, approval_report,
                        summary_report)
from .requests import RequestStore
from .retry import TransientError, call_with_retry
from .service import IAMService
from .sqlite_provider import SqliteProvider

__all__ = [
    "OnboardingAgent",
    "NewHire",
    "PlanStep",
    "AuditEntry",
    "IdentityProvider",
    "MockProvider",
    "SqliteProvider",
    "EntraProvider",
    "GraphClient",
    "SqliteAuditStore",
    "ConsoleNotifier",
    "SmtpNotifier",
    "TransientError",
    "call_with_retry",
    "classify",
    "make_approver",
    "terminal_human_approver",
    "Database",
    "ConsoleEmailSender",
    "SmtpEmailSender",
    "email_sender_from_env",
    "welcome_subject",
    "welcome_body",
    "migrate",
    "Settings",
    "RequestStore",
    "AuthStore",
    "IAMService",
    "Metrics",
    "AlertManager",
    "check_health",
    "access_report",
    "activity_report",
    "approval_report",
    "summary_report",
]
