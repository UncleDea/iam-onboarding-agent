import os
import smtplib
import tempfile
import unittest
from unittest import mock

from iam_agent import MockProvider, NewHire, OnboardingAgent
from iam_agent.db import Database
from iam_agent.emailing import (SmtpEmailSender, email_sender_from_env,
                                welcome_body, welcome_subject)
from iam_agent.migrations import migrate
from iam_agent.requests import RequestStore
from iam_agent.service import IAMService


def hire(email="ada.lovelace@example.com"):
    return NewHire("Ada", "Lovelace", "ada.lovelace", "Engineering",
                   "engineer", manager="carol.manager",
                   start_date="2026-11-02", email=email)


class FakeSender:
    def __init__(self):
        self.sent = []

    def send(self, to, subject, body):
        self.sent.append((to, subject, body))


class FailingSender:
    def send(self, to, subject, body):
        raise RuntimeError("SMTP server down")


class TestTemplate(unittest.TestCase):
    def test_template_contains_details_and_no_password(self):
        body = welcome_body(hire())
        self.assertIn("Ada Lovelace", body)
        self.assertIn("ada.lovelace", body)
        self.assertIn("Engineering", body)
        self.assertIn("engineer", body)
        self.assertIn("carol.manager", body)
        self.assertIn("2026-11-02", body)
        self.assertNotIn("password", body.lower())
        self.assertIn("Ada", welcome_subject(hire()))


class TestNewHireEmail(unittest.TestCase):
    def test_invalid_email_rejected(self):
        with self.assertRaises(ValueError):
            NewHire("Ada", "Lovelace", "ada.lovelace", "Engineering",
                    "engineer", email="not-an-email")


class FakeSMTP:
    instances = []

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.messages = []
        FakeSMTP.instances.append(self)

    def starttls(self):
        pass

    def login(self, user, password):
        self.user = user
        self.password = password

    def send_message(self, message):
        self.messages.append(message)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class TestSmtpSender(unittest.TestCase):
    def test_send_uses_config_and_headers(self):
        env = {
            "IAM_SMTP_HOST": "smtp.example.com",
            "IAM_SMTP_PORT": "587",
            "IAM_SMTP_USER": "sender@example.com",
            "IAM_SMTP_PASSWORD": "secret",
            "IAM_WELCOME_FROM": "welcome@example.com",
        }
        FakeSMTP.instances = []
        with mock.patch.dict(os.environ, env, clear=False):
            with mock.patch.object(smtplib, "SMTP", FakeSMTP):
                sender = SmtpEmailSender.from_env()
                sender.send("ada@example.com", "Hi", "Body")
        message = FakeSMTP.instances[0].messages[0]
        self.assertEqual(message["From"], "welcome@example.com")
        self.assertEqual(message["To"], "ada@example.com")
        self.assertEqual(message["Subject"], "Hi")

    def test_sender_from_env_none_when_unconfigured(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(email_sender_from_env())

    def test_sender_from_env_console_when_flagged(self):
        with mock.patch.dict(os.environ, {"IAM_EMAIL_CONSOLE": "1"},
                             clear=True):
            sender = email_sender_from_env()
            self.assertIsNotNone(sender)


class TestEngineWelcome(unittest.TestCase):
    def test_welcome_sent_when_address_and_sender(self):
        sender = FakeSender()
        agent = OnboardingAgent(MockProvider(), approver=lambda p, h: True,
                                email_sender=sender)
        result = agent.run(hire())
        self.assertEqual(result["status"], "done")
        self.assertEqual(len(sender.sent), 1)
        self.assertEqual(sender.sent[0][0], "ada.lovelace@example.com")
        welcome = [e for e in agent.audit if e.action == "send_welcome"][0]
        self.assertEqual(welcome.status, "done")

    def test_welcome_skipped_without_address(self):
        sender = FakeSender()
        agent = OnboardingAgent(MockProvider(), approver=lambda p, h: True,
                                email_sender=sender)
        agent.run(hire(email=""))
        self.assertEqual(sender.sent, [])
        welcome = [e for e in agent.audit if e.action == "send_welcome"][0]
        self.assertEqual(welcome.status, "skipped")

    def test_welcome_skipped_without_sender(self):
        agent = OnboardingAgent(MockProvider(), approver=lambda p, h: True)
        result = agent.run(hire())
        self.assertEqual(result["status"], "done")
        welcome = [e for e in agent.audit if e.action == "send_welcome"][0]
        self.assertEqual(welcome.status, "skipped")

    def test_failed_welcome_does_not_fail_onboarding(self):
        agent = OnboardingAgent(MockProvider(), approver=lambda p, h: True,
                                email_sender=FailingSender())
        result = agent.run(hire())
        self.assertEqual(result["status"], "done")
        welcome = [e for e in agent.audit if e.action == "send_welcome"][0]
        self.assertEqual(welcome.status, "failed")
        user = agent.provider.users["ada.lovelace"]
        self.assertTrue(user["active"])
        self.assertIn("engineering", user["groups"])


class TestServiceWelcome(unittest.TestCase):
    def test_approve_sends_welcome(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.unlink(path)
        db = Database(path)
        migrate(db)
        try:
            sender = FakeSender()
            service = IAMService(
                MockProvider(), request_store=RequestStore(db),
                email_sender=sender)
            request = service.submit_onboard({
                "first_name": "Ada", "last_name": "Lovelace",
                "username": "ada.lovelace", "department": "Engineering",
                "role": "engineer", "manager": "", "start_date": "2026-11-02",
                "email": "ada.lovelace@example.com",
            }, "alice")
            finished = service.approve(request["id"], "boss", "approver")
            self.assertEqual(finished["status"], "done")
            self.assertEqual(len(sender.sent), 1)
        finally:
            db.close()
            if os.path.exists(path):
                os.unlink(path)


if __name__ == "__main__":
    unittest.main()
