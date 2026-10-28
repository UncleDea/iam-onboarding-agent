"""Demo: on-board two fictional hires with the mock provider.

Run it with:  python main.py

It shows the two modes that matter:
1. DRY RUN -- print the plan, change nothing.
2. APPROVED RUN -- a human approves the plan, then it executes, and
   every step lands in the audit log.

Nothing here touches a real system. Swap MockProvider for a real
provider (see iam_agent/entra_provider.py) when you are ready.

The welcome email is printed to the console for Ada (who has an
email address) and skipped, with an audit note, for Bob (who does
not) -- both behaviours are part of the design.
"""

from iam_agent import MockProvider, NewHire, OnboardingAgent
from iam_agent.emailing import ConsoleEmailSender


def approver(plan, hire) -> bool:
    print(f"\nApproval requested for {hire.display_name}:")
    for i, step in enumerate(plan, 1):
        print(f"  {i}. {step.description}")
    # Demo only: auto-approve. A real deployment asks a human here
    # (a prompt, a button, a ticket approval) and returns their answer.
    print("  -> approved (demo auto-approval)")
    return True


def main() -> None:
    agent = OnboardingAgent(MockProvider(), approver=approver,
                            email_sender=ConsoleEmailSender())

    hires = [
        NewHire("Ada", "Lovelace", "ada.lovelace", "Engineering",
                "engineer", manager="carol.manager", start_date="2026-11-02",
                email="ada.lovelace@example.com"),
        NewHire("Bob", "Builder", "bob.builder", "Sales",
                "sales", manager="carol.manager", start_date="2026-11-02"),
    ]

    print("=== DRY RUN (nothing is created) ===")
    for hire in hires:
        result = agent.run(hire, dry_run=True)
        for step in result["planned"]:
            print(f"  [{hire.username}] would: {step.description}")

    print("\n=== APPROVED RUN ===")
    for hire in hires:
        result = agent.run(hire)
        print(f"  [{hire.username}] status: {result['status']}")

    print("\n=== FINAL STATE (mock provider) ===")
    for username, user in agent.provider.users.items():
        print(f"  {username}: groups={user['groups']} "
              f"licenses={user['licenses']} active={user['active']}")

    print("\n=== AUDIT LOG ===")
    for entry in agent.audit:
        print(f"  {entry.timestamp} {entry.action:15} {entry.target:15} "
              f"{entry.status} -- {entry.note}")


if __name__ == "__main__":
    main()
