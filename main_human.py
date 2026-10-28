"""Demo with a REAL human approver (README step 1).

Run it with:  python main_human.py

Same hires and mock provider as main.py, but the approver is no longer
auto-approval: for each hire it prints the exact plan and asks you
"Approve this plan? [y/n]". Answer "y" to create that hire, "n" to
reject it -- and watch the audit log record the rejection, with
nothing created for that hire.

This is the safety rail that matters before any real provider is
plugged in: the agent never creates anything until a human has seen
and approved the exact checklist. The original main.py demo is left
untouched, so you can compare the two.
"""

from iam_agent import MockProvider, NewHire, OnboardingAgent


def human_approver(plan, hire) -> bool:
    print(f"\nApproval requested for {hire.display_name}:")
    for i, step in enumerate(plan, 1):
        print(f"  {i}. {step.description}")
    answer = input("Approve this plan? [y/n]: ").strip().lower()
    approved = answer.startswith("y")
    print(f"  -> {'approved' if approved else 'rejected'} by human")
    return approved


def main() -> None:
    agent = OnboardingAgent(MockProvider(), approver=human_approver)

    hires = [
        NewHire("Ada", "Lovelace", "ada.lovelace", "Engineering",
                "engineer", manager="carol.manager", start_date="2026-11-02"),
        NewHire("Bob", "Builder", "bob.builder", "Sales",
                "sales", manager="carol.manager", start_date="2026-11-02"),
    ]

    print("=== HUMAN-APPROVAL RUN (mock provider, nothing real) ===")
    for hire in hires:
        result = agent.run(hire)
        print(f"  [{hire.username}] status: {result['status']}")

    print("\n=== FINAL STATE (mock provider) ===")
    for username, user in agent.provider.users.items():
        print(f"  {username}: groups={user['groups']} "
              f"licenses={user['licenses']} active={user['active']}")
    if not agent.provider.users:
        print("  (no users created)")

    print("\n=== AUDIT LOG ===")
    for entry in agent.audit:
        print(f"  {entry.timestamp} {entry.action:15} {entry.target:15} "
              f"{entry.status} -- {entry.note}")


if __name__ == "__main__":
    main()
