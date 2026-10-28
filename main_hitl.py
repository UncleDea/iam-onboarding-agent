"""Demo: risk-tiered human-in-the-loop approvals.

Run it with:  python main_hitl.py

Three hires show the three routes:
- Ada (engineer): standard access -> auto-approved, no human asked.
- Carol (manager): privileged role -> a human is asked.
- Wally (unknown role "chief-wizard"): unknown to policy -> a human
  is asked, because the agent must not guess about access it does not
  understand.

Answer the prompts to see both outcomes. Mock provider only: nothing
real is created.
"""

from iam_agent import MockProvider, NewHire, OnboardingAgent
from iam_agent.approval import make_approver, terminal_human_approver


def main() -> None:
    agent = OnboardingAgent(
        MockProvider(),
        approver=make_approver(terminal_human_approver,
                               human_name="terminal-user"),
    )

    hires = [
        NewHire("Ada", "Lovelace", "ada.lovelace", "Engineering",
                "engineer", start_date="2026-11-02"),
        NewHire("Carol", "Manager", "carol.manager", "Engineering",
                "manager", start_date="2026-11-02"),
        NewHire("Wally", "Wizard", "wally.wizard", "Engineering",
                "chief-wizard", start_date="2026-11-02"),
    ]

    print("=== HUMAN-IN-THE-LOOP RUN (mock provider, nothing real) ===")
    for hire in hires:
        result = agent.run(hire)
        print(f"  [{hire.username}] status: {result['status']}")

    print("\n=== AUDIT LOG (note who decided each approval) ===")
    for entry in agent.audit:
        print(f"  {entry.timestamp} {entry.action:15} {entry.target:15} "
              f"{entry.status} -- {entry.note}")


if __name__ == "__main__":
    main()
