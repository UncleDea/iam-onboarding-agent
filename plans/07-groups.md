# Groups, read only

Access review stays the screen for one person. This page answers a different question: who is in this group?

`GET /groups` is available to anyone who can open Access review. The nav item is **Groups**, and it stays highlighted on that page. There is no form. Nothing on the page adds or removes a member. A change is still a request that the other person approves.

The rows are derived. There is no new table. A group appears if the policy names it (any role, the fallback, or the privileged list) or if any person holds it. An empty policy group is shown with no members, so a role's group is visible before anyone has it. A group that exists only because someone holds it, and the policy does not name it, is shown too and is not marked privileged.

Each row has the group name, whether the policy lists it as privileged, the people who hold it directly, and the people who only inherit it. Inherited names come from `inherited_groups` on the directory user. The built-in directory has none. Entra already separates direct membership from transitive membership, and an offboard does not remove an inherited group, so those two lists stay apart.

Privileged groups are listed first, then the name. Member names are the directory usernames.

The index is a function next to the access report, so a test can build it without HTTP. The page test signs in, opens `/groups`, and checks a known group, an empty policy group, a privileged mark, and that a POST to `/groups` is not a way to change membership.
