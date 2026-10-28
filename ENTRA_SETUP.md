# Connecting the Entra provider

The Entra provider (`iam_agent/entra_provider.py`) talks to a real
Microsoft Entra ID tenant over Microsoft Graph. This guide takes you
from nothing to a first safe run. Read the warnings: this touches a
real identity system.

## 0. Use a test tenant first

Never point this at a production tenant on the first run. Use a
Microsoft 365 developer tenant, or a test tenant your admin created
for this purpose. Everything below is reversible, but a test tenant
makes mistakes cheap.

## 1. Create the app registration

In the Microsoft Entra admin center, or the Azure portal:

1. Go to **App registrations** → **New registration**.
2. Name it something clear, e.g. `iam-onboarding-agent`.
3. Supported account types: **Accounts in this organizational
   directory only**.
4. No redirect URI is needed: this app uses the client-credentials
   flow (app-only, no user sign-in).

## 2. Grant least-privilege API permissions

In the app registration, **API permissions** → **Add a permission** →
**Microsoft Graph** → **Application permissions**:

- `User.ReadWrite.All` — create, update, disable users
- `GroupMember.ReadWrite.All` — add/remove group members
- `Organization.Read.All` — read subscribed SKUs (licence lookup)
- `Directory.Read.All` — look up users and groups by name

Then **Grant admin consent** for your tenant. Without consent, every
Graph call fails with an authorization error — that is the system
working as intended.

These permissions are the minimum for the provider's operations. If
the app is compromised, the damage is bounded by exactly this list,
which is why it must not be given Global Administrator or
`Directory.ReadWrite.All`.

## 3. Create a client secret

**Certificates & secrets** → **New client secret**. Copy the value
immediately — it is shown once. Treat it like a password:

- Never commit it, never paste it into a chat, never put it on a
  command line (command lines end up in shell history).
- Prefer a short expiry (e.g. 6 months) and a calendar reminder to
  rotate it. A secret that never expires is a liability.

## 4. Set the environment variables

```bash
export IAM_ENTRA_TENANT_ID="your-tenant.onmicrosoft.com"  # or the tenant GUID
export IAM_ENTRA_CLIENT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export IAM_ENTRA_CLIENT_SECRET="the secret from step 3"
export IAM_ENTRA_DOMAIN="your-tenant.onmicrosoft.com"
export IAM_ENTRA_TEMP_PASSWORD="a temporary password meeting your tenant policy"
# Optional: map policy licence names to Graph skuPartNumbers
export IAM_ENTRA_LICENSE_MAP='{"office-standard": "ENTERPRISEPACK"}'
```

Notes:

- `IAM_ENTRA_DOMAIN` builds userPrincipalNames: username
  `ada.lovelace` becomes `ada.lovelace@your-tenant.onmicrosoft.com`.
  A username that already contains `@` is used as-is.
- New accounts are created with
  `forceChangePasswordNextSignIn=true`, so the temporary password
  is single-use by design. For a production rollout, prefer the
  invitation or self-service password reset flow instead of a shared
  temporary password.
- Licence mapping: find your tenant's skuPartNumbers in the Entra
  admin center (**Billing → Licenses**) or by calling
  `GET /subscribedSkus` with Graph Explorer. An unmapped licence
  name is a loud error at run time, never a guess.

## 5. Dry run first, then a real run

```bash
# See the plan for two demo hires, changing nothing in the tenant
python -m iam_agent.cli --provider entra --dry-run

# Review what the tenant already holds
python -m iam_agent.cli --provider entra --review

# Create one real user (asks a human first, audits everything)
python -m iam_agent.cli --provider entra --hires hires.csv
```

`--auto-approve` exists for scripted tests only. Against a real
tenant, always let a human approve.

## 6. What to check after the first run

- The user exists in Entra with the right department and job title.
- Group memberships match `policies.json`.
- The licence was assigned (remember: in Entra, a licence is
  assigned separately from account creation, exactly as in the admin
  center's "Create new user" flow).
- The audit log (JSONL or the SQLite store) shows the approve entry
  with who approved it.

## Troubleshooting

- **"Insufficient privileges"** — admin consent was not granted, or a
  permission from step 2 is missing. Check the app's API permissions.
- **"Request_ResourceNotFound" for a group** — the group display
  name in `policies.json` does not exactly match a group in the
  tenant. Group lookup is by exact display name.
- **Licence errors** — the skuPartNumber is not subscribed in the
  tenant, or the licence map is missing an entry.
- **Token errors** — tenant ID, client ID, or secret is wrong, or
  the secret expired. Rotate it and update the environment.
