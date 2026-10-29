# IAM Onboarding

One install for one company. Version 1.0.0.

It records who asked for access, who approved it, and what changed. Two people are required: the person who submits a request cannot approve it.

## What a company gets

- A web app. The first visit creates the company name, an admin, and a separate approver. No password is printed.
- A policy file. Roles, groups, licences, conflicts, and which grants count as privileged live there. An admin can edit that file from the Policy page. A bad edit is refused and the previous file stays.
- A built-in directory for a company that does not use Microsoft Entra, including a sample company an admin can load.
- Optional Microsoft Entra for the directory. New accounts are created disabled, then enabled after groups and licences are assigned. Each account gets its own temporary password, shown once to the operator, and must change it at next sign-in. The app role is stored as employee type. A manager is set when the request names one.
- Optional Microsoft sign-in for people who already have an app account. Username and password remain available.
- An audit log of directory changes and app administration. The chain can be checked with the command-line tool.

## Who decides

A standard grant or an offboard needs an approver or an admin who is not the requester. A privileged grant — a privileged role, group, or licence, or a role the policy does not name — needs an admin who is not the requester. Nothing approves itself.

## What this version does not include

A license server, a second database, Google Workspace, live proof against a customer's Entra tenant, access recertification campaigns, HR or ticket ingestion, and a language model. Direct changes in the Entra portal are outside this audit.

## What the buyer still does

Install it on one machine, complete setup with two people, and, if they use Entra, follow ENTRA_SETUP.md on a test tenant before a production tenant.
