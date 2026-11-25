# Security

## Reporting a vulnerability

Report a vulnerability through the private vulnerability reporting of GitHub:
the button "Report a vulnerability" on the Security tab of this repository.

## Supported versions

Security fixes go into `main`. Earlier commits and images get no fixes.

## Scope

These faults are in scope:

- A bypass of the sign-in of `rsim-api`, of a session, of an API token or of the sign-in lockout.
- A device credential, a sealed secret of a managed credential or the key `RSIM_SECRET_KEY` that is readable through the API, the UI, a log or an error.
- A read or a write of the snapshot store or the inventory database outside the API operations.
- A bypass of the SSH host-key check or the TLS check of `rsim-collect`.
