# CHRONOS — Maintainer Solution

## Intended solve path

1. Observe the unstable landing page.
2. Inspect frontend source and discover the incident
   manifest reference.
3. Read the incident manifest and identify the
   diagnostic API and timeline log.
4. Correlate the synthetic event timestamps.
5. Investigate the lease issuance and redemption workflow.
6. Obtain one legitimate lease.
7. Demonstrate that sequential redemption is rejected.
8. Send two synchronized redemption requests using the
   same session and lease.
9. Verify that vulnerable mode produces two different
   signed receipt IDs.
10. Submit both receipts to the mission endpoint.
11. Verify that the archive returns the configured flag.

## Intended vulnerability

The legacy redemption handler checks whether a lease
has been consumed, waits, and then updates the state
without an atomic conditional update.

Two concurrent requests can both pass the initial check.

## Required validation

The archive requires two distinct receipt IDs, valid
signatures, and the current session identity.

The two receipts are allowed to reference the same
lease ID. This is necessary for the intended exploit.

## Expected negative tests

- A second sequential redemption must fail.
- A second lease in the same session must be rejected.
- A duplicated receipt ID must be rejected.
- A tampered signature must be rejected.
- Receipts from another session must be rejected.
- Secure mode must allow only one concurrent redemption.
