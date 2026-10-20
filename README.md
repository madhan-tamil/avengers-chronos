# Avengers: Project CHRONOS

## Overview

Project CHRONOS is a time-themed web exploitation CTF
inspired by the Avengers universe.

Players investigate an unstable interface, discover
incident evidence, examine timestamped logs, and
investigate a legacy authorization workflow.

The intended vulnerability is a race condition in
single-use lease redemption.

## Technology

- Python
- Flask
- SQLite
- HTML, CSS and JavaScript
- Podman and Compose
- Pytest

## Local Setup

Install Podman and podman-compose, then prepare `.env`
using `.env.example` as a reference.

Generate separate session and receipt-signing secrets.
Set a unique local flag.

Start the service:

    podman compose up --build -d

Check the health endpoint:

    curl http://127.0.0.1:5000/healthz

## Tests

Run the race test only when vulnerable mode is enabled:

    python tools/test_race.py http://127.0.0.1:5000

Run receipt integrity checks in vulnerable mode:

    python tools/test_integrity.py

Run the secure-mode concurrency test only when secure
mode is enabled:

    python tools/test_secure.py http://127.0.0.1:5000

Expected secure-mode behavior: one redemption succeeds
and the competing redemption is rejected.

## Security Notes

The intentionally vulnerable mode is for an isolated,
authorized CTF environment only.

Do not expose the development instance directly to
the public internet.

Never commit `.env`, signing keys, real flags, database
files, or maintainer-only solution documents.

The player-facing challenge description must be
distributed separately from the source and solution.
