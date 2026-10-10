# Digital Chain of Custody

A small Flask application for recording the chain of custody of digital evidence.
It does four things:

1. **Hashes evidence.** Every upload is hashed with SHA-256 as it is written to disk. The hash is stored on the evidence record.
2. **Enforces roles.** Investigators, reviewers and admins can each do different things, and every route checks the role.
3. **Keeps a tamper-evident log.** Every action goes into an append-only audit log. Each entry includes the hash of the entry before it, so any edit or deletion can be detected.
4. **Issues PDF certificates.** It generates a certificate of custody with ReportLab, listing the file hash, the integrity checks and every custody event.

The scope is deliberately small: one Flask app, three tables and a few hundred lines of application code, so the whole thing can be read in one sitting.

## Quick start

```bash
cp .env.example .env        # then edit every value in .env
docker compose up --build
```

Open <http://127.0.0.1:8000> and sign in with `ADMIN_USERNAME` / `ADMIN_PASSWORD` from `.env`. As admin, create at least two investigators and one reviewer. The admin role cannot touch evidence (see the roles table below).

Useful commands:

```bash
docker compose exec web flask verify-log                      # check the whole hash chain
docker compose exec web flask verify-log --expect-head <hash> # also detect truncation (see below)
docker compose exec web flask create-user carol investigator  # prompts for a password
```

### Running the tests

```bash
pip install -r requirements-dev.txt
pytest
```

The tests use SQLite in a temporary directory, so they do not need Docker or Postgres.

## Roles

Permissions are declared in one table, `PERMISSIONS` in `app/auth.py`. Every view is wrapped in `@require("<permission>")`.

| Permission          | investigator | reviewer | admin |
|---------------------|:-----------:|:--------:|:-----:|
| `evidence.view`     | ✓ | ✓ |   |
| `evidence.create`   | ✓ |   |   |
| `evidence.transfer` | ✓ (only the current custodian, only to another active investigator) | | |
| `evidence.verify`   | ✓ | ✓ |   |
| `certificate.issue` | ✓ | ✓ |   |
| `audit.view`        |   | ✓ | ✓ |
| `users.manage`      |   |   | ✓ |

The admin role is kept away from evidence on purpose (separation of duties). The account that can create users cannot also handle evidence or rewrite custody. Denied requests return `403` and are themselves written to the audit log as `access.denied`.

## Architecture

```
 browser ──HTTP──▶ gunicorn (3 workers) ──▶ Flask app
                                              │
         ┌───────────────┬────────────────────┼───────────────────┐
         ▼               ▼                    ▼                   ▼
   auth.py          routes.py            services.py        certificate.py
   login, RBAC      thin views           ingest / transfer  ReportLab PDF
   (@require)                            / verify
                                              │
                         ┌────────────────────┴─────────────┐
                         ▼                                  ▼
                    hashing.py                          audit.py
                    streamed SHA-256,                   append(), verify_chain(),
                    write-once files                    append-only guards
                         │                                  │
                         ▼                                  ▼
               /data/evidence volume               PostgreSQL: users, evidence,
               (files named by UUID, mode 0440)    audit_log (+ triggers)
```

| File | Responsibility |
|------|----------------|
| `app/hashing.py` | Hashes files in 1 MiB chunks. `store_and_hash` hashes the exact bytes it writes, refuses to overwrite an existing file (`open(..., "xb")`), fsyncs, and then makes the file read-only. |
| `app/audit.py` | Builds and verifies the hash chain, and installs the guards that stop the log being modified. |
| `app/services.py` | Business operations. Each one writes its audit entry in the same database transaction as the change it records, so you never get a change without a log entry or a log entry without a change. |
| `app/auth.py` | Login, logout, the permission table and the `@require` decorator. |
| `app/certificate.py` | Builds the PDF certificate. |
| `app/routes.py` | HTTP views. |

**Custody events are audit-log entries.** There is no separate custody table. Upload, transfer, verify and certificate issue are all entries in the hash chain, filtered by `evidence_id`. This means the custody history is protected by the same chain as everything else. `evidence.custodian_id` is only a convenience pointer.

### The audit hash chain

Each row in `audit_log` stores:

```
id, timestamp, actor, action, evidence_id, details (canonical JSON), prev_hash, entry_hash
entry_hash = SHA-256( canonical_json({id, timestamp, actor, action, evidence_id, details, prev_hash}) )
```

- The first entry has a `prev_hash` of 64 zeros. `id` is set explicitly to the previous id + 1, so it is also covered by the hash.
- `verify_chain()` walks the whole log in order. For each entry it recomputes the hash, checks the link to the previous entry and checks that the ids have no gaps. It reports exactly which entry failed.
- **Concurrent writers.** On PostgreSQL, `append()` takes a transaction-scoped advisory lock before reading the newest entry, so writers queue up instead of racing. `prev_hash` is also `UNIQUE`, so even if the lock were bypassed the chain could not fork. This was tested with 30 concurrent requests spread across 3 gunicorn workers.
- **Guards against modification.** The application has no update or delete path for log entries. An ORM `before_flush` hook raises an error on any update or delete of an `AuditEntry`. Database triggers reject `UPDATE`, `DELETE` and, on PostgreSQL, `TRUNCATE`. If something gets past all of that, `verify_chain()` detects it.

### Evidence integrity

The SHA-256 of each file is recorded in two places: the `evidence.sha256` column, and the hash-chained `evidence.upload` log entry. Re-verification (`POST /evidence/<id>/verify`) re-hashes the stored file and compares it against both. An attacker who replaces the file *and* edits the column is still caught, because they cannot change the chained copy without breaking the chain.

### Certificate of custody

`POST /evidence/<id>/certificate` re-hashes the file, verifies the whole chain, and renders a PDF containing:

- the evidence metadata
- the acquisition hash and the hash computed now
- PASS/FAIL for file integrity and for the chain
- the current head hash of the chain
- a table of every custody event, with the hash of each entry

If any check fails, the PDF says **INTEGRITY CHECK FAILED** and does not use certifying language. The SHA-256 of the generated PDF is then recorded in a `certificate.issue` log entry, so a certificate handed over later can be matched against the log.

A sample certificate generated by the Docker stack is in [`docs/sample-certificate.pdf`](docs/sample-certificate.pdf).

## Threat model (short)

**Assets:** the evidence files, the record of who held them and when, and the credibility of the certificates.

**What can be detected or prevented:**

| Threat | Mitigation |
|---|---|
| A user acts outside their role (for example, a reviewer uploads, or an admin edits evidence) | `@require` on every route. A test fails if any route lacks it, and a role × route matrix test covers every permission. Denials are logged. |
| An investigator takes custody of an item they don't hold | Transfers are only allowed from the current custodian, and only to an active investigator. |
| Evidence file altered or replaced on disk | Re-verification against the SHA-256 in the column and in the chain. Stored files are read-only. Names are random UUIDs, never derived from user input. |
| A log entry is edited, deleted, inserted or reordered with direct DB access | Triggers block casual changes. Any change that gets through breaks `entry_hash` or `prev_hash` linkage and is reported by `verify_chain()`. This is covered by tests that drop the triggers and tamper with the table. |
| An attacker edits an entry *and* recomputes that entry's hash | The next entry's `prev_hash` no longer matches, so the change is still detected. |
| Cross-site request forgery | Flask-WTF CSRF tokens on every POST. Session cookies are `HttpOnly` and `SameSite=Lax`, and `Secure` when `SESSION_COOKIE_SECURE=1`. |
| Untrusted text injected into the UI or the PDF | Jinja autoescaping in the UI. ReportLab markup is escaped in the PDF. |
| Password guessing | Passwords are salted (Werkzeug scrypt) with a 12-character minimum. Failed logins are logged. Disabled accounts cannot sign in. |

**What is *not* defended against** (see the limitations below): an attacker with full DB write access who **rewrites the entire chain** from some point onward, or who **deletes the most recent entries**. A hash chain only proves that the log is internally consistent. Detecting these attacks needs a copy of the head hash stored somewhere the attacker cannot reach.

## Known limitations and out-of-scope

- **No external anchoring.** Truncating the tail of the log, or recomputing the whole chain, passes `verify_chain()` on its own. The building blocks to detect this exist: the head hash is printed on every certificate and in the UI, and `flask verify-log --expect-head` checks that an earlier head is still present. What is missing is automatic publication of the head hash to a write-once store, an RFC 3161 timestamping authority or a transparency log. That is the main next step.
- **The database owner can drop the triggers.** The app connects as the table owner. In production, use a separate DB role that has only `INSERT, SELECT` on `audit_log`, and run migrations as another role.
- **No digital signatures.** Certificates and log entries are hashed but not signed. A hash proves the content is unchanged, not who wrote it. Signing the entries or PDFs (for example with an HSM-held key) is out of scope.
- **Evidence is not encrypted at rest** and is stored on a local Docker volume. There is no backup or replication. Use encrypted volumes and an off-host, write-once backup in any real deployment.
- **Timestamps come from the server clock** and are not independently attested.
- **No case-level access control.** Every investigator and reviewer can see every item. There is no MFA, account lockout or rate limiting.
- **Server-side checks only.** The app hashes what it *receives*. Hashing at acquisition time, on the examiner's workstation, and comparing the two values is a manual step.
- **Schema management is `create_all()`.** There are no migrations (for example Alembic).
- **Evidence is not downloadable through the app,** to keep the attack surface small. Analysts access the volume out of band.
- **Upload size** is capped by `MAX_UPLOAD_MB` (default 512). Gunicorn sync workers will struggle with multi-GB images. Large images should be ingested from disk by a CLI instead.
- **TLS is not included.** Put a reverse proxy in front, and set `SESSION_COOKIE_SECURE=1`. Compose binds the app to `127.0.0.1` only.

## Project layout

```
app/
  __init__.py      app factory, CLI commands (create-user, bootstrap-admin, verify-log)
  models.py        User, Evidence, AuditEntry
  hashing.py       SHA-256 streaming + write-once storage
  audit.py         hash chain, verification, append-only guards
  auth.py          login/logout, PERMISSIONS table, @require
  services.py      ingest, transfer, verify, user admin
  certificate.py   ReportLab certificate
  routes.py        views
  templates/
tests/
  test_hashing.py         known SHA-256 vectors, streaming, write-once storage, tamper detection
  test_access_control.py  role × route matrix, anonymous access, custody rules, CSRF
  test_audit_log.py       chain links, field coverage, ORM/trigger guards, edit/delete/truncate detection, PDF
docs/sample-certificate.pdf
Dockerfile, docker-compose.yml, entrypoint.sh, .env.example
```
