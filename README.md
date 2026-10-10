# Digital Chain of Custody

A small Flask application for recording the chain of custody of digital evidence, and for examining that evidence without changing it.
It does six things:

1. **Hashes evidence.** Every file is hashed with SHA-256 as it is written to disk. The hash is stored on the evidence record. If you supply the hash from your imaging tool, a file that doesn't match is rejected.
2. **Enforces roles and cases.** Investigators, reviewers and admins can each do different things, and every route checks the role. Users only see evidence in cases they are assigned to.
3. **Keeps a tamper-evident log.** Every action goes into an append-only audit log. Each entry includes the hash of the entry before it and is signed with the server's Ed25519 key. A signed copy of the latest hash is also written outside the database at regular intervals. Editing, deleting, rewriting or truncating the log can all be detected.
4. **Lets investigators analyse evidence read-only.** The tools are file-type identification, hashes and entropy, a hex viewer, strings extraction and keyword search. Findings are saved into the signed log. For external tools, the current custodian can export a working copy, and the hash is verified first.
5. **Issues PDF certificates.** It generates a certificate of custody with ReportLab, listing the file hash, the integrity checks and every custody event. Anyone with access can later check whether a given PDF is genuine.
6. **Secures accounts and automation.** It supports authenticator-app two-factor login, account lockout, and forced password changes. A token-authenticated JSON API and a command-line import cover large files and scripting.

The scope is still deliberately small: one Flask app, six tables and no background workers, so the whole thing can be read in an afternoon.

> **Upgrading from v1:** v2 adds cases and signed audit entries, so it needs a fresh database. The app refuses to start on a v1 database and tells you so. Delete the `instance/` folder (local) or run `docker compose down -v` (Docker).

## Quick start

### Docker (Postgres, gunicorn, anchor service)

```bash
cp .env.example .env        # then edit every value in .env
docker compose up --build
```

Open <http://127.0.0.1:8000> and sign in with `ADMIN_USERNAME` / `ADMIN_PASSWORD` from `.env`.

### Local, without Docker (SQLite)

macOS / Linux:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
export SECRET_KEY=dev-secret
python -m flask --app wsgi create-user admin admin    # prompts for a password (12+ chars)
python -m flask --app wsgi run                        # http://127.0.0.1:5000
```

Windows PowerShell:

```powershell
python -m venv .venv; .venv\Scripts\Activate.ps1      # if blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
pip install -r requirements-dev.txt
$env:SECRET_KEY = "dev-secret"                        # needed in every new PowerShell window
python -m flask --app wsgi create-user admin admin
python -m flask --app wsgi run
```

Local data (database, evidence, signing key, anchors) lives in `instance/`.

### First steps in the app

1. **As admin:** go to **Users** and create investigators and a reviewer. Each one must choose their own password at first sign-in. Then go to **Cases**, create a case and add the users as members.
2. **As an investigator:** **Upload** a file into your case. Open it, then click **Analyse (read-only)** to run the tools and record findings. Use **Transfer custody** to hand it to another investigator on the case.
3. **As a reviewer:** re-verify the hash, download the **custody certificate**, and check the **Audit log** page.
4. **Optional:** turn on two-factor login on the **Account** page (click your username), and create API tokens there.

### Command line

| Command | What it does |
|---|---|
| `flask verify-log` | Checks every entry's hash, link and signature, and every anchor. Exits with status 1 on failure. |
| `flask verify-log --expect-head <hash>` | As above, and also checks that an earlier head hash (for example, one printed on a certificate) is still in the log. |
| `flask anchor` | Writes a signed record of the current log head to `ANCHOR_FILE`. The Docker `anchor` service runs this every `ANCHOR_INTERVAL` seconds. |
| `flask ingest FILE --case C-1 --description "..." --as alice [--expected-sha256 HEX]` | Imports a file from disk with no upload size limit. With Docker, put the file in `./ingest/` and use the path `/ingest/<file>`. |
| `flask verify-certificate FILE.pdf` | Checks that this exact PDF was issued here and that its log entry is intact. |
| `flask create-user NAME ROLE` | Creates a user. Prompts for the password. |

With Docker, prefix each command with `docker compose exec web`.

### Running the tests

```bash
pip install -r requirements-dev.txt
pytest
```

There are 172 tests. They use SQLite in a temporary directory, so they need neither Docker nor Postgres. They run in about 20 seconds.

## Roles and cases

Permissions are declared in one table, `PERMISSIONS` in `app/auth.py`. Every view, in both the web UI and the API, is wrapped in `@require("<permission>")`. A test fails if any route is missing it.

| Permission | investigator | reviewer | admin |
|---|:-:|:-:|:-:|
| `cases.view`, `evidence.view` | ✓ | ✓ | |
| `evidence.create` | ✓ | | |
| `evidence.transfer` | ✓ (current custodian only, to another investigator on the case) | | |
| `evidence.verify` | ✓ | ✓ | |
| `evidence.analyze` (tools and findings) | ✓ | | |
| `evidence.export` | ✓ (current custodian only) | | |
| `certificate.issue`, `certificate.verify` | ✓ | ✓ | |
| `audit.view` | | ✓ | ✓ |
| `cases.manage`, `users.manage` | | | ✓ |
| `account.self` (password, 2FA, API tokens) | ✓ | ✓ | ✓ |

**Case membership is checked on top of the role.** Every evidence lookup goes through `services.get_evidence_for(user, id)`, which returns *404 Not Found* for evidence in a case the user is not on. A user on a different case cannot even confirm that an item exists.

**The admin role never touches evidence** (separation of duties). Admins create users and cases and assign members, but cannot view, upload, analyse or transfer evidence. Denied requests return `403` and are written to the audit log as `access.denied`.

## Architecture

```
 browser ─┐                                   ┌─ anchor service (every N s)
 API client ─HTTP─▶ gunicorn (3 workers) ─▶ Flask app        │
 flask ingest (CLI) ──────────────────────────┤               │
                                              ▼               ▼
   auth.py / account.py      routes.py / api.py         services.py ─▶ certificate.py
   login, lockout, 2FA,      web views / JSON API       cases, ingest,    ReportLab PDF
   PERMISSIONS, @require     (same @require, same       transfer, export,
                              services underneath)      tokens, 2FA
                                              │
               ┌──────────────────────────────┼─────────────────────────────┐
               ▼                              ▼                             ▼
          hashing.py                     analysis.py                    audit.py ◀── signing.py
          streamed SHA-256,              read-only tools:               hash chain,      Ed25519 key
          write-once files               identify, profile, hex,        signatures,      (SIGNING_KEY_PATH)
               │                         strings, search                anchors, guards
               ▼                              │                             │            │
     /data/evidence (UUID names, 0440) ◀──────┘          PostgreSQL ◀────────┘            ▼
                                                         users, cases, evidence,   /data/anchors/anchors.jsonl
                                                         api_tokens, audit_log     (signed heads; keep off-host)
```

| File | Responsibility |
|------|----------------|
| `app/hashing.py` | Hashes files in 1 MiB chunks. `store_and_hash` hashes the exact bytes it writes, refuses to overwrite an existing file, fsyncs, and makes the file read-only. |
| `app/audit.py` | The hash chain, the signatures, the anchors, full verification, and the guards that stop the log being modified. |
| `app/signing.py` | Loads or creates the Ed25519 key, and signs and verifies. |
| `app/analysis.py` | Read-only analysis tools. They open the file `rb` and work through it in chunks, so multi-GB images are fine. |
| `app/services.py` | All business operations, shared by the web UI, the API and the CLI. Each one writes its audit entry in the same transaction as the change it records. |
| `app/auth.py`, `app/account.py` | Login with lockout and 2FA, the permission table, `@require`, forced password change, and the account pages. |
| `app/routes.py`, `app/api.py` | Web views and the JSON API. Both are thin layers over `services.py`. |
| `app/certificate.py` | Builds the PDF certificate. |

**Custody events are audit-log entries.** There is no separate custody table. Upload, transfer, verification, analysis, findings, export and certificate issue are all entries in the signed hash chain, filtered by `evidence_id`. `evidence.custodian_id` is only a convenience pointer.

### The audit log: chain, signatures, anchors

Each row in `audit_log` stores:

```
id, timestamp, actor, action, evidence_id, details (canonical JSON), prev_hash, entry_hash, key_id, signature
entry_hash = SHA-256( canonical_json({id, timestamp, actor, action, evidence_id, details, prev_hash}) )
signature  = Ed25519_sign(server key, entry_hash)
```

The three layers each close a different gap:

| Layer | Detects | Can't detect on its own |
|---|---|---|
| **Hash chain** (`prev_hash`) | Editing, deleting, inserting or reordering an entry | Someone with database access recomputing *every* hash from the edit onward |
| **Signatures** (key file, not in the DB) | The above, even with every hash recomputed, because a valid signature needs the key | Deleting the newest entries: what's left is still validly signed |
| **Anchors** (signed `{entry_id, head_hash}` lines in `ANCHOR_FILE`) | Truncation: every anchored entry must still exist with the same hash | Entries written after the most recent anchor |

`verify_chain()` checks all three and reports exactly which entry or anchor line failed. It runs on the Audit log page, before every certificate, in `flask verify-log`, and at `GET /api/v1/audit/verify`.

To catch truncation of recent entries, anchors are written in two ways. The Docker `anchor` service writes one every `ANCHOR_INTERVAL` seconds (default 300), skipping the write when nothing has changed. Every certificate issue also writes one immediately, so a certificate's own log entry is always anchored.

The rest works as in v1:
- **Concurrent writers:** a PostgreSQL advisory lock, plus `UNIQUE(prev_hash)` so the chain can never fork.
- **Database guards:** an ORM hook and triggers that reject `UPDATE`, `DELETE` and `TRUNCATE`.

All of this was tested against Postgres with concurrent requests across three gunicorn workers.

### Evidence integrity

The SHA-256 of each file is recorded in two places: the `evidence.sha256` column, and the signed `evidence.upload` log entry. Re-verification, export and certificates all re-hash the stored file and compare it against both.

At ingest you can supply the **acquisition hash** from your imaging tool (FTK Imager, dc3dd, and so on). You can do this in the upload form, with the API's `expected_sha256` field, or with `flask ingest --expected-sha256`. If the hashes differ, the file is rejected and deleted, and the rejection is logged.

### Analysis (read-only)

The original file is never opened for writing. Each tool run is logged with its parameters (`analysis.run`), so the custody record shows who looked at what.

| Tool | What it does |
|---|---|
| **Identify** | Detects the file type from magic bytes: E01, NTFS/FAT/ext volumes, MBR disk images, ISO, ZIP/Office, OLE, PE/ELF executables, SQLite, registry hives, EVTX, pcap, archives, images, PDF. |
| **Hashes and entropy** | MD5 and SHA-1 (for matching against hash sets such as NSRL) plus SHA-256, all in one pass. Also Shannon entropy, a hint that the data is encrypted or compressed. About 5 s/GB. |
| **Hex viewer** | Any offset, up to 4 KiB per page, with previous/next paging. |
| **Strings** | ASCII and UTF-16LE (Windows) strings with byte offsets, paginated. |
| **Keyword search** | Case-insensitive search as both ASCII and UTF-16LE. Each hit shows its offset and context, with a link to the hex view. |
| **Findings** | Free-text notes written into the signed chain. They cannot be edited or deleted, and they appear on the certificate. |
| **Export working copy** | Current custodian only. The stored file is re-hashed first. On a mismatch the export is refused and the refusal is logged. |

Strings extraction and search work through the file in chunks. A property test checks that they return identical results with chunk sizes from 7 bytes to 1 MiB, so a match is never lost at a chunk boundary.

### Certificate of custody

`POST /evidence/<id>/certificate` re-hashes the file, verifies the whole log (chain, signatures, anchors), and renders a PDF. The PDF contains:
- the case and evidence metadata
- the acquisition hash and the hash computed now
- PASS/FAIL for file integrity and for the log
- the log head
- the signing key ID
- every custody event, with the hash of each entry

If any check fails, the PDF says **INTEGRITY CHECK FAILED** and does not use certifying language.

After rendering, the server records the PDF's SHA-256 in a signed `certificate.issue` entry and writes an anchor. To check a certificate later, use **Verify certificate** in the UI, `POST /api/v1/certificates/verify`, or `flask verify-certificate`. Changing even one byte of the PDF makes the check fail. Users who aren't on the case are told whether the certificate is genuine, but not which evidence it covers.

A sample certificate generated by the Docker stack is in [`docs/sample-certificate.pdf`](docs/sample-certificate.pdf).

### Accounts

- **Lockout:** after `MAX_FAILED_LOGINS` failures (default 5), whether wrong passwords or wrong 2FA codes, the account is locked for `LOCKOUT_MINUTES` (default 15). While locked, even the correct password is refused. Admins can unlock an account.
- **Two-factor login (TOTP):** works with any authenticator app; enrol by scanning a QR code on the Account page. Clock drift of ±30 s is allowed, and each code works only once. Set `REQUIRE_2FA=1` to make every user enrol before using the system.
- **Password changes:** admin-created accounts and admin password resets require the user to choose a new password at the next sign-in. A reset also unlocks the account and revokes its API tokens.

### JSON API

Create a token on the Account page. The token is shown once, and only its SHA-256 is stored. Send it as `Authorization: Bearer <token>` to `/api/v1/...`:

```bash
H="Authorization: Bearer coc_..."
curl -H "$H" http://127.0.0.1:8000/api/v1/cases
curl -H "$H" -F case=C-1 -F description="SSD image" -F expected_sha256=<hex> -F file=@disk.dd http://127.0.0.1:8000/api/v1/evidence
curl -H "$H" -X POST -H "Content-Type: application/json" -d '{"keyword":"password"}' http://127.0.0.1:8000/api/v1/evidence/1/analysis/search
curl -H "$H" -X POST -o cert.pdf http://127.0.0.1:8000/api/v1/evidence/1/certificate
```

These are the endpoints. Each one checks the same permission as the matching web page.

| Method and path | Purpose |
|---|---|
| `GET /me` | The user the token belongs to. |
| `GET /cases` | Your cases. |
| `GET /evidence[?case=]` | Evidence in your cases, optionally for one case. |
| `POST /evidence` | Upload evidence. |
| `GET /evidence/<id>` | One item, including its events. |
| `POST /evidence/<id>/verify` | Re-verify the hash. |
| `POST /evidence/<id>/transfer` | Transfer custody. |
| `POST /evidence/<id>/analysis/<tool>` | Run an analysis tool. |
| `POST /evidence/<id>/notes` | Add a finding. |
| `POST /evidence/<id>/export` | Download a verified working copy. |
| `POST /evidence/<id>/certificate` | Issue a certificate. |
| `POST /certificates/verify` | Check a certificate. |
| `GET /audit/verify` | Verify the whole audit log. |

The API **ignores the session cookie**. A logged-in browser gets `401` from it. This is what makes it safe to exempt the API from CSRF tokens: a malicious site can make your browser send cookies, but it can't make it send your token.

## Threat model (short)

**Assets:** the evidence files, the record of who held and examined them, and the credibility of the certificates.

**What can be detected or prevented:**

| Threat | Mitigation |
|---|---|
| A user acts outside their role | `@require` on every web and API route. Matrix tests cover every role × route, and a test fails if a route lacks the decorator. Denials are logged. |
| A user reads evidence from someone else's case | Every lookup is scoped to the user's case memberships and returns 404 otherwise. Tests cover each evidence route and the API. |
| Evidence altered on disk, or between acquisition and upload | Re-hash against the column and the signed log entry. An optional acquisition hash is checked at ingest. Analysis is read-only, and export is refused on a mismatch. |
| A log entry is edited, deleted, inserted or reordered | The hash chain detects it. |
| The **whole chain is rewritten** with recomputed hashes (database access, no key) | Signatures fail. *(Tested.)* |
| The **newest entries are deleted** | Anchors outside the database no longer match. *(Tested, including against Postgres via `psql`.)* |
| The anchor file is edited to hide a truncation | Anchors are signed, so an edited anchor fails verification. |
| A forged or edited certificate PDF | Its SHA-256 isn't in any signed `certificate.issue` entry. |
| Password guessing or credential stuffing | Account lockout, optional or required TOTP, a 12-character minimum, scrypt hashing, and logged failures. |
| A stolen password | TOTP. Admin resets revoke API tokens. |
| CSRF | CSRF tokens on every form. The API refuses cookies. `SameSite=Lax`, `HttpOnly`, and `Secure` when `SESSION_COOKIE_SECURE=1`. |
| Injection into the UI or the PDF | Jinja autoescaping. ReportLab markup escaping. Uploaded file names are reduced to their base name and never used as storage paths. |

**What is still *not* defended against** (see the limitations below):
- An attacker who controls the **app server**, and so holds the signing key and can write anchors.
- An attacker who deletes entries written **after the last anchor**.
- Anything that happens to the evidence **before** it reaches the app.

## Known limitations and out-of-scope

- **The signing key sits on the app server.** It's a file on its own volume, so database-only access isn't enough to forge entries. But anyone with root on the app host has it. For real use, keep the key in an HSM or a cloud KMS and rotate it. Rotation isn't implemented: entries signed by an earlier key would fail verification.
- **Anchors are only as safe as where you put them.** In Docker they're on a separate volume on the same host. Point `ANCHOR_FILE` at storage the app and database hosts can't rewrite, such as a WORM bucket or a different server. Better still, timestamp anchors with an RFC 3161 authority or publish them to a transparency log; neither is implemented. Entries written after the most recent anchor can still be truncated without detection.
- **The database owner can drop the triggers.** The app connects as the table owner. In production, use a role that has only `INSERT, SELECT` on `audit_log`.
- **Lockout can be abused.** Anyone who knows a username can lock that account for 15 minutes. There's no per-IP rate limiting; put a reverse proxy with rate limits in front.
- **Analysis runs in the request.** Hashing a 10 GB image takes about 50 s and holds a gunicorn worker the whole time. There's no job queue. For very large images, use the CLI, or export a working copy to a forensic suite (Autopsy, X-Ways and so on).
- **The analysis tools work on the raw file.** They don't parse filesystems, carve deleted files or look inside E01/AFF containers. They identify and inspect; the export is for deeper work.
- **Evidence is not encrypted at rest,** and there's no backup or replication.
- **Timestamps come from the server clock** and are not independently attested.
- **Schema management is `create_all()`.** There are no migrations. v1 → v2 needs a fresh database.
- **Uploads through the browser or API** are capped by `MAX_UPLOAD_MB` (default 512). `flask ingest` has no cap.
- **TLS is not included.** Put a reverse proxy in front and set `SESSION_COOKIE_SECURE=1`. Compose binds the app to `127.0.0.1` only.

## Project layout

```
app/
  __init__.py      app factory, config, CLI (create-user, bootstrap-admin, verify-log, anchor, ingest, verify-certificate)
  models.py        User, Case, Evidence, ApiToken, AuditEntry
  hashing.py       SHA-256 streaming + write-once storage
  signing.py       Ed25519 key handling
  audit.py         hash chain, signatures, anchors, verification, append-only guards
  analysis.py      read-only tools: identify, profile, hexdump, strings, search
  auth.py          login (lockout, 2FA), PERMISSIONS, @require, forced account setup
  account.py       password change, 2FA enrolment, API tokens
  services.py      all business operations (web, API and CLI share them)
  certificate.py   ReportLab certificate
  routes.py        web views
  api.py           JSON API (token auth only)
  templates/
tests/
  test_hashing.py           SHA-256 vectors, streaming, write-once storage, tamper detection
  test_access_control.py    role × route matrix, anonymous access, custody rules, CSRF
  test_cases.py             case isolation (404s), membership rules, v1-database refusal
  test_account_security.py  lockout, TOTP enrolment/login/replay, forced password change, token revocation
  test_audit_log.py         chain links, field coverage, ORM/trigger guards, tamper detection, PDF
  test_signing_anchors.py   signatures, whole-chain rewrite, truncation, anchor tampering, certificate verification
  test_analysis.py          file signatures, hashes/entropy, hex, strings/search incl. chunk-boundary property test, export
  test_api.py               token auth, cookie refusal, roles/cases via API, end-to-end flow
  test_ingest_cli.py        large-file ingest, acquisition-hash mismatch, CLI verification
docs/sample-certificate.pdf
Dockerfile, docker-compose.yml, entrypoint.sh, .env.example, ingest/
```
