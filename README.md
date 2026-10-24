# DetectLab

**Security Detection Testing & Log Analysis**

DetectLab is a small, test-driven detection-engineering lab. It stores security
events in a database, evaluates threshold-based detection rules against them,
and lets you check that a rule fires on a known scenario. It is a learning and
portfolio project, **not** a SIEM, a SOC platform, or a production detection
product.

## What it does today

- Stores hosts and security events (FastAPI + SQLite).
- Stores detection rules written in YAML and validates them on creation.
- Evaluates enabled **threshold** rules over a time window, grouped by fields
  such as host and user.
- Runs **scenarios** (known event sequences) against a rule and records a
  PASS/FAIL result, so detection behavior can be tested repeatedly.
- Reports scenario **coverage** per rule and **regressions** (rules whose latest
  scenario run failed).
- Includes a benchmark for the detection service.

## What it does not do

- It does not collect logs. Events must be submitted through the API.
- It has one detection type (`threshold`) and one shipped rule (`DET-001`).
- There is no authentication, no frontend, no alert lifecycle, no
  deduplication, no suppression and no cross-rule correlation.
- Detection results from `/detections/evaluate` are returned, not stored.
- Rules cannot be updated, deleted or toggled through the API yet.

## Quick start (Windows PowerShell)

Tested with Python 3.13 on Windows.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

python -m app.init_db        # creates data/detectlab.db and its tables
python -m app.seed_rules     # loads rules/*.yaml (idempotent)
python -m uvicorn app.main:app --reload
```

Interactive API docs: <http://127.0.0.1:8000/docs>. Health check:
`GET /health`.

Run the tests:

```powershell
python -m pytest -q
```

### Try the shipped scenario

The scenario targets host `WIN11-LAB` and rule `DET-001`, so create the host
first (in a second terminal):

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/hosts `
  -ContentType "application/json" `
  -Body '{"hostname":"WIN11-LAB","platform":"windows","ip_address":"192.168.56.10"}'

Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8000/api/v1/scenarios/library/SCN-001/run
```

The run inserts five `authentication_failure` events for one user into the
database, evaluates the rules, and saves the result. Then:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/v1/scenarios/runs
Invoke-RestMethod http://127.0.0.1:8000/api/v1/coverage
Invoke-RestMethod http://127.0.0.1:8000/api/v1/regressions
```

Scenario runs write real events and run records to the configured database.

## Architecture

```
rules/*.yaml ──seed──▶ rules table (YAML stored in definition_yaml)
POST /events ────────▶ events table (timestamps normalized to UTC)
                              │
POST /detections/evaluate     ▼
   service.evaluate_enabled_rules
     1. load enabled rules, parse YAML, skip invalid ones (with a reason)
     2. query events newer than (evaluation_time - largest rule window)
     3. normalize timestamps to aware UTC
     4. engine.evaluate_threshold for each rule
     5. return detections + rules_evaluated + rules_skipped
```

| Path | Responsibility |
|---|---|
| `app/main.py` | FastAPI app and router registration |
| `app/models.py`, `app/database.py` | SQLAlchemy models, SQLite connection |
| `app/schemas.py` | Request and response models |
| `app/detection/engine.py` | Rule validation and threshold evaluation |
| `app/detection/service.py` | Database-backed evaluation of enabled rules |
| `app/detection/rule_validator.py` | Validation of YAML rules at creation time |
| `app/detection/scenario.py`, `scenario_library.py` | Scenario runner and YAML scenario loader |
| `app/seed_rules.py` | Loads `rules/*.yaml` into the database |
| `rules/` | Shipped detection rules |
| `scenarios/` | Shipped test scenarios |
| `benchmarks/` | Detection service benchmark |

## Rule format

```yaml
id: DET-001                  # must match the file name and the API rule_id
name: Multiple Failed Logins
description: Detects repeated failed authentication attempts.
platform: windows
severity: medium
mitre_technique: T1110.001   # optional metadata
condition:
  type: threshold            # the only supported type
  event_type: authentication_failure
  count: 5                   # positive integer
  window_seconds: 60         # positive integer
  group_by:                  # non-empty, unique field names
    - host
    - user
```

Required: `id`, `name`, `description`, `platform`, `severity`, `condition`.
Rules with any other condition type are rejected at creation time.
`group_by` fields are looked up on the event (`host`) or inside `event_data`
(for example `user`).

## Detection semantics

These behaviors are covered by tests:

- The window is `(evaluation_time - window_seconds, evaluation_time]`: an event
  exactly at the start is excluded, an event exactly at the evaluation time is
  included, and future events are excluded.
- Events are grouped by the combination of all `group_by` values. Different
  hosts or users produce separate detections.
- A group triggers when its event count is **at least** `count`. More events than
  the threshold still produce one detection per group.
- Events with a missing group field, a naive or non-datetime timestamp, or an
  unhashable group value are ignored.
- One invalid rule is skipped (and reported) without stopping the others.
- Evaluation time must be timezone-aware. Event timestamps submitted through the
  API must include a timezone and are converted to UTC before storage.

A detection looks like this:

```json
{
  "rule_id": "DET-001",
  "count": 5,
  "threshold": 5,
  "window_seconds": 60,
  "window_start": "2026-10-24T11:59:00Z",
  "window_end": "2026-10-24T12:00:00Z",
  "group": {"host": "WIN11-LAB", "user": "scenario-test-user"}
}
```

The engine evaluates one window ending at the evaluation time; it does not
slide the window across history.

## Shipped rule: DET-001, Multiple Failed Logins

Fires when five or more `authentication_failure` events for the same host and
user fall inside a 60-second window.

- **Useful for:** spotting rapid repeated failed logins (MITRE T1110.001,
  password guessing).
- **Does not establish** that an attack occurred. It is a signal that needs
  context.
- **Possible false positives:** stale saved credentials, misconfigured services,
  users mistyping passwords.
- **Does not catch:** slow guessing spread over more than 60 seconds, or
  guessing across many accounts from one host.
- It counts every `authentication_failure` event; the rule file lists a `status`
  field but the engine does not filter on it.

## API

All routes are under `/api/v1` except `/health`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Health check |
| POST, GET | `/hosts` | Create / list hosts |
| POST, GET | `/rules` | Create (validated) / list rules |
| POST, GET | `/events` | Ingest / list events |
| POST | `/detections/evaluate` | Evaluate enabled rules at a given time (not persisted) |
| POST | `/detections/validate` | Check that an expected rule detects on an expected host |
| POST | `/scenarios/run` | Run an inline scenario and save the result |
| POST | `/scenarios/library/{scenario_id}/run` | Run a scenario from `scenarios/` |
| GET | `/scenarios/runs`, `/scenarios/runs/{run_id}` | Scenario run history |
| GET | `/coverage` | Scenario coverage per rule |
| GET | `/regressions` | Rules whose latest scenario run failed |

## Testing

`python -m pytest -q` runs the full suite (engine, service, API, rule
validation, scenarios, seeding). Passing tests show the behaviors above work as
specified; they are not a measure of how complete the project is.

## Benchmark

```powershell
python -m benchmarks.benchmark_detection_service
```

Runs the detection service against an **in-memory** SQLite database with
5, 10 and 20 rules and 1,000, 5,000 and 10,000 events, in a
historical-heavy workload (only five recent events) and a recent-heavy workload
(80% recent), and reports median wall-clock time over five runs. Timings depend
on the machine and are for comparing code changes on identical workloads, not
for absolute capacity claims. The benchmark checks that all rules are evaluated
and none skipped; it does not compare detection outputs between implementations.

Design note: limiting the database query to the largest active rule window
keeps historical-heavy runtime nearly flat as stored events grow. An in-memory
event-type index was tried and removed because it showed no consistent
speedup on the same benchmark.

## Known limitations

- SQLite only; no migrations (tables are created with `create_all`).
- One condition type, one shipped rule.
- No authentication or authorization; do not expose the API to untrusted
  networks.
- The database URL is hard-coded in `app/database.py`.

## License

See `LICENSE`.
