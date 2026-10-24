# Adding a rule and a scenario

This guide walks through adding a detection rule to DetectLab, proving it with
a scenario, and checking that the tests and coverage report pick it up. It uses
the shipped rules (`DET-001` to `DET-003`) as the pattern.

## 1. Decide what you are detecting

Write down, before any YAML:

- **The behavior.** For example "ten failed SSH logins from one IP in two
  minutes".
- **The event type.** Events are matched on an exact `event_type` string such as
  `authentication_failure`. DetectLab does not parse real log formats, so you
  define the event type and the fields inside `event_data`.
- **The grouping.** Which fields identify "the same actor"? They go in
  `group_by` (`host` is a built-in field; others are looked up in
  `event_data`).
- **Counting events or distinct values.** Add `distinct_field` to count
  distinct values (for example distinct users) instead of events.
- **A false-positive story** and what the rule will **not** catch. Write these
  in the README section for the rule.

Only `threshold` rules are supported. If the behavior cannot be expressed as
"at least N events (or distinct values) per group inside one window", the
engine needs a new feature first.

## 2. Write the rule file

Create `rules/DET-004.yaml`. The file name (without `.yaml`) **must equal the
`id`**, or seeding rejects it.

```yaml
id: DET-004
name: Short Rule Name
description: One sentence about what it detects.
platform: windows            # free text, e.g. windows or linux
severity: medium
mitre_technique: T1110.001   # optional
condition:
  type: threshold
  event_type: authentication_failure
  count: 5                   # positive integer
  window_seconds: 60         # positive integer
  group_by:                  # non-empty, unique
    - host
    - user
  # distinct_field: user     # optional; must not also be in group_by
```

Required top-level fields: `id`, `name`, `description`, `platform`, `severity`,
`condition`. Validation happens in `app/detection/rule_validator.py`
(on rule creation and seeding) and again in `app/detection/engine.py` (on
evaluation).

## 3. Write the scenario

Create `scenarios/SCN-004.yaml`. Again the file name must equal `scenario_id`.

```yaml
scenario_id: SCN-004
name: Same Name As The Rule
description: >
  Verify that <the exact triggering condition> triggers the expected detection.
expected_rule_id: DET-004
expected_host: WIN11-LAB

events:
  - seconds_before_evaluation: 50
    event_type: authentication_failure
    event_data: {user: someone, status: failure}
    raw_event: {source: scenario-library}
  # ...one entry per event
```

Rules of thumb:

- Every event must be **strictly newer than** the window start, so
  `seconds_before_evaluation` must be **less than** `window_seconds`. An event
  exactly `window_seconds` old is outside the window.
- `expected_host` must exist as a host in the database. The scenario run fails
  with a 404 otherwise.
- The pass check looks for the host in the detection's `group`, so **`host`
  must be one of the rule's `group_by` fields**.
- Unknown fields in the scenario file are rejected.
- Give the scenario exactly the events needed to trigger the rule, so it tests
  the threshold and not an accident.

## 4. Test it

The generic test `tests/test_shipped_rules.py` loads every file in `rules/`,
seeds them, then runs every file in `scenarios/` against them. Adding the two
files above is enough to get a positive end-to-end test for free.

Add **negative tests** for behavior the scenario cannot show. Copy the pattern
in `tests/test_shipped_rules.py` (for `DET-002`) or
`tests/test_distinct_threshold.py`:

- one event short of the threshold does not trigger
- events from different groups are not combined
- events outside the window do not count

Then run:

```powershell
python -m pytest -q
git diff --check
```

## 5. Load it and run it

```powershell
python -m app.seed_rules
python -m uvicorn app.main:app --reload
```

In a second terminal:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/scenarios/library/SCN-004/run
Invoke-RestMethod http://127.0.0.1:8000/api/v1/coverage
Invoke-RestMethod http://127.0.0.1:8000/api/v1/regressions
```

Expected: the run returns `status: PASS`, `/coverage` lists the new rule as
`TESTED`, and `/regressions` shows it `HEALTHY`.

## 6. Document it

Add a "Shipped rule" section to the README with: what it is useful for, that a
detection does not establish an attack, false positives, and what it does not
catch.

## Checklist

- [ ] File names match the `id` and `scenario_id`.
- [ ] `host` is in `group_by`.
- [ ] Scenario event ages are less than `window_seconds`.
- [ ] `expected_host` exists in the database.
- [ ] Negative tests added.
- [ ] `python -m pytest -q` passes and `git diff --check` is clean.
- [ ] README section written.

## Known gotchas

- **Seeding never overwrites.** `python -m app.seed_rules` skips a rule whose ID
  is already in the database. If you edit a rule file after seeding it, the
  database keeps the old definition. There is no update or delete endpoint yet,
  so the options are to use a new rule ID or reset your local development
  database (this deletes its data).
- **Event types are exact strings.** `authentication_failure` and
  `auth_failure` are different event types.
- **Timestamps must carry a timezone.** The events API rejects naive
  timestamps and converts others to UTC.
- **Missing or unhashable group fields silently exclude an event.** If a rule
  never fires, check that the events actually contain every `group_by` and
  `distinct_field` value.
- **A detection is a signal, not proof.** Keep that wording in rule
  documentation.
