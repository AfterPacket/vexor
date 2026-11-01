# Vexor 2.7.3 audit and release notes

## Scope

Version 2.7.3 records the local secret/run-data protection updates from the recent
workspace session. It updates `main.py`, `run_toolkit.bat`, and `run_toolkit.sh`
to report version 2.7.3, expands `.gitignore` for local config override names
and local run/result data, and documents safe Git handling in `README.md`.
Shared example/config files remain eligible for version control. This is not a
provider/model compatibility release, and no provider API behavior was changed
as part of the version bump.

## Verification

- `venv/Scripts/python -m compileall -q .`: passed.
- `venv/Scripts/python -m unittest discover -s tests -v`: 91 tests run; 89 passed,
  2 failed.
- Known failure: `test_completed_benign_evaluation_retains_evaluated_status` reports
  `total_clean` as 0 instead of 1.
- Known failure: `test_mixed_coverage_is_partial_not_clean` does not include `PARTIAL` in
  the summary and reports the result as `UNVALIDATED` with partial coverage.
- Importing `models.integrations` emits a deprecation warning for
  `google.generativeai`; it is not a test failure.
- No live provider calls, paid scans, Windows launcher execution, or browser
  end-to-end tests were performed during this audit.

## Security notes

`.gitignore` does not affect files already tracked or remove secrets from Git
history. Review staged paths and content before committing. Rotate any credential
that has been committed or exposed. This workspace currently has no `.git`
metadata, so tracked-file status, commit creation, and push readiness could not
be verified here.
