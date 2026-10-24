# rekit - project rules

Inherits `C:\dshggg\AGENTS.md`. Project-specific rules go here.

- Entry point: `src/main.py` (thin wrapper) -> `src/rekit/cli.py`
- Tests: `python tests/selftest.py` (43 checks, must stay green)
- Runtime: `C:\Python 3.14\python.exe`, no third-party packages, no MSVC/clang

## Constraints

- **Zero dependencies.** Standard library only. Do not add pefile/lief/capstone.
  The point of this project is that it runs on a bare Windows box.
- Every parser change needs a selftest assertion. The synthetic PE in
  `tests/selftest.py` is the fixture - extend it instead of adding binary files.
- Heuristic thresholds live in `src/rekit/entropy.py` and `src/rekit/pe.py`.
  If you retune them, re-run the scan against `C:\Windows\System32\drivers` and
  confirm the false-positive count stays near zero (resource-only `.mui` images
  were the original source of noise).

## Do not touch

- `docs/` is prose for humans; code changes do not go there.
- Do not commit samples, dumps, or anything from `C:\Windows` into the repo.
