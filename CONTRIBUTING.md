# Contributing

## Setup

```bash
git clone <repo-url> && cd traust-ledger
make setup
```

Installs deps (`uv sync`) and enables git hooks. One time per clone.

## Commit messages

Conventional commits required. Format: `type(scope): subject`

Types: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `chore`, `ci`, `build`, `style`, `revert`

```
feat(identity): add fingerprint helper
fix(writer): enforce ldap_verified on human-fp
perf!: change claim hash recipe          ← breaking change
```

## Hooks

| Hook | Runs | Speed |
|------|------|-------|
| `commit-msg` | subject format check | instant |
| `pre-commit` | ruff lint on staged `.py` | <1s |
| `pre-push` | full lint + unit tests | ~10s |

Bypass: `--no-verify` on commit or push. CI still enforces.

## Releasing

If your MR has `feat:`, `fix:`, `perf:`, or `!` (breaking) commits:

```bash
make bump minor
# add ## [X.Y.Z] section to CHANGELOG.md
make check-release
git add VERSION pyproject.toml CHANGELOG.md
git commit -m "chore: release X.Y.Z"
```

CI validates on MR. On merge to main, CI tags automatically.

## CI pipeline

**MR:** lint → conventional commits → release-ready → tests

**Main:** tag if `VERSION` > latest git tag

## Running tests

```bash
make test
uv run pytest -q
```

## Architecture

See [README.md](README.md) for module layout, golden vectors, and consumption.
