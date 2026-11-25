"""Every ${X_PW} / ${VIEW_PSEUDONYM_KEY_*} a migration substitutes must be defined in
the README's /etc/ssdf/migrate-secrets.env heredoc, or a fresh install fails closed."""

import pathlib
import re

_CLICKHOUSE = pathlib.Path(__file__).resolve().parents[3] / "infra" / "clickhouse"
_PLACEHOLDER = re.compile(r"\$\{((?:[A-Z_]+_PW)|(?:VIEW_PSEUDONYM_KEY_[A-Z]+))[}:]")


def _heredoc_names() -> set[str]:
    readme = (_CLICKHOUSE / "README.md").read_text()
    block = re.search(r"migrate-secrets\.env <<'EOF'\n(.*?)\nEOF\n", readme, re.S)
    assert block, "migrate-secrets.env heredoc not found in README"
    return {line.split("=", 1)[0] for line in block.group(1).splitlines() if "=" in line}


def test_readme_heredoc_defines_every_migration_secret():
    used = set()
    for sql in _CLICKHOUSE.glob("[0-9]*.sql"):
        used |= set(_PLACEHOLDER.findall(sql.read_text()))
    assert used, "no placeholders found; the pattern is broken"
    assert used - _heredoc_names() == set()
