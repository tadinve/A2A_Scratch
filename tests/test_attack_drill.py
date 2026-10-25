"""Day 05.9: the consolidated attack drill must pass in full (see scripts/attack_drill.py)."""

from scripts.attack_drill import run


def test_attack_drill_all_pass():
    failed = [f"{section}: {label} {detail}" for section, label, ok, detail in run(verbose=False) if not ok]
    assert failed == []
