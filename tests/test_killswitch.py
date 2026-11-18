import pytest

from preflight.safety.killswitch import KillSwitch, KillSwitchEngaged


def test_memory_flag_and_file(tmp_path):
    ks = KillSwitch(tmp_path / "KILL")
    assert not ks.is_engaged()
    ks.engage("test")
    assert ks.is_engaged() and (tmp_path / "KILL").exists()
    with pytest.raises(KillSwitchEngaged):
        ks.check()


def test_file_alone_engages_from_another_process(tmp_path):
    (tmp_path / "KILL").write_text("{}")
    assert KillSwitch(tmp_path / "KILL").is_engaged()


def test_release_needs_named_human(tmp_path):
    ks = KillSwitch(tmp_path / "KILL")
    ks.engage("x")
    with pytest.raises(ValueError):
        ks.human_release("  ")
    ks.human_release("alice")
    assert not ks.is_engaged()
