from skillguard_core import config


def test_defaults():
    config.get_settings.cache_clear()
    settings = config.get_settings()
    assert settings.scan_timeout_s == 300
    assert settings.danger_min == 70
    assert settings.caution_min == 30
    config.get_settings.cache_clear()


def test_env_override(monkeypatch):
    monkeypatch.setenv("SKILLGUARD_SCAN_TIMEOUT_S", "42")
    config.get_settings.cache_clear()
    settings = config.get_settings()
    assert settings.scan_timeout_s == 42
    config.get_settings.cache_clear()
