from scripts.verify_role_locks import (
    ROLES,
    _clean_environment,
    parse_required_entries,
    required_modules_for_role,
)


def test_required_entry_option_is_repeatable() -> None:
    assert parse_required_entries(
        [
            "--require-entry",
            "collector",
            "--require-entry",
            "materializer",
        ]
    ) == frozenset({"collector", "materializer"})


def test_requested_entry_is_added_only_to_its_role_probe() -> None:
    requested = frozenset({"collector"})

    collector_modules = required_modules_for_role(
        "collector", ROLES["collector"], requested
    )
    dev_modules = required_modules_for_role("dev", ROLES["dev"], requested)

    assert "crypto_collector.runtime.worker" in collector_modules
    assert "crypto_collector.runtime.worker" not in dev_modules


def test_clean_environment_rejects_credentials_and_pip_injection(
    monkeypatch,
) -> None:
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "not-for-a-child-process")
    monkeypatch.setenv("PIP_TARGET", "/tmp/injected-target")
    monkeypatch.setenv("PIP_REQUIREMENT", "/tmp/injected-requirements.txt")
    monkeypatch.setenv("PIP_INDEX_URL", "https://packages.example/simple")

    environment = _clean_environment(allow_package_index=True)

    assert environment["PIP_INDEX_URL"] == "https://packages.example/simple"
    assert "AWS_SECRET_ACCESS_KEY" not in environment
    assert "PIP_TARGET" not in environment
    assert "PIP_REQUIREMENT" not in environment
