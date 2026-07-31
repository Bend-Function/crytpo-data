import pytest


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if item.get_closest_marker("live"):
            item.add_marker(pytest.mark.enable_socket)
        elif item.get_closest_marker("network"):
            item.add_marker(pytest.mark.allow_hosts(["127.0.0.1", "::1"]))
