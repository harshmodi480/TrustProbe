import pytest

from trustprobe.sandbox.docker import docker_available


def pytest_collection_modifyitems(config, items):
    """Skip @pytest.mark.docker tests when no Docker daemon is reachable."""
    if not any("docker" in item.keywords for item in items):
        return
    ok, reason = docker_available()
    if ok:
        return
    skip = pytest.mark.skip(reason=f"Docker not available: {reason}")
    for item in items:
        if "docker" in item.keywords:
            item.add_marker(skip)
