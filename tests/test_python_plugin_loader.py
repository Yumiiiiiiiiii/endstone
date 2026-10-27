import importlib
import importlib.machinery
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

_executable, _base_executable = sys.executable, sys._base_executable
plugin_loader = importlib.import_module("endstone.plugin.plugin_loader")

sys.executable, sys._base_executable = _executable, _base_executable


def test_new_plugin_directory_is_searchable_after_install(tmp_path, monkeypatch):
    site_dir = tmp_path / "not-created-yet"
    monkeypatch.syspath_prepend(str(site_dir))
    name = "fork_cache_regression_plugin"
    assert importlib.machinery.PathFinder.find_spec(name) is None
    assert sys.path_importer_cache[str(site_dir)] is None

    def install(*args, **kwargs):
        site_dir.mkdir()
        (site_dir / (name + ".py")).write_text("value = 42\n", encoding="utf-8")
        return subprocess.CompletedProcess(args, 0)

    ep = SimpleNamespace(load=lambda: importlib.import_module(name))
    fake_loader = SimpleNamespace(_prefix=str(tmp_path), _load_plugin_from_ep=lambda entry: entry.load())
    eps = SimpleNamespace(select=lambda **kwargs: [ep])
    try:
        with (
            patch.object(plugin_loader.pkginfo, "Wheel", return_value=SimpleNamespace(name="endstone-cache-test")),
            patch.object(plugin_loader, "distribution", return_value=SimpleNamespace(entry_points=eps)),
            patch.object(plugin_loader.subprocess, "run", side_effect=install),
        ):
            result = plugin_loader.PythonPluginLoader.load_plugin(fake_loader, "fixture.whl")
        assert result.value == 42
    finally:
        sys.modules.pop(name, None)
        sys.path_importer_cache.pop(str(site_dir), None)


def test_find_python_preserves_explicit_virtualenv_path(tmp_path, monkeypatch):
    executable = tmp_path / "venv" / "bin" / "python"
    executable.parent.mkdir(parents=True)
    try:
        executable.symlink_to(sys.executable)
    except OSError:
        pytest.skip("Symlinks unavailable on this host")
    monkeypatch.setenv("ENDSTONE_PYTHON_EXECUTABLE", str(executable))
    assert plugin_loader.find_python() == executable


def test_failed_install_does_not_load_stale_distribution():
    fake_loader = SimpleNamespace(_prefix="fixture-prefix")
    with (
        patch.object(plugin_loader.pkginfo, "Wheel", return_value=SimpleNamespace(name="endstone-failed")),
        patch.object(plugin_loader, "distribution") as distribution,
        patch.object(plugin_loader.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "pip")) as install,
        pytest.raises(subprocess.CalledProcessError),
    ):
        plugin_loader.PythonPluginLoader.load_plugin(fake_loader, "fixture.whl")
    assert install.call_args.kwargs["check"] is True
    distribution.assert_not_called()
