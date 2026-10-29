import getpass
import os
from pathlib import Path

from trustprobe.redact import Redactor


def test_home_directory_is_replaced():
    r = Redactor()
    text = f"error in {Path.home() / 'projects' / 'x.py'}"
    out = r.text(text)
    assert str(Path.home()) not in out and "<host-path>" in out


def test_forward_slash_and_backslash_forms():
    home = Path.home()
    r = Redactor()
    assert str(home) not in r.text(str(home))
    assert home.as_posix() not in r.text(home.as_posix())


def test_extra_paths(tmp_path):
    secret_dir = tmp_path / "customer-secret-dir"
    assert "customer-secret-dir" not in Redactor([secret_dir]).text(f"reading {secret_dir}/file.txt")


def test_username_is_replaced_on_word_boundaries():
    name = getpass.getuser()
    if len(name) < 3:
        return
    r = Redactor()
    assert name not in r.text(f"owner={name}")
    assert r.text(f"x{name}y") == f"x{name}y"  # inside a longer word it is left alone


def test_host_environment_values_are_replaced(monkeypatch):
    monkeypatch.setenv("MY_SECRET_TOKEN", "super-secret-value-12345")
    out = Redactor().text("token is super-secret-value-12345 here")
    assert "super-secret-value-12345" not in out and "<env-value>" in out


def test_short_environment_values_are_left_alone(monkeypatch):
    monkeypatch.setenv("TP_SHORT", "abc")
    assert Redactor().text("abc stays") == "abc stays"


def test_honeytoken_values_are_kept():
    text = "HONEY-7f3a91c2-SSH and sk-HONEY-7f3a91c2-ENVVAR"
    assert Redactor().text(text) == text


def test_redacts_recursively_in_json_like_data():
    home = str(Path.home())
    data = {"a": [f"{home}/x", {"b": f"at {home}"}], "n": 3, "ok": True, None: None}
    out = Redactor().obj(data)
    assert home not in str(out)
    assert out["n"] == 3 and out["ok"] is True


def test_path_matching_is_case_insensitive_on_windows_style_paths():
    if os.name != "nt":
        return
    assert str(Path.home()).upper() not in Redactor().text(str(Path.home()).upper())
