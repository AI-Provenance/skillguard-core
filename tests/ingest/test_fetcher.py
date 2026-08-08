import io
import subprocess
import zipfile

import httpx
import pytest
import respx

from skillguard_core.ingest.fetcher import IngestLimitExceeded, content_hash, fetch


def make_zip_bytes(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    return buf.getvalue()


def test_local_directory(tmp_path):
    fetched = fetch(str(tmp_path), tmp_root=tmp_path / "work", max_bytes=1024)
    assert fetched.origin == "local"
    assert fetched.path == tmp_path.resolve()


def test_missing_local_directory(tmp_path):
    with pytest.raises(FileNotFoundError):
        fetch(str(tmp_path / "nope"), tmp_root=tmp_path, max_bytes=1024)


@respx.mock
def test_zip_url_download(tmp_path):
    payload = make_zip_bytes({"my-skill/SKILL.md": "# hi"})
    respx.get("https://example.com/skill.zip").mock(return_value=httpx.Response(200, content=payload))
    fetched = fetch("https://example.com/skill.zip", tmp_root=tmp_path, max_bytes=10_000)
    assert fetched.origin == "zip"
    assert (fetched.path / "SKILL.md").read_text() == "# hi"


@respx.mock
def test_zip_size_cap(tmp_path):
    payload = make_zip_bytes({"big.txt": "x" * 5000})
    respx.get("https://example.com/big.zip").mock(return_value=httpx.Response(200, content=payload))
    with pytest.raises(IngestLimitExceeded):
        fetch("https://example.com/big.zip", tmp_root=tmp_path, max_bytes=1000)


def test_git_clone(tmp_path):
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:2] == ["git", "clone"]:
            dest = cmd[-1]
            subprocess.run(["mkdir", "-p", dest], check=True)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="abc123\n", stderr="")

    fetched = fetch("https://github.com/user/my-skill", tmp_root=tmp_path, max_bytes=1024, git_runner=runner)
    assert fetched.origin == "git"
    assert fetched.version_ref == "abc123"
    assert calls[0][:2] == ["git", "clone"]


def test_content_hash_is_stable_and_path_sensitive(tmp_path):
    (tmp_path / "a.txt").write_text("hello")
    h1 = content_hash(tmp_path)
    h2 = content_hash(tmp_path)
    assert h1 == h2
    (tmp_path / "a.txt").write_text("changed")
    assert content_hash(tmp_path) != h1
