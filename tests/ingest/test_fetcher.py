import io
import subprocess
import zipfile

import httpx
import pytest
import respx

from skillguard_core.ingest.fetcher import IngestLimitExceeded, content_hash, discover_skills, fetch


def make_zip_bytes(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    return buf.getvalue()


def test_local_directory(tmp_path):
    (tmp_path / "SKILL.md").write_text("# Test skill")
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


def test_discover_skills_root_is_single_skill(tmp_path):
    (tmp_path / "SKILL.md").write_text("# root skill")
    skills = discover_skills(tmp_path)
    assert [s.path for s in skills] == [tmp_path]


def test_discover_skills_recursive(tmp_path):
    (tmp_path / "a" / "skills" / "one").mkdir(parents=True)
    (tmp_path / "a" / "skills" / "one" / "SKILL.md").write_text("# one")
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "SKILL.md").write_text("# b")
    (tmp_path / "docs").mkdir()
    skills = discover_skills(tmp_path)
    assert [s.path for s in skills] == sorted([tmp_path / "a" / "skills" / "one", tmp_path / "b"])


def test_discover_skills_empty(tmp_path):
    (tmp_path / "README.md").write_text("# no skills")
    assert discover_skills(tmp_path) == []


def test_discover_skills_root_wins_over_nested(tmp_path):
    (tmp_path / "SKILL.md").write_text("# root")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "SKILL.md").write_text("# nested")
    skills = discover_skills(tmp_path)
    assert [s.path for s in skills] == [tmp_path]


def test_fetch_github_tree_url_normalizes_and_sets_subpath(tmp_path):
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:2] == ["git", "clone"]:
            dest = cmd[-1]
            subprocess.run(["mkdir", "-p", dest], check=True)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="abc123\n", stderr="")

    fetched = fetch(
        "https://github.com/acme/skills/tree/main/config/skills/my-skill",
        tmp_root=tmp_path, max_bytes=1024, git_runner=runner,
    )
    assert calls[0][0] == "git"
    assert calls[0][1] == "clone"
    assert calls[0][-1].endswith("repo")
    assert "https://github.com/acme/skills" in " ".join(calls[0])
    assert "/tree/" not in " ".join(calls[0])
    assert fetched.origin == "git"
    assert fetched.subpath == "config/skills/my-skill"
    assert fetched.source_url == "https://github.com/acme/skills"


def test_fetch_plain_git_url_has_empty_subpath(tmp_path):
    def runner(cmd, **kwargs):
        if cmd[:2] == ["git", "clone"]:
            subprocess.run(["mkdir", "-p", cmd[-1]], check=True)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="abc123\n", stderr="")

    fetched = fetch("https://github.com/acme/skills.git", tmp_root=tmp_path, max_bytes=1024, git_runner=runner)
    assert fetched.subpath == ""


def test_fetch_github_tree_url_root_subpath(tmp_path):
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:2] == ["git", "clone"]:
            subprocess.run(["mkdir", "-p", cmd[-1]], check=True)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="abc123\n", stderr="")

    fetched = fetch(
        "https://github.com/acme/skills/tree/main", tmp_root=tmp_path, max_bytes=1024, git_runner=runner
    )
    assert fetched.subpath == ""
    assert "/tree/main" not in " ".join(calls[0])
    assert "https://github.com/acme/skills" in " ".join(calls[0])


def test_fetch_github_tree_url_decodes_subpath(tmp_path):
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd)
        if cmd[:2] == ["git", "clone"]:
            subprocess.run(["mkdir", "-p", cmd[-1]], check=True)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="abc123\n", stderr="")

    fetched = fetch(
        "https://github.com/acme/skills/tree/main/some%20skill",
        tmp_root=tmp_path, max_bytes=1024, git_runner=runner,
    )
    assert fetched.subpath == "some skill"
    assert "/tree/" not in " ".join(calls[0])
