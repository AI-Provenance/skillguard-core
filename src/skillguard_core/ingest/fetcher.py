import hashlib
import io
import subprocess
import tempfile
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import httpx


class IngestLimitExceeded(RuntimeError):
    pass


@dataclass(slots=True)
class Fetched:
    path: Path
    origin: str
    source_url: str
    version_ref: str
    subpath: str = ""


def content_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for file_path in sorted(p for p in root.rglob("*") if p.is_file() and not p.is_symlink()):
        rel = file_path.relative_to(root).as_posix()
        file_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()
        digest.update(f"{rel}:{file_hash}\n".encode())
    return digest.hexdigest()


def fetch(
    target: str,
    *,
    tmp_root: Path,
    max_bytes: int,
    max_zip_members: int = 10_000,
    client: httpx.Client | None = None,
    git_runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    timeout_s: int = 120,
) -> Fetched:
    tmp_root.mkdir(parents=True, exist_ok=True)
    clone_target, subpath = _normalize_github_tree_url(target)
    if subpath:
        target = clone_target
    if "://" not in target and not target.endswith(".git"):
        local = Path(target).expanduser().resolve()
        if not local.is_dir():
            raise FileNotFoundError(f"not a directory: {target}")
        if not (local / "SKILL.md").exists():
            raise FileNotFoundError(f"no SKILL.md found in '{target}'")
        return Fetched(path=local, origin="local", source_url=str(local), version_ref="")

    workdir = Path(tempfile.mkdtemp(dir=tmp_root))
    if target.endswith(".zip") or "/zipball/" in target:
        _download_zip(target, workdir, max_bytes, max_zip_members, client, timeout_s)
        return Fetched(
            path=_unwrap_single_dir(workdir), origin="zip", source_url=target, version_ref=""
        )

    version_ref = _git_clone(target, workdir, git_runner, timeout_s)
    return Fetched(
        path=workdir / "repo", origin="git", source_url=clone_target, version_ref=version_ref, subpath=subpath
    )


def discover_skills(root: Path) -> list[Fetched]:
    root = root.expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"not a directory: {root}")
    if (root / "SKILL.md").exists():
        return [Fetched(path=root, origin="local", source_url=str(root), version_ref="")]
    subdirs = sorted({p.parent for p in root.rglob("SKILL.md") if p.is_file()})
    return [
        Fetched(path=d, origin="local", source_url=str(d), version_ref="")
        for d in subdirs
    ]


def _download_zip(
    url: str,
    dest: Path,
    max_bytes: int,
    max_zip_members: int,
    client: httpx.Client | None,
    timeout_s: int,
) -> None:
    own_client = client is None
    client = client or httpx.Client(follow_redirects=True, timeout=timeout_s)
    try:
        data = bytearray()
        with client.stream("GET", url) as response:
            response.raise_for_status()
            for chunk in response.iter_bytes():
                data.extend(chunk)
                if len(data) > max_bytes:
                    raise IngestLimitExceeded(f"download exceeds {max_bytes} bytes")
        buf = io.BytesIO(bytes(data))
        with zipfile.ZipFile(buf) as zf:
            members = zf.infolist()
            if len(members) > max_zip_members:
                raise IngestLimitExceeded(
                    f"zip has {len(members)} members (cap {max_zip_members})"
                )
            total = sum(m.file_size for m in members)
            if total > max_bytes:
                raise IngestLimitExceeded(
                    f"uncompressed size {total} exceeds {max_bytes} bytes"
                )
            for member in members:
                member_path = Path(member.filename)
                if member_path.is_absolute() or ".." in member_path.parts:
                    raise IngestLimitExceeded(f"unsafe zip entry: {member.filename}")
            zf.extractall(dest)
    finally:
        if own_client:
            client.close()


def _normalize_github_tree_url(target: str) -> tuple[str, str]:
    parsed = urlparse(target)
    if parsed.netloc not in ("github.com", "www.github.com") or parsed.scheme not in ("http", "https"):
        return target, ""
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 4 or parts[2] != "tree":
        return target, ""
    clone_url = f"{parsed.scheme}://{parsed.netloc}/{parts[0]}/{parts[1]}"
    subpath = "/".join(parts[4:])
    return clone_url, subpath


def _git_clone(
    url: str,
    workdir: Path,
    runner: Callable[..., subprocess.CompletedProcess],
    timeout_s: int,
) -> str:
    dest = workdir / "repo"
    clone = runner(
        ["git", "clone", "--depth", "1", url, str(dest)],
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )
    if clone.returncode != 0:
        raise RuntimeError(f"git clone failed: {(clone.stderr or '').strip()[-2000:]}")
    rev = runner(
        ["git", "-C", str(dest), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return rev.stdout.strip()


def _unwrap_single_dir(workdir: Path) -> Path:
    entries = list(workdir.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return workdir
