"""
tests/test_docker_jail_executor.py — Unit tests for DockerJailExecutor path translation.

Scope: _get_container_workdir() only. No Docker, no subprocess, no network.
These tests verify the path-translation contract introduced to replace the
fragile string-prefix match that silently fell back to /workspace.

Design decisions locked in by these tests:
  - A _work_dir equal to host_repo_root/project maps to /workspace (exact root).
  - A _work_dir inside host_repo_root/project maps to /workspace/<rel>.
  - A _work_dir outside host_repo_root/project raises WorkdirOutOfScopeError.
  - /tmp is explicitly rejected: it is a container-side tmpfs with no host
    bind-mount. A host /tmp/... path has no valid container equivalent.
  - The repo_root itself (one level above ./project) is outside scope and
    must also raise, not fall back.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make demo module importable from tests/
sys.path.insert(0, str(Path(__file__).parent.parent))

from demo.run_agent_test import DockerJailExecutor, WorkdirOutOfScopeError


@pytest.fixture()
def repo_root(tmp_path: Path) -> Path:
    """
    Create a minimal fake repo layout that mirrors the real structure:
        tmp_path/              ← host_repo_root (Warden repo root)
        tmp_path/project/      ← bind-mounted to /workspace in the container
        tmp_path/project/src/  ← a subdirectory inside the workspace
    """
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    (project_dir / "src").mkdir()
    (project_dir / "src" / "deep").mkdir()
    return tmp_path


# ── Happy-path translations ─────────────────────────────────────────────────

def test_workdir_at_project_root_translates_to_workspace(repo_root: Path) -> None:
    """_work_dir == host_repo_root/project → /workspace (the mount root)."""
    exe = DockerJailExecutor(
        host_repo_root=repo_root,
        work_dir=repo_root / "project",
    )
    assert exe._get_container_workdir() == "/workspace"


def test_workdir_one_level_inside_project_translates_correctly(repo_root: Path) -> None:
    """_work_dir == host_repo_root/project/src → /workspace/src."""
    exe = DockerJailExecutor(
        host_repo_root=repo_root,
        work_dir=repo_root / "project" / "src",
    )
    assert exe._get_container_workdir() == "/workspace/src"


def test_workdir_nested_deep_translates_correctly(repo_root: Path) -> None:
    """_work_dir == host_repo_root/project/src/deep → /workspace/src/deep."""
    exe = DockerJailExecutor(
        host_repo_root=repo_root,
        work_dir=repo_root / "project" / "src" / "deep",
    )
    assert exe._get_container_workdir() == "/workspace/src/deep"


# ── Out-of-scope paths must raise, not fall back ────────────────────────────

def test_workdir_at_repo_root_raises(repo_root: Path) -> None:
    """
    _work_dir == host_repo_root (one level above ./project) must raise.
    Previously this fell back silently to /workspace, masking the divergence.
    """
    exe = DockerJailExecutor(
        host_repo_root=repo_root,
        work_dir=repo_root,
    )
    with pytest.raises(WorkdirOutOfScopeError, match="outside the jail's bind-mounted project root"):
        exe._get_container_workdir()


def test_workdir_completely_outside_repo_raises(repo_root: Path) -> None:
    """A path wholly unrelated to the repo root must raise WorkdirOutOfScopeError."""
    exe = DockerJailExecutor(
        host_repo_root=repo_root,
        work_dir=Path("/some/unrelated/directory"),
    )
    with pytest.raises(WorkdirOutOfScopeError):
        exe._get_container_workdir()


def test_tmp_path_raises_not_silently_defaults(repo_root: Path) -> None:
    """
    /tmp is a container-side tmpfs with NO host bind-mount.
    A host /tmp path has no container equivalent. It must raise, not default
    to /workspace, which would silently run commands in the wrong directory.

    WHY this decision: the container's /tmp is ephemeral and separate from the
    host's /tmp. Translating a host /tmp/... path to a container /tmp/... path
    would be wrong (different filesystem). Translating it to /workspace would
    also be wrong (different directory entirely). There is no safe translation.
    """
    exe = DockerJailExecutor(
        host_repo_root=repo_root,
        work_dir=Path("/tmp/agent_work"),
    )
    with pytest.raises(WorkdirOutOfScopeError, match="bind-mounted project root"):
        exe._get_container_workdir()


def test_path_sharing_prefix_but_not_child_raises(repo_root: Path) -> None:
    """
    A sibling directory that shares the 'project' prefix (e.g. 'project_backup/')
    must NOT pass the boundary check. This is the exact failure mode of the old
    string-startswith approach; pathlib.relative_to() is path-boundary-aware.
    """
    sibling = repo_root / "project_backup"
    sibling.mkdir()
    exe = DockerJailExecutor(
        host_repo_root=repo_root,
        work_dir=sibling,
    )
    with pytest.raises(WorkdirOutOfScopeError):
        exe._get_container_workdir()
