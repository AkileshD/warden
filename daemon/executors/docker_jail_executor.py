import subprocess
from pathlib import Path
from typing import Optional

from daemon.executors.base import Executor, ExecutionResult
from daemon.parser.shell_parser import ParsedAction
from daemon.inspectors.base import Verdict

class WorkdirOutOfScopeError(Exception):
    pass

class DockerJailExecutor(Executor):
    def __init__(self, host_repo_root: Path, work_dir: Optional[Path] = None) -> None:
        self._host_repo_root = Path(host_repo_root).resolve()
        self._work_dir = Path(work_dir).resolve() if work_dir else self._host_repo_root

    def _get_container_workdir(self) -> str:
        host_project_root = self._host_repo_root / "project"
        try:
            rel = self._work_dir.relative_to(host_project_root)
        except ValueError:
            raise WorkdirOutOfScopeError(
                f"Daemon _work_dir {str(self._work_dir)!r} is outside the jail's "
                f"bind-mounted project root ({host_project_root}). "
                f"The container mount is ./project:/workspace — workdirs outside "
                f"this tree (including /tmp) have no valid container translation."
            )
        if rel == Path("."):
            return "/workspace"
        return f"/workspace/{rel}"

    def run(self, action: ParsedAction, verdict: Verdict) -> ExecutionResult:
        try:
            container_workdir = self._get_container_workdir()
        except WorkdirOutOfScopeError as e:
            return ExecutionResult(
                stdout="",
                stderr=f"warden: workdir translation failed — {e}",
                exit_code=1,
                was_real=True,
                was_fabricated=False,
            )
        
        translated_args = []
        for arg in action.args:
            if arg.startswith("./project/"):
                translated_args.append(arg.replace("./project/", "./", 1))
            else:
                translated_args.append(arg)
                
        cmd = ["docker-compose", "exec", "-T", "--workdir", container_workdir, "jail", action.binary] + action.flags + translated_args
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            
            if action.redirect_target:
                mode = "a" if action.redirect_append else "w"
                try:
                    with open(action.redirect_target, mode) as f:
                        f.write(result.stdout)
                    stdout_result = ""
                except Exception as e:
                    return ExecutionResult(
                        stdout="",
                        stderr=f"warden: failed to write redirection to {action.redirect_target}: {e}",
                        exit_code=1,
                        was_real=True,
                        was_fabricated=False,
                    )
            else:
                stdout_result = result.stdout

            return ExecutionResult(
                stdout=stdout_result,
                stderr=result.stderr,
                exit_code=result.returncode,
                was_real=True,
                was_fabricated=False,
            )
        except subprocess.TimeoutExpired:
            return ExecutionResult(
                stdout="",
                stderr="Timeout inside jail",
                exit_code=124,
                was_real=True,
                was_fabricated=False,
            )
        except Exception as e:
            return ExecutionResult(
                stdout="",
                stderr=f"Jail execution error: {e}",
                exit_code=1,
                was_real=True,
                was_fabricated=False,
            )
