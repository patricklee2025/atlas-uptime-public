"""Exercise the real Git storage workflow against a disposable local remote."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path("state_store.sh").resolve()


class StateStoreTests(unittest.TestCase):
    def test_ciphertext_only_updates_and_lease(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            remote, work = root / "remote.git", root / "work"
            def run(*args, cwd=None, ok=True, env=None):
                result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True)
                if ok:
                    self.assertEqual(result.returncode, 0, result.stderr)
                return result
            run("git", "init", "--bare", str(remote))
            run("git", "init", "-b", "main", str(work))
            run("git", "config", "user.name", "Test", cwd=work)
            run("git", "config", "user.email", "test@example.invalid", cwd=work)
            (work / "README.md").write_text("Public source only")
            run("git", "add", "README.md", cwd=work)
            run("git", "commit", "-m", "Initial source", cwd=work)
            run("git", "remote", "add", "origin", str(remote), cwd=work)
            run("git", "push", "-u", "origin", "main", cwd=work)
            env = dict(os.environ, MODE="check")
            self.assertNotEqual(run("bash", str(SCRIPT), "load", cwd=work, env=env, ok=False).returncode, 0)
            env["MODE"] = "initialize"
            run("bash", str(SCRIPT), "load", cwd=work, env=env)
            self.assertFalse((work / "state-work/README.md").exists())
            (work / "state-work/state.enc").write_text("test-ciphertext-1")
            # An accidental untracked report must never be included in a commit.
            (work / "state-work/STATUS.md").write_text("PRIVATE")
            run("bash", str(SCRIPT), "save", cwd=work)
            names = run("git", "--git-dir", str(remote), "ls-tree", "--name-only", "encrypted-state").stdout.strip()
            self.assertEqual(names, "state.enc")
            run("git", "worktree", "remove", "--force", "state-work", cwd=work)
            self.assertNotEqual(run("bash", str(SCRIPT), "load", cwd=work, env=env, ok=False).returncode, 0)
            env["MODE"] = "check"
            run("bash", str(SCRIPT), "load", cwd=work, env=env)
            (work / "state-work/state.enc").write_text("test-ciphertext-2")
            run("bash", str(SCRIPT), "save", cwd=work)
            count = run("git", "--git-dir", str(remote), "rev-list", "--count", "encrypted-state").stdout.strip()
            self.assertEqual(count, "1")
            # A stale writer still has the previous lease and cannot replace the new state.
            (work / "state-work/state.enc").write_text("test-ciphertext-stale")
            self.assertNotEqual(run("bash", str(SCRIPT), "save", cwd=work, ok=False).returncode, 0)
            current = run("git", "--git-dir", str(remote), "show", "encrypted-state:state.enc").stdout
            self.assertEqual(current, "test-ciphertext-2")
