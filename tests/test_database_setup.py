import os
import subprocess
import sys
from pathlib import Path


def test_importing_database_module_creates_data_directory(tmp_path):
    repo_root = Path(__file__).resolve().parent.parent

    subprocess.run(
        [sys.executable, "-c", "import app.database"],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(repo_root)},
        check=True,
    )

    assert (tmp_path / "data").is_dir()