"""Include bounded third-party source snapshots in binary distributions."""
from pathlib import Path
from shutil import copytree

from setuptools import setup
from setuptools.command.build_py import build_py


class BuildWithVendor(build_py):
    def run(self):
        super().run()
        source = Path(__file__).parent / "vendor"
        destination = Path(self.build_lib) / "av_susvibes" / "vendor"
        copytree(source, destination, dirs_exist_ok=True,
                 ignore=lambda _directory, names: {n for n in names if n in {"__pycache__", "node_modules", ".cache"}
                                                or n.endswith((".pyc", ".pyo"))})


setup(cmdclass={"build_py": BuildWithVendor})
