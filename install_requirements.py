import subprocess
import sys


def install_packages() -> None:
    with open(file="requirements.txt") as f:
        packages: list[str] = [line.strip() for line in f.readlines() if line.strip()]
        for package in packages:
            subprocess.check_call(args=[sys.executable, "-m", "pip", "install", package])


if __name__ == "__main__":
    install_packages()
