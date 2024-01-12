import subprocess
import sys


def install_packages():
    with open("requirements.txt") as f:
        packages = [line.strip() for line in f.readlines() if line.strip()]
        for package in packages:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])


if __name__ == "__main__":
    install_packages()
