from pathlib import Path

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
    name="malduck",
    version="4.4.0",
    description="Malduck is your ducky companion in malware analysis journeys",
    long_description=Path("README.md").read_text(),
    long_description_content_type="text/markdown",
    author="CERT Polska",
    author_email="info@cert.pl",
    packages=["malduck"],
    package_data={"malduck": ["py.typed"]},
    entry_points={
        "console_scripts": [
            "malduck = malduck.main:main",
        ],
    },
    license="GPLv3",
    include_package_data=True,
    install_requires=Path("requirements.txt").read_text().splitlines(),
    url="https://github.com/CERT-Polska/malduck",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.8",
)
