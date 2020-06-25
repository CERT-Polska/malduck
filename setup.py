try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
    name="malduck",
    version="3.2.0",
    description="Malduck is your ducky companion in malware analysis journeys",
    author="CERT Polska",
    author_email="info@cert.pl",
    packages=["malduck"],
    entry_points={
        "console_scripts": [
            "malduck = malduck.main:main",
        ],
    },
    license="GPLv3",
    include_package_data=True,
    install_requires=open("requirements.txt").read().splitlines(),
    url="https://github.com/CERT-Polska/malduck",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires='>=3.6'
)
