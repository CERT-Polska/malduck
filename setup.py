from setuptools import setup, Extension

try:
    from Cython.Build import cythonize
    extensions = cythonize([
        Extension("malduck.native.ints.nativeint", ["malduck/native/ints/nativeint.pyx"])
    ])
except ImportError:
    # Fallback for source package compilation (without Cython)
    extensions = [
        Extension("malduck.native.ints.nativeint", ["malduck/native/ints/nativeint.c"])
    ]

setup(
    name="malduck",
    version="5.0.0",
    description="Malduck is your ducky companion in malware analysis journeys",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="CERT Polska",
    author_email="info@cert.pl",
    packages=["malduck"],
    package_data={"malduck": ["py.typed"]},
    ext_modules=extensions,
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
    python_requires='>=3.8',
    zip_safe=False,
)
