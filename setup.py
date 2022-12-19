from glob import glob
from os.path import basename
from os.path import splitext
from setuptools import find_packages
from setuptools import setup

from src.dtCrowdstrike import _VERSION, _MAINTAINER, _TITLE, _DESCRIPTION, _AUTHOR
from src.dtCrowdstrike import _AUTHOR_EMAIL, _PROJECT_URL, _DOCS_URL

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r") as fh:
    requirements = fh.read().splitlines()

setup(
    name=_TITLE,
    version=_VERSION,
    author=_AUTHOR,
    author_email=_AUTHOR_EMAIL,
    maintainer=_MAINTAINER,
    maintainer_email=_AUTHOR_EMAIL,
    docs_url=_DOCS_URL,
    description=_DESCRIPTION,
    long_description=long_description,
    long_description_content_type="text/markdown",
    url=_PROJECT_URL,
    packages=find_packages("src", exclude=('tests', 'docs', 'samples')),
    package_dir={"": "src"},
    py_modules=[splitext(basename(path))[0] for path in glob("src/*.py")],
    include_package_data=True,
    install_requires=requirements,
    extras_require={
        "dev": [
            "flake8",
            "coverage",
            "pydocstyle",
            "pylint",
            "pytest-cov",
            "pytest",
            "bandit",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Operating System :: Unix",
        "Operating System :: POSIX",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Framework :: Flake8",
        "License :: OSI Approved :: The Unlicense (Unlicense)",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities"
    ],
    python_requires='>=3.9',
)