# -*- coding: utf-8 -*-

"""
processcdb
"""
import versioneer
from os.path import abspath, dirname, join
from setuptools import setup
PACKAGE_NAME="processcdb"
CWD = abspath(dirname(__file__))
with open(join(CWD, "requirements.txt"), encoding="utf-8") as f:
    REQUIREMENTS = f.read().splitlines()

# Get the long description from the README file
with open(join(CWD, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

CLASSIFIERS = """
Development Status :: 3 - Alpha
Topic :: Software Development :: Testing
Operating System :: OS Independent
License :: OSI Approved :: Apache Software License
Programming Language :: Python
Programming Language :: Python :: 3
Programming Language :: Python :: 3.7
Programming Language :: Python :: 3.8
Programming Language :: Python :: 3.9
Topic :: Software Development :: Testing
""".strip().splitlines()

setup(
    name=PACKAGE_NAME,
    version=versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    description="Front-end to process compile_commands.json file and run various static analysis tools against it",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/rasjani/processcdb",
    author="Jani Mikkonen",
    author_email="jani.mikkonen@gmail.com",
    license="Apache License 2.0",
    classifiers=CLASSIFIERS,
    install_requires=REQUIREMENTS,
    keywords="staticanalysis frontend clang cppcheck clangtidy compile_commands.json",
    platforms="any",
    packages=[PACKAGE_NAME],
    package_dir={"": "src"},
    entry_points={
        'console_scripts': ['processcdb = processcdb.__main__:main'],
    }
)
