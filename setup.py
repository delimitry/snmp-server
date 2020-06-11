#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name="pytest_snmpserver",
    version="0.1",
    packages=find_packages(),
    long_description="blah",
    long_description_content_type="text/markdown",
    python_requires=">=3.6",
    install_requires=[],
    entry_points={"pytest11": ["pytest_snmpserver = pytest_snmpserver.pytest_plugin"]}
)
