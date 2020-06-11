#!/usr/bin/env python3

from setuptools import setup

setup(
    name="pytest_snmpserver",
    version="0.1.1",
    packages=["pytest_snmpserver"],
    long_description="SNMP server as a pytest plugin",
    long_description_content_type="text/markdown",
    python_requires=">=3.6",
    install_requires=[],
    entry_points={"pytest11": ["pytest_snmpserver = pytest_snmpserver.pytest_plugin"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        ],
    )
