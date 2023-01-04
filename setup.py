#!/usr/bin/env python3

from setuptools import find_packages, setup

package_name = "aws_cpt"

setup(
    name=package_name,
    version="1.0",
    description="AWS Cloud Pentest Utility",
    author="ViolentTestPen",
    author_email="violenttestpen@users.noreply.github.com",
    url="https://github.com/violenttestpen/aws_cpt/",
    packages=find_packages(
        include=[
            package_name,
            f"{package_name}.*",
        ]
    ),
    install_requires=[
        "rich",
    ],
    package_dir={},
    entry_points={
        "console_scripts": [f"awscpt = {package_name}.__main__:main"],
    },
)
