import os
from setuptools import setup, find_packages

DIR = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(DIR, "README.md")) as f:
    long_desc = f.read()

desc = '''sentry event processor for protecting sensitive infos'''


setup(
    name="sentry-processor",
    version="0.0.1",
    author="laiyongtao",
    author_email="laiyongtao6908@163.com",
    url="https://github.com/laiyongtao/sentry-processor" ,
    license="BSD-3-Clause License",
    description=desc,
    long_description=long_desc,
    long_description_content_type="text/markdown",
    platforms="all",
    classifiers=[
        "Programming Language :: Python",
    ],
    keywords = ["sentry", "processor", "sensitive", "filter"],
    packages=find_packages(exclude=["demos"]),
)
