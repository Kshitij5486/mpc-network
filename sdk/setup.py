from setuptools import setup, find_packages

setup(
    name="mpc-sdk",
    version="0.1.0",
    description="Python SDK for the MPC Network — privacy-preserving computation",
    author="Kshitij5486",
    packages=find_packages(),
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security :: Cryptography",
    ],
)