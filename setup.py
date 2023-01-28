import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="py25519",
    version="0.1.0",
    author="Jonathan Levin",
    description="Python wrapper for lib25519 microlibrary",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ondesmartenot/py25519",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security :: Cryptography",
        "Topic :: Security"
    ],
    requires=["lib25519"],
    package_dir={"": "."},
    packages=setuptools.find_packages(where="."),
    python_requires=">=3.6",
)
