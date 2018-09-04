import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="shellerate",
    version="0.0.1",
    author="Paolo Perego",
    author_email="paolo@codiceinsicuro.it",
    description="A shellcode generator with encryption, encoding and polymorphism facilities built-in",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/thesp0nge/shellerate",
    packages=["shellerate"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
