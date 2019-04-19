import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="shellerate",
    version="0.4.3",
    python_requires='>=3.6.*',
    author="Paolo Perego",
    author_email="paolo@armoredcode.com",
    description="A shellcode generator with encryption, encoding and polymorphism facilities built-in",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/thesp0nge/shellerate",
    packages=["shellerate"],
    scripts=["bin/shellerate"],
    #install_requires=["binutils"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
