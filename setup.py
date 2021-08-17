import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

with open('cisco_documentation/VERSION', 'r') as f:
    version = f.read()

setuptools.setup(
    name="cisco-documentation",
    version=version,
    author="John Burt",
    author_email="johnburt.jab@gmail.com",
    description="Gather information from switches to create documentation in excel.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/alphabet5/cisco_documentation",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.9',
    entry_points={'console_scripts': ['cisco-documentation=cisco_documentation.cli:main']},
    include_package_data=True,
    package_data={'cisco_documentation': ['*', 'templates/*'], },
    install_requires=['napalm',
                      'yamlarg',
                      'keyring',
                      'ntc_templates',
                      # 'aiomultiprocess',
                      'joblib',
                      'requests',
                      'openpyxl'],
)
