#!/usr/bin/env python
"""Package configuration."""

import setuptools

def readme():
    """Returns the contents of the README file"""
    with open('README.rst', 'r') as handle:
        return handle.read()

setuptools.setup(
    name='keyholder',
    maintainer='Faidon Liambotis',
    maintainer_email='faidon@wikimedia.org',
    description='filtering proxy for ssh-agent',
    long_description=readme(),
    url='https://github.com/wikimedia/keyholder',
    license='Apache2',
    packages=setuptools.find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Intended Audience :: System Administrators',
    ],
    keywords=['ssh', 'agent'],
    install_requires=[
        'pyyaml',
    ],
    entry_points={
        'console_scripts': [
            'keyholderd = keyholder.daemon:main',
        ],
    },
    scripts=['bin/keyholder'],
    setup_requires=[
        'setuptools_scm',
        'pytest-runner>=2.0,<3dev',
    ],
    tests_require=[
        'pytest',
    ],
    zip_safe=False,
    use_scm_version=True,
)
