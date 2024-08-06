from setuptools import setup, find_packages

setup(
    name="vex",
    version="1.1",
    url="https://github.com/casterbyte/vex",
    author="Magama Bazarov",
    author_email="caster@exploit.org",
    scripts=['vex.py'],
    description="RouterOS Security Inspector",
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    license="Apache-2.0",
    keywords=['network security', 'mikrotik', 'routeros'],
    packages=find_packages(),
    install_requires=[
        'colorama',
    ],
    entry_points={
        "console_scripts": ["vex = vex:main"],
    },
    python_requires='>=3.11',
)