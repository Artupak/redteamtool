from setuptools import setup, find_packages

setup(
    name="redteamops",
    version="1.0.0",
    author="ARTUPAK",
    author_email="artupak@example.com",
    description="A comprehensive Red Team Operations framework",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/redteamops",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=[
        "click>=8.1.3",
        "colorama>=0.4.6",
        "paramiko>=3.3.1",
        "requests>=2.31.0",
        "pyyaml>=6.0.1",
        "rich>=13.6.0",
        "scapy>=2.5.0",
        "impacket>=0.11.0",
        "python-nmap>=0.7.1",
        "reportlab>=4.0.7",
        "jinja2>=3.1.2",
        "cryptography>=41.0.7",
        "pyOpenSSL>=23.3.0",
        "beautifulsoup4>=4.12.2",
        "dnspython>=2.4.2",
        "python-docx>=1.0.1"
    ],
    entry_points={
        "console_scripts": [
            "redteamops=main:cli",
        ],
    },
    include_package_data=True,
    package_data={
        "redteamops": [
            "config/*.yaml",
            "templates/*.html",
            "templates/*.j2",
        ],
    },
) 