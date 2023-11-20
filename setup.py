import subprocess
from setuptools import find_packages, setup

subprocess.run(
    "gcc -o src/python/adf/bpf_tap src/bpf_tap.c -lpcap -pthread",
    shell=True,
    capture_output=True
)

setup(
    name="ARL-ADF",
    version="3.0",
    author="USArmyResearchLab",
    description="A fully modular network packet processing and event-handling framework",
    python_requires=">=3.8",
    packages=find_packages(where="src/python/"),
    package_dir={"": "src/python/"},
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: POSIX :: Linux",
        "Environment :: Console",
        "Topic :: Security",
    ],
    package_data={
        "adf": ["config/*.cfg", "bpf_tap"],
    },
    install_requires=[
        "IPy",
        "dpkt",
        "pycrypto",
        "paho-mqtt",
        "python-pytun",
        "pypcap",
        'python-can', 
        'cantools'
    ],
    entry_points={
        "console_scripts": [
            "adf = adf.__main__:main",
            "adf_mp = adf.__main__:main",
            "adfcon = adf.adfcon:main",
            "parallel = adf.adf_parallel:main",
        ],
        "arl_adf_plugins": [],
    }
)
