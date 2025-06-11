import subprocess
from setuptools import find_packages, setup

print(subprocess.run(
    "gcc -o src/python/adf/bpf_tap src/bpf_tap.c -lpcap -pthread",
    shell=True,
    capture_output=True
))

install_requires = [
    "IPy",
    "dpkt"
]

extras_require = {
    'mqtt':    ["paho-mqtt"],
    'tap':     ["python-pytun"],
    'pcap':    ["pcap-ct"],
    'can':     ['python-can', 'cantools'],
    'nfqueue': ['netfilterqueue']
}
# flatten all extra requirement into the all option
# how to parse this: make a list from the generator dep, where...
#                       ...for each extras_require.values element as deps,
#                       ...each element of deps is yielded by dep
extras_require['all'] = [dep 
                         for deps in extras_require.values()
                         for dep in deps]

entry_points = {
    "console_scripts": [
        "adf = adf.__main__:main",
        "adf_mp = adf.__main__:main",
        "adfcon = adf.adfcon:main",
        "parallel = adf.adf_parallel:main",
    ],
    "arl_adf_plugins": [],
}

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
    install_requires=install_requires,
    extras_require=extras_require,
    entry_points=entry_points
)
