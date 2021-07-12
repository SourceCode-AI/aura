.. image:: files/logo/logotype.png
   :target: https://aura.sourcecode.ai/


======

.. class:: center

    |homepage_flair| |docs_flair| |docker_flair|
    |license_flair| |travis_flair| |pypi_flair|



Source code auditing and static code analysis
=============================================

Aura is a static analysis framework developed as a response to the ever-increasing threat of malicious packages and vulnerable code published on PyPI.


Project goals:

* provide an automated monitoring system over uploaded packages to PyPI, alert on anomalies that can either indicate an ongoing attack or vulnerabilities in the code
* enable an organization to conduct automated security audits of the source code and implement secure coding practices with a focus on auditing 3rd party code such as python package dependencies
* allow researches to scan code repositories on a large scale, create datasets and perform analysis to further advance research in the area of vulnerable and malicious code dependencies


Feature list:

- Suitable for analyzing malware with a guarantee of a zero-code execution
- Advanced deobfuscation mechanisms by rewriting the AST tree - constant propagations, code unrolling, and other dirty tricks
- Recursive scanning automatically unpacks archives such as zips, wheels, etc.. and scans the content
- Support scanning also non-python files - plugins can work in a “raw-file” mode such as the built-in Yara integration
- Scan for hardcoded secrets, passwords, and other sensitive information
- Custom diff engine - you can compare changes between different data sources such as typosquatting PyPI packages to what changes were made
- Works for both Python 2.x and Python 3.x source code
- High performance, designed to scan the whole PyPI repository
- Output in numerous formats such as pretty plain text, JSON, SQLite, SARIF, etc…
- Tested on over 4TB of compressed python source code
- Aura is able to report on code behavior such as network communication, file access, or system command execution
- Compute the “Aura score” telling you how trustworthy the source code/input data is
- and much much more…

Didn't find what you are looking for? Aura's architecture is based on a robust plugin system, where you can customize almost anything, ranging from a set of data analyzers, transport protocols to custom out formats.


Installation
============


::

    # Via pip:
    pip install aura-security[full]
    # or build from source/git
    poetry install --no-dev -E full

Or just use a prebuild docker image ``sourcecodeai/aura:dev``


Running Aura
============

::

    docker run -ti --rm sourcecodeai/aura:dev scan pypi://requests -v

Aura uses a so-called URIs to identify the protocol and location to scan, if no protocol is used, the scan argument is treated as a path to the file or directory on a local system.


.. image:: files/imgs/aura_scan.png


Diff packages::

    docker run -ti --rm sourcecodeai/aura:dev diff pypi://requests pypi://requests2


.. image:: docs/source/_static/imgs/aura_diff.png


Find most popular typosquatted packages (you need to call ``aura update`` to download the dataset first)::

    aura find-typosquatting --max-distance 2 --limit 10


.. image:: https://asciinema.org/a/367999.svg
   :target: https://asciinema.org/a/367999

----

.. image:: files/imgs/download_dataset.png
   :target: https://cdn.sourcecode.ai/pypi_datasets/index/datasets.html
   :align: center
   :width: 256


Why Aura?
---------

While there are other tools with functionality that overlaps with Aura such as Bandit, dlint, semgrep etc. the focus of these alternatives is different which impacts the functionality and how they are being used. These alternatives are mainly intended to be used in a similar way to linters, integrated into IDEs, frequently run during the development which makes it important to **minimize false positives** and reporting with clear **actionable** explanations in ideal cases.

Aura on the other hand reports on ** behavior of the code**, **anomalies**, and **vulnerabilities** with as much information as possible at the cost of false positive. There are a lot of things reported by aura that are not necessarily actionable by a user but they tell you a lot about the behavior of the code such as doing network communication, accessing sensitive files, or using mechanisms associated with obfuscation indicating a possible malicious code. By collecting this kind of data and aggregating it together, Aura can be compared in functionality to other security systems such as antivirus, IDS, or firewalls that are essentially doing the same analysis but on a different kind of data (network communication, running processes, etc).

Here is a quick overview of differences between Aura and other similar linters and SAST tools:

- **input data**:
    - **Other SAST tools** - usually restricted to only python (target) source code and python version under which the tool is installed.
    - **Aura** can analyze both binary (or non-python code) and python source code as well. Able to analyze a mixture of python code compatible with different python versions (py2k & py3k) using **the same Aura installation**.
- **reporting**:
    - **Other SAST tools** - Aims at integrating well with other systems such as IDEs, CI systems with actionable results while trying to minimize false positives to prevent overwhelming users with too many non-significant alerts.
    - **Aura** - reports as much information as possible that is not immediately actionable such as behavioral and anomaly analysis. The output format is designed for easy machine processing and aggregation rather than human readable.
- **configuration**:
    - **Other SAST tools** - The tools are fine-tuned to the target project by customizing the signatures to target specific technologies used by the target project. The overriding configuration is often possible by inserting comments inside the source code such as ``# nosec`` that will suppress the alert at that position
    - **Aura** - it is expected that there is little to no knowledge in advance about the technologies used by code that is being scanned such as auditing a new python package for approval to be used as a dependency in a project. In most cases, it is not even possible to modify the scanned source code such as using comments to indicate to linter or aura to skip detection at that location because it is scanning a copy of that code that is hosted at some remote location.


Authors & Contributors
======================

* **Martin Carnogursky** - *Initial work and project lead* - https://is.muni.cz/person/410345
* **Mirza Zulfan** - *Logo Design* - https://github.com/mirzazulfan


Donate
======

* GitHub Sponsors: https://github.com/sponsors/RootLUG
* Liberapay: https://liberapay.com/SourceCode.AI
* BuyMeACoffee: https://www.buymeacoffee.com/SourceCodeAI
* BTC: 3FVTaLsLwTDinmDjPh3BjS1qv3bYHbkcYc
* XMR: 46xvWZGCexo1NbvjLMMpLB1GhRd819AQr8eFPJT1q6kKMuuDy43JLiESh9XUM3asjk4SVUYqGakFVQZRY1adx8cS6ka4EXr
* ETH/ERC20: 0x708F1A08E3ee4922f037673E720c405518C0Ec85


LICENSE
=======
Aura framework is licensed under the **GPL-3.0**.
Datasets produced from global scans using Aura are released under the **CC BY-NC 4.0** license.
Use the following citation when using Aura or data produced by Aura in research:

::

    @misc{Carnogursky2019thesis,
    AUTHOR = "CARNOGURSKY, Martin",
    TITLE = "Attacks on package managers [online]",
    YEAR = "2019 [cit. 2020-11-02]",
    TYPE = "Bachelor Thesis",
    SCHOOL = "Masaryk University, Faculty of Informatics, Brno",
    SUPERVISOR = "Vit Bukac",
    URL = "Available at WWW <https://is.muni.cz/th/y41ft/>",
    }


.. |homepage_flair| image:: https://img.shields.io/badge/Homepage-aura.sourcecode.ai-blue
   :target: https://aura.sourcecode.ai/
   :align: middle

.. |docs_flair| image:: https://img.shields.io/badge/-Documentation-blue
   :target: https://docs.aura.sourcecode.ai/
   :align: middle

.. |docker_flair| image:: https://img.shields.io/badge/docker-SourceCodeAI/aura-blue
   :target: https://hub.docker.com/r/sourcecodeai/aura
   :align: middle

.. |license_flair| image:: https://img.shields.io/github/license/SourceCode-AI/aura?color=blue

.. |travis_flair| image:: https://travis-ci.com/SourceCode-AI/aura.svg?branch=dev

.. |pypi_flair| image:: https://badge.fury.io/py/aura-security.svg
   :target: https://pypi.org/project/aura-security/
   :align: middle
