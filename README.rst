.. image:: files/logo/logotype.png


======

.. image:: https://travis-ci.com/SourceCode-AI/aura.svg?branch=dev

Security auditing and static code analysis
=================================================

Aura is a static analysis framework developed as a response to ever increasing threat of malicious packages and vulnerable code published on PyPI.


Project goals:

* provide an automated monitoring system over uploaded packages to PyPI, alert on anomalies that can either indicate an ongoing attack or vulnerabilities in the code
* enable an organization to conduct automated security audits of the source code and implement secure coding practices with a focus on auditing 3rd party code such as python package dependencies
* allow researches to scan code repositories on a large scale, create datasets and perform analysis to further advance research in the area of vulnerable and malicious code dependencies


============= ======
License       GPLv3
Documentation docs.aura.sourcecode.ai
Homepage      aura.sourcecode.ai
Docker        https://hub.docker.com/r/sourcecodeai/aura
============= ======


Why Aura?
---------

While there are other tools with a functionality that overlaps with Aura such as Bandit, dlint, semgrep etc. the focus of these alternatives is different which impacts functionality and how they are being used. These alternatives are mainly intended to be used in a similar way to linters, integrated into IDEs, frequently run during the development which makes it important to **minimize false positives** and reporting with clear **actionable** explanation in ideal cases.

Aura on the other hand reports on **behaviour of the code**, **anomalies** and **vulnerabilities** with as much information as possible at the cost of false positive. There are a lot of things reported by aura that are not necessarily actionable by a user but they tell you a lot about the behaviour of the code such as doing network communication, accessing sensitive files or using mechanisms associated with obfuscation indicating a possible malicious code. By collecting this kind of data and aggregating it together, Aura can be compared in functionality to other security systems such as antivirus, IDS or firewalls that are essentially doing the same analysis but on a different kind of data (network communication, running processes etc).

Here is a quick overview of differences between Aura and other similar linters and SAST tools:

- **input data**:
    - **Other SAST tools** - usually restricted to only python (target) source code and python version under which the tool is installed.
    - **Aura** can analyze both binary (or non python code) and python source code as well. Able to analyze a mixture of python code compatible with different python versions (py2k & py3k) using **the same Aura installation**.
- **reporting**:
    - **Other SAST tools** - Aims at integrating well with other systems such as IDEs, CI systems with actionable results while trying to minimize false positives to prevent overwhelming users with too much non-significant alerts.
    - **Aura** - reports as much information as possible that is not immediately actionable such as behavioral and anomaly analysis. Output format is designed for easy machine processing and aggregation rather then human readable.
- **configuration**:
    - **Other SAST tools** - The tools is fine-tuned to the target project by customizing the signatures to target specific technologies used by the target project. Overriding configuration is often possible by inserting comments inside the source code such as ``# nosec`` that will suppress the alert at that position
    - **Aura** - it is expected that there is little to no knowledge in advance about the technologies used by code that is being scanned such as auditing a new python package for approval to be used as a dependency in a project. In most cases, it is not even possible to modify the scanned source code such as using comments to indicate to linter or aura to skip detection at that location because it is scanning a copy of that code that is hosted at some remote location.


Installation
============

::

    poetry install --no-dev -E full

Or just use a prebuild docker image ``sourcecodeai/aura:dev``


Running Aura
============

::

    docker run -ti --rm sourcecodeai/aura:dev scan pypi://requests -v

Aura uses a so called URIs to identify the protocol and location to scan, if no protocol is used, the scan argument is treated as a path to the file or directory on a local system.


Diff packages::

    docker run -ti --rm sourcecodeai/aura:dev diff pypi://requests pypi://requestes


Authors & Contributors
======================

* **Martin Carnogursky** - *Initial work and project lead* - https://is.muni.cz/person/410345
* **Mirza Zulfan** - *Logo Design* - https://github.com/mirzazulfan
