============
Running Aura
============

.. _docker_image:

---------------------
Official Docker image
---------------------

A stable (master) release of Aura has an official docker image that can be run via the following command:

::

    docker run -ti --rm sourcecodeai/aura:dev scan <uri_to_scan>

.. sidebar:: Lite version

    We also provide docker images for lite version - a minimal installation that includes only the core dependencies. This version is available under the `dev-lite` docker tag.


The docker image also contains an override command `run_tests` that would execute a full unit test suite to verify the Aura functionality inside the docker image. Configuration files are located under the `/config` directory inside the docker image and if no configuration is provided a default one is copied (including semantic signatures and yara rules) to the `/config` directory when container starts. You can override this behaviour by mounting your own config directory/files inside the container or setting the `AURA_CFG` environment respectively.

------------------------
Scanning the source code
------------------------

The core part of the framework is scanning the source code to find anomalies as defined in the semantic rules, which can be done by running `aura scan <path_to_file_or_directory>`. There are several protocols supported for input and output data, for example `aura scan pypi://requests` would download and scan the latest release of a `requests` package directly from PyPI. You can pass these URIs to aura to specify the input source for data (provided by plugins) and/or even filter the input data (such as scanning a specific package release version). By default, if no URI protocol is specified, aura assumes it is a path on a local filesystem to a file or a directory. You can use the same method to also specify the format for the output data such as `aura scan ./quarantine -f json` which would output the scan data in a json format. Aura framework also supports specifying more then one output type so you can display the data for example into both, stdout as text format and as json into the file using `aura scan ./quarantine -f text -f json://my_results.json`. More command line options and format options are described in the :ref:`aura_scan_cli` documentation.

----------
Exit codes
----------

Different exit codes are used to communicate the status of a scan in case aura is used in a scripted pipeline such as bash scripts or CI integration.
The following table gives an overview of the exit codes used by Aura:

==== ===========
Code Explanation
==== ===========
0    Code scan completed successfully, passing all audit checks
1    An error occurred during the code scan or the audit checks haven't passed
2    This feature is disabled. This is most likely caused by missing dependencies. Run `aura info` for explanation.
==== ===========
