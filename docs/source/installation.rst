============
Installation
============


.. sidebar:: Aura docker image

    If you just want to try out Aura then it is highly recommended to run the Aura via a provided docker image instead of self-installing it as described in the :ref:`docker_image`. Local installation, on the other hand, provides a benefit of significantly increasing the speed of scans that is useful for example when doing research or customizing the framework.

This framework is intended to run under Python 3.7+. It is also possible to scan a Python 2.7, in such case, the framework is still installed under the Python 3.7+ but uses Python 2.7 interpreter to parse the source code, this is done automatically. It is highly recommended to have both interpreters configured (as it is by default) which maximizes the code compatibility.


Aura can be installed using poetry:

::

    poetry install --no-dev -E full
    pytest tests/  # Verify the installation
    aura update  # (Optional) Update to the latest dataset
    aura info # Display information about the Aura framework and available plugins


.. sidebar:: Lite version

    You can also install Aura in "lite" mode that excludes all optional dependencies and uses only core requirements needed to run the framework. Running `aura info` will then display information to you about missing dependencies that are required to enable specific plugins and integrations.


---------------------------
Updating the Aura framework
---------------------------


Updating the aura to the latest dataset versions is not needed but highly recommended. The dataset is not included in the framework itself as it is frequently updated and we recommend running `aura update` frequently. It mostly contains pre-computed statistics about packages published on PyPI that enables advanced features such as typosquatting analysis or reputation checks, which are disabled if the datasets are not present. As the data is changed frequently, you can receive false positives or incorrect information when scanning the source code with outdated datasets.
