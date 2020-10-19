Datasets
========

Several datasets are frequently published by the SourceCode.AI team that are not required to run Aura but can provide a much accurate results if the datasets are used being and frequently updated. Below is an overview of available datasets that are frequently published by the Aura team.


PyPI download stats
-------------------

This datasets contains aggregated statistics of package downloads from the official PyPI repository for the last 30 days. It contains a name of the package and how many times it was downloaded in the 30 days. This is accomplished by aggregating the networks logs that are `published in the open dataset on google big query <https://packaging.python.org/guides/analyzing-pypi-package-downloads/>`_. The main usage is to calculate the popularity of a given package which is used as several places such as computing the aura score or in a typosquatting protection where it's suspicious for a package with very low number of downloads to have a very similar name to a package with a very high number of downloads. Google Big Query offers a free tier that is based/priced on amount of data analyzed and as such the current refresh period for this dataset is around 3 days.


PyPI Package list
-----------------

This dataset simply contains just a list of all packages present in our offline PyPI mirror that is being used by the Aura team to conduct global PyPI scans. It is updated every hour when a mirror synchronization is triggered. This dataset is not being used by Aura directly at the moment.


PyPI dependency list
--------------------

This is an aggregation of a package JSON metadata files from which we extracted a list of dependencies on other packages. This dataset is generated every hour when a mirror synchronization is triggered; not used directly by Aura.


PyPI reverse dependencies list
------------------------------

This is an aggregation and normalization of the previous PyPI dependency list that just reverses the direction of dependencies, e.g. for each package it lists other packages that have the package in it's dependencies. This dataset is used by Aura to compute scoring mechanism and importance of a package, when more packages include it it's dependencies, the higher the importance and `aura score` of the package is.

========================= ========================================================= ============= ============
Dataset name              URL                                                       Update period Note
========================= ========================================================= ============= ============
MD5 checksums             https://cdn.sourcecode.ai/aura/md5_checksums.txt          ~1 hour       Contains MD5 checksums of all published datasets
PyPI package list         https://cdn.sourcecode.ai/aura/pypi_package_list.gz       ~1 hour
PyPI download stats       https://cdn.sourcecode.ai/aura/pypi_download_stats.gz     ~3 days
PyPI dependency list      https://cdn.sourcecode.ai/aura/dependency_list.gz         ~1 hour
PyPI reverse dependencies http://cdn.sourcecode.ai/aura/reverse_dependencies.gz     ~1 hour
Aura update dataset       https://cdn.sourcecode.ai/aura/aura_dataset.tgz           ~1 hour       Contains all the datasets required by aura in a single archive
========================= ========================================================= ============= ============
