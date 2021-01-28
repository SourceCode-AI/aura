Typosquatting
=============

One of the main features in Aura and the goal of this project is to provide tools and techniques for investigating possible typosquatting packages and related attack vectors on package managers (namely PyPI).

.. warning::
	This document is still a work in progress and should be treated as a draft in the current state

Indicators
----------

During the investigation of existing typosquatting, we gathered a set of indicators that could be used to get a better understanding of possible typosquatting attacks.  Threat actors often just clone the target package, add modifications (malware, backdoor, etc...), and publish the typosquatting package. This cloning of the package would also result in either completely or near similar metadata information as compared to the original.

Name of the package
    This of course needs to be different from the original as the threat actor does not have permission to overwrite the original package files. A common trend in the name is that the typosquatting name would have a very small edit distance to the original (Levenshtein or similar metric). This depends on the typosquatting technique used as in some cases the edit distance can be relatively high but the name would consist of shuffling the words of the original package, for example ``django-models`` vs ``models-django``

Description
    Package description is often completely copied from the original resulting in a perfect match.

Repository URL
    Often copied (e.g. exactly the same) or removed. There is no guarantee that if a repository URL is provided that it links to the original source from which the package was produced (e.g. reproducible builds) and thus the information provided in this field should not be trusted.

Classifiers
    Copied or removed completely

Authors
    Copied, removed, or modified. This field is taken from a package metadata and should not be trusted to provide correct information

Maintainers
    Modified with a disjoint set as compared to the original. This list of maintainers is taken from the PyPI (warehouse) system based on which users have permissions to access the project namespace. As this information is not user-defined it is thus hard to forge/tamper with and can be (relatively) trusted. In case of malware/typosquatting attack, it is expected that a list of maintainers is disjoint from the set of maintainers of the original project. Otherwise, the attacker would have access to the original project and would leverage that to modify the existing package (more stealth approach) rather than doing it via a typosquatting attack (relying on a human error).

Release history
    Threat actors often clone the latest available version of the original package, modify it, and re-release it as typosquatting. We can often see that if the package had more than one release over time (ss it is common with popular projects/likely targets), those previous versions would be most likely completely missing from the typosquatting package. In this case, a reliable indicator is that the typosquatting package releases are a subset of the releases of the original package.

Distribution packages
    PyPI provides several types of python packages to be hosted/available for a given package release. The standard distribution types are source distributions (sdists), egg files, and compiled wheels. Sdist files for our purpose contains more information as compared to the other types as they include almost all (relevant) files available in the source repository as compared to wheels. For optimization, wheel files have been created to provide a pre-compiled version of python packages, this is usually bound to a specific OS or python version, which results in multiple wheels being published. It would be very hard for the attacker to completely replicate the exact set of provided distribution packages, especially if the package requires compilation (e.g. non-pure-python package). We have observed that typosquatting packages provide often a very limited subset of the distributions as compared to the original or are vastly different.


The list of indicators listed above provides a good overview of what to look for when judging if a package is a typosquatting another package or if it's just a coincidence that they have similar names and are legitimate. We mentioned some indicators that are either copied or removed; This does not necessarily mean that there may not be any kind of modifications (e.g. 1:1 copy or nothing) which is more common. The reason for this is that while it can be an exact copy of when the typosquatting package was created, the original package is also being updated over time. Authors can modify the description, classifiers, and other information of the original package. Typosquatting attacks are often "one-shot" and not updated over time with changes tracking the original package. This would result in modifications the longer the offending package is alive/present and the differences in the information would often retain a high similarity ratio with the original one.

It is also worth noting that we have observed several different strategies of what kind of content the typosquatting package provides. The simplest form is just creating a minimal package (in terms of content) that contains just the malicious code. This would however quickly raise suspicion as the intended functionality is missing, prompting the developer to investigate more closely and potentially finding out he/she installed a typosquatting package. An "improved" version of the attack can be made by copying the original package content and modifying it to include the malicious code. After installation of the package, the intended functionality is presently making it very likely for the attack to go unnoticed. This is indeed also the most common scenario we see in the wild at this moment. There is an approach combining the previous two. Creating a minimal package that contains the malicious code and declare a dependency on the original package.


Typosquatting in Aura
---------------------

Aura provides a set of built-in features to aid in the research and investigation of possible typosquatting packages.
We have created a scoring system that is designed for prioritization (sorting) of possible typosquatting pairs and also to filter out noise.

Aura provides a CLI interface that would output and enumerate possible pairs of typosquatting packages, the generated pairs depend on installed plugins that provide various techniques for the discovery of such packages.

::

    aura find-typosquatting

.. image:: /_static/imgs/aura_find_typosquatting.png


To investigate a specific typosquatting package, aura provides a diff functionality which is designed to highlight modifications done to the original package as well as comparison of metadata information between original and typosquatting package. The aura diff functionality also compares the code on semantic level by diffing produced detections which are used to produce static behavioral indicators of a modified code.

.. image:: /_static/imgs/aura_diff.png
