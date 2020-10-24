Global PyPI Scan
================

The Aura team conducts periodic scans of the PyPI repository on a best effort basis where we scan the latest version of all published packages. The diagram below depicts an overview of the architecture being used to conduct these scans:

.. image:: /_static/imgs/architecture.png


The central piece of this is a Synology server which hosts an offline copy of the PyPI repository. This offline repository is being synced periodically every hour with the official PyPI repository using `bandersnatch <https://pypi.org/project/bandersnatch/>`_ via custom `dataset update scripts <https://gitlab.com/SourceCode.AI/aura-dataset-update>`_. The synchronization is invoked using scheduled Gitlab CI pipelines on a runner hosted on the server. After the PyPI synchronization is finished, new :ref:`datasets` are being re-generated where applicable and uploaded to our CDN for public access.

.. sidebar:: SSD cache

    We scan only the latest package releases (of all types such as wheels, sdists, bdists, etc.) available at the time of scan so the disk space requirements on the SSD cache are lower than the main offline PyPI repository.


The PyPI scan itself is done on a separate high-performance worker node. While it is possible to scan the offline PyPI repository directly we opted for a few changes to increase the performance and avoid problems such as network outages. We observed that the network latency and time to transfer the PyPI packages from NAS to the worker node were severely impacting the performance and total run time of the scan.

The worker node has a fast SSD disk dedicated to caching the packages for the scan that are prefetched from the offline PyPI mirror right before the scan starts. After the prefetch is completed a full scan of all packages is conducted by running parallel Aura scans. All scripts used on the worker node are available under the ``files/`` directory at the root of the Aura repository.


Technical specification of the worker node:

===== =====
CPU   AMD Ryzen 9 3900X 12-Core Processor
RAM   HyperX 32GB Kit DDR4 3200MHz CL16 XMP
GPU   SAPPHIRE NITRO+ Radeon RX 580 OC 8G
Disk  2x Intel 660p M.2 2TB SSD NVMe
OS    Windows 10 with Aura running inside WSL2 Ubuntu 18.04
===== =====
