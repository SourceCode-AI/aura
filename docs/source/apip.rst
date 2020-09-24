apip
====

Aura contains an experimental wrapper around the ``pip`` command that would intercept any package installation and sends it to Aura for analysis.
This wrapper is available under the `<project root>/aura/apip.py` and can be copy/pasted into your bin directory. this is done automatically in case the framework is installed via poetry. apip requires to have the ``AURA_PATH`` environment variable set to point to the aura installation, e.g. the `aura` command, which you can find by running ``which aura`` in your shell. Usage of apip is exactly the same as using the pip command, it proxies everything behind the scenes to the pip script and monkey patch the pip installation to allow intercepting of the package installation.
