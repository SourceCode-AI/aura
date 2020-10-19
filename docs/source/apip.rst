apip
====

Aura contains an experimental wrapper around the ``pip`` command that would intercept any package installation and sends it to Aura for analysis.
This wrapper is available under the `<project root>/aura/apip.py` and can be copy/pasted into your bin directory. this is done automatically in case the framework is installed via poetry. apip requires having the ``AURA_PATH`` environment variable set to point to the aura installation, e.g. the `aura` command, which you can find by running ``which aura`` in your shell. Usage of apip is exactly the same as using the pip command, it proxies everything behind the scenes to the pip script and monkey patch the pip installation to allow intercepting of the package installation.

As pip itself does not provide any standard mechanism to hook into package installation, the ``apip`` is using a monkey patching technique to modify existing pip structures to be able to intercept package installations. We are trying to push for a native functionality using this GitHub issue ticket: https://github.com/pypa/pip/issues/8938 .
