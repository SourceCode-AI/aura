===========
Development
===========

This document outlines procedures, generic workflow, and tips for developing the Aura framework and/or associated plugins.

----------------
End to end tests
----------------

Aura contains a mixture of several test types. There are standard tests that are testing a small portion of the intended functionality, other tests include a so-called end-to-end test. These types of tests execute Aura using a CLI runner, simulating running Aura via command line using specific CLI options. Such tests are very heavy and resource intensive (as compared to standard tests) but are very helpful in ensuring the functionality of a framework is not broken when running Aura via CLI. E2E tests are disabled by default and can be enabled using the ``--e2e`` CLI option for pytest, it is required for e2e tests to pass when doing a new release or merging a pull request/branch.


----------------
Mutation testing
----------------

We highly recommend to run mutation tests after significant modifications and/or adding new features to the Aura framework. Use the following command to run the mutation tests:

::

    mutmut run --paths-to-mutate="aura/" --tests-dir="tests/" --runner="pytest -x tests/"

Please refer to the mutmut documentation on how to interpret the results and use mutation testing to improve the test coverage: https://mutmut.readthedocs.io/en/latest/

