Introduction
============

.. mdinclude:: ../../README.md

Aura is a static analysis tool focused mostly on a python source code. Aura itself is a framework designed to parse the source code into an AST tree which is then scanned with installed analyzers. Other files other than source code are also supported such as images, raw data, executables, or any raw binary data in general. The framework also contains a taint analysis part which can be used to find unknown vulnerabilities by tracking how untrusted user input is propagated inside the program. The input data is never executed as the primary original use case was to find potential malware in packages hosted on PyPI.


Feature set:
    * Supports both Python 2.x and Python 3.x
    * Extremely fast, designed to scan the whole PyPI repository (over 4.8T of data)
    * Easily understand an unknown source code; Aura extract specific features of the source code such as doing network calls, executing system commands, and so on
    * Flexible configuration allowing to specify semantic signatures
    * Easy to use plugin system for custom analyzers
    * Output formats in JSON, plain text, and SQLite (with code snippets)
    * Scan the raw binary input data with integrations such as Yara
    * Recursive scanning by unpacking the archives


Use cases:
    * Enforce developer policies such as banning specific libraries, function calls (also with parameters), or any specific piece of code
    * Scan for potential vulnerabilities and problems or prevent data breaches by looking up hardcoded credentials
    * Scan terabytes of data to generate datasets or perform research on specific code practices
