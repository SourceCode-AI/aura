Creating a path based analyzer
==============================

A path based analyzer receives a path to the file on a local filesystem as an input. In general, it should not care what kind of file this path is pointing to, it can be for example an image, binary executable, empty file, text file or a python source code. The path based analyzer is intended to work with a binary data or other file attributes instead of a parsed AST source code of a python source code.

As an example we will write a path based analyzer that takes the path as input and checks permissions of the file that we are scanning.

We will use the following empty template to start the development of our analyzer:

.. literalinclude:: ../templates/path_analyzer.py
   :linenos:
   :language: python


Our analyzer will receive a location keyword argument that is an instance of the `ScanLocation` class. This objects contains a pointer to the current file being analyzer by Aura. We will perform a file permission check on the input file to see if the permissions are too wide (e.g. 777/rwxrwxrwx) or if the file is owned by root. When we detect such problem, we will report it back to the framework by yielding an instance of the Detection class.

.. warning::
    Detections reported by the analyzer must be hashable objects as Aura performs a deduplication based on hash. By default a `Detection.signature:str` attribute is used to compute the hash unless the __hash__ method is overridden in the `Detection` subclass.

The implementation of our analyzer is following:

.. literalinclude:: path_analyzer.py
   :name: path_analyzer.py
   :linenos:
   :language: python


You can now run this analyzer via aura by using the `-a` cli switch that takes the path/importable module as argument.

.. tip::
    By default all functions/classes tagged by analyzer in the module would be executed when running a custom analyzer module unless you specify a function name using the `:<function/class name>` after the path to the python script that contains the analyzer. E.g. `path_analyzer.py:file_permission_analyzer`


We can now test our analyzer by creating a sample file under the quarantine folder:

::

    bash$ touch quarantine/permission_test
    bash$ chmod 777 quarantine/permission_test
    bash$ aura scan -a path_analyzer.py quarantine/permission_test

    ╒════════════════════════════════════════════════════════════════════════════════════════════╕
    ├░░░░░░░░░░░░░░░░░░░░░░░ Scan results for quarantine/permission_test ░░░░░░░░░░░░░░░░░░░░░░░░┤
    │ Scan score: 10                                                                             │
    │                                                                                            │
    │ Critical severity - 0x                                                                     │
    │ High severity - 0x                                                                         │
    │ Medium severity - 0x                                                                       │
    │ Low severity - 1x                                                                          │
    │ Unknown severity - 0x                                                                      │
    │                                                                                            │
    ├░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ No imported modules detected ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░┤
    ├░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ Code detections ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░┤
    ╞════════════════════════════════════════════════════════════════════════════════════════════╡
    ├░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ FilePermissions / Low severity ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░┤
    ├┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┤
    │ File permissions are too open (777)                                                        │
    ├┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┤
    │ Line N/A at quarantine/permission_test                                                     │
    ├┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┤
    │ Score: 10                                                                                  │
    │ Tags:                                                                                      │
    │ Extra:                                                                                     │
    │ {}                                                                                         │
    ╘════════════════════════════════════════════════════════════════════════════════════════════╛
    2020-09-20 17:43:23,803 - aura.commands - INFO - Scan finished in 0.1174173355102539 s


.. tip::
    You can make your analyzer available to Aura automatically by installing it via setup tools using the following syntax for the `aura.analyzers` entrypoint, for example:
    ::

        archive = aura.analyzers.archive:archive_analyzer

    where ``aura.analyzers.archive`` is an importable module and ``archive_analyzer`` is the name of the function/class within that module that contains the analyzer implementation.
