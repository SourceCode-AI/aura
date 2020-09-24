Configuration
=============

Aura can be configured using two yaml files. The first one is the main framework configuration that configures the behaviour of the framework such as scoring system, restrictions or interpreters used to parse the source code. The second file is a list of semantic signatures and patterns to look for inside the files. The framework is bundled with a default set of configuration files which can be found under `<repository_root>/aura/data`.


CLI options
-----------

.. _aura_scan_cli:


Aura scan
^^^^^^^^^

-v              verbose, some detections items are hidden by default from output that are marked as informational such as file size of input data. Providing this flag would output also these informational data into the specified file format. This flag can be specified more then once. Second verbosity level would also output detectionbs filtered as false positives, such as AST parse errors for string blobs
-a              Analyzer name, can be specified more then once. Allows to override a list of default analyzers that are run on the input data.
-f              Output format
--min-score     Aura would not write any output information if the total score of the scanned input data is below this threshold
--benchmark     Run aura scan in a benchmark mode. This is intended for development purposes as it enables the python cProfile to run during the scan
--benchmark-sort    Sort benchmark profile by a given statistics name
--async     Run aura in async mode. After the input files are preprocessed, a separate process would be forked to scan that input file. Increases the speed of data scans in some circumstances, especially on multi-core machines.
--no-async  Disable the aura async mode.
-t      Filter output detections to only given tags. Detections can also be filtered to be excluded if they contain a given tag when prefixed by exclamation mark, e.g. `"!test-code"`


Scan Output format options
""""""""""""""""""""""""""

The following options are present for each of the built-in output URI formats:

::

    fmt://location?min_score=0&verbosity=1&tags=tag1,!tag2

* fmt - output format, can be either text, json or sqlite
* location - output location(file). If given the output is written to the path as specified by the location instead of stdout. Required for sqlite output format
* min_score - same as `--min-score` cli option for aura scan, specify the minimum score threshold after which is the output produced
* tags - filter detections for given tags, same as `-t` cli option
* verbosity - specify output verbosity, same as `-v` cli option


Aura diff
^^^^^^^^^

-f    Output format for the diff data
--detections    Enable scanning the diff data for detections. This is the same as performing the `aura scan` on the diff data. Detections are then diffed against each other in the same manner as diff is done on files, e.g. added/removed/modified. This option allows to semantically detect changes in the source code from the point of functionality and capabilities.
--no-detections     Disable the detections mode for diffed files.
--patch     Output the diff patch to show changes in text files
--no-patch  Disable the diff patch output
--output-same-renames   By default, if files between diffs are exactly the same but they only differ in a name, they are filtered from the diff output. This behaviour can be disabled by using this flag which would force to display diff also for same files that were just renamed.
--no-same-renames   Default behaviour, hide same files with only filenames changes/renames from the diff output.


Diff output format options
""""""""""""""""""""""""""

The following options are present for each of the built-in output URI formats:

::

    fmt://location?detections=true&output_same_renames=true&patch=true

* fmt - same meaning as for aura scan
* location - same meaning as for aura scan
* detections - enable/disable outputting detections diff
* output_same_renames - enable/disable hiding of a files that are same but only renamed
* patch - enable/disable output of a text diff patch


.. _aura_main_config:


Main configuration file
-----------------------

This a documented default configuration file

.. literalinclude:: ../../aura/data/aura_config.yaml
    :language: yaml


You can easily overwrite or extend this configuration file by using YAML anchors. This native feature of YAML allows you to merge existing YAML documents/parts into a single document. Aura requires you to prefix the YAML configuration with the `---`, which indicated it's a multi document file. When Aura detects this string at the beginning of the YAML configuration file, it injects the default configuration anchors into the document allowing you to inherit default configuration without a need of copy/pasting the unchanged parts.

An example of YAML file overriding the the configuration while preserving the default values:


::

    ---
    # Make sure to include the `---` prefix at the beginning of the document
    aura:
        # Inherit the default configuration section
        <<: *aura_config
        # Overwrite the default option
        min-score: 100
        # You can also insert new config options in case some plugins needs it
        custom_option: "yes please"


Signatures configuration file
-----------------------------

Default documented signatures file:

.. literalinclude:: ../../aura/data/signatures.yaml
    :language: yaml


Signature definitions can be overridden and extended in the same manner as the main configuration file by using YAML anchors and prefixing the config with the `---`.


Environment config options
--------------------------

The following environment variable configuration options can be used to configure the aura behaviour:

======================= =============================================================
Environment variable    Explanation
======================= =============================================================
AURA_CFG                Overwrite the path to the main configuration file
AURA_SIGNATURES         Overwrite the path to the configuration file for signatures/patterns
AURA_MIRROR_PATH        Location to the local pypi mirror repository
AURA_LOG_LEVEL          Output log level
AURA_NO_BLOBS           Disable extraction of data blobs for further analysis
AURA_NO_PROGRESS        Disable cli progress bar, useful when redirecting stderr and stdout
AURA_DEBUG_LINES        List of line numbers separated by ``,``. Aura will then call ``breakpoint()`` when traversing AST tree and it visits a node located on those specific line numbers
======================= =============================================================
