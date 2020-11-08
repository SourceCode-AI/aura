.. _detections:

Built-in detections
===================

The following list is a comprehensive overview of all built-in detections in the Aura frame, provided output examples are in JSON format as the goal of this documentation page is to ease the analysis of a published dataset.


Top level format
----------------

Below is an example of the main JSON format produced by the Aura scan:

::

    {
      "detections": [
        // Contains the list of detection types
      ],
      "imported_modules": [
        // Aggregated module imports extracted from the `ModuleImport` detection type
        ".test_stock_picking_customer_ref",
        "odoo.api",
        "odoo.tests.common",
        ".stock_picking",
        "odoo.fields",
        "odoo.models",
        ".models"
      ],
      "tags": [
        // Aggregated set of tags collected from detections
        "url",
        "test_code"
      ],
      "metadata": {
        "format": [
          "json"
        ],
        "analyzers": [],
        "source": "cli",
        "fork": false,
        "output_opts": {
          "verbosity": 2
        },
        "name": "mirror://odoo10-addon-stock-picking-customer-ref",
        "uri_scheme": "mirror",
        "uri_input": {
          // Metadata associated from the parsed CLI input
          "package": "odoo10-addon-stock-picking-customer-ref",
          "package_opts": {
            "release": "latest"
          }
        },
        "depth": 0
      },
      "score": 0,  // Total score, sum of scores from the detections
      "name": "mirror://odoo10-addon-stock-picking-customer-ref"  // input as passed on the command line
    }


The `.detections[]` array contains various types of detections triggered by the scan. Please note that some of the detections might not appear in the output unless the verbose (``-v``) or extra verbose mode is used (``-vv``).


FunctionCall
^^^^^^^^^^^^

Detection as a result of an AST pattern match on the function call

::

    {
      "score": 0,
      "type": "FunctionCall",
      "severity": "unknown",
      "tags": [
        "taint_sink",
        "file_access"
      ],
      "extra": {
        "function": "open"  // Fully resolved name of the function including the module if any, for example `flask.Flask.run`
      },
      "line": "self._shellcodeFP = open(self._shellcodeFilePath, \"rb\")",
      "line_no": 615,
      "signature": "ast_pattern#open_file/615#/mnt/pypi_mirror/packages/9b/6e/fd9ae6d86fe8da323c9426b6bfc9933b42bc52691ee907521bc075154ca5/sqlmap-1.4.10.tar.gz$sqlmap-1.4.10/sqlmap/lib/takeover/metasploit.py",
      "message": "Code is accessing files via open",
      "location": "/mnt/pypi_mirror/packages/9b/6e/fd9ae6d86fe8da323c9426b6bfc9933b42bc52691ee907521bc075154ca5/sqlmap-1.4.10.tar.gz$sqlmap-1.4.10/sqlmap/lib/takeover/metasploit.py"
    }


ModuleImport
^^^^^^^^^^^^

Detection generated for each import statement

::

    {
      "score": 0,
      "type": "ModuleImport",
      "severity": "unknown",
      "extra": {
        "name": "binascii"
      },
      "line": "import binascii",
      "line_no": 1,
      "signature": "module_import#binascii#/mnt/pypi_mirror/packages/80/3b/9e2fa0d13c860b0e91c6b40fc98050bf3ecbb02ede66324b9f6a7ee91b5d/shellcodepatterns-0.1.tar.gz$shellcodepatterns-0.1/shellcodepatterns/__init__.py",
      "message": "Module 'binascii' import in a source code",
      "location": "/mnt/pypi_mirror/packages/80/3b/9e2fa0d13c860b0e91c6b40fc98050bf3ecbb02ede66324b9f6a7ee91b5d/shellcodepatterns-0.1.tar.gz$shellcodepatterns-0.1/shellcodepatterns/__init__.py"
    }

Base64Blob
^^^^^^^^^^

A string was found in the source code (post-processed AST) that is a valid base64 encoded blob of data

::

    {
      "score": 0,
      "type": "Base64Blob",
      "severity": "unknown",
      "tags": [
        "base64"
      ],
      "extra": {
        "base64_decoded": "https://www.tiktok.com/api/user/detail/"  // decoded payload
      },
      "line": "helper = base64.b64decode(\"aHR0cHM6Ly93d3cudGlrdG9rLmNvbS9hcGkvdXNlci9kZXRhaWwv\").decode()",
      "line_no": 11,
      "signature": "data_finder#base64_blob#-119572759001070983#-2548831473978034482",
      "message": "Base64 data blob found",
      "location": "/mnt/pypi_mirror/packages/7f/e3/46ed3fa11eb08ca42e88ef7f26567f317778c717ebace5e4c021b1dd1eef/tiky-1.0.6.tar.gz$tiky-1.0.6/tiky.py"
    }

Binwalk
^^^^^^^

Detection triggered by binwalk output run on the raw input data

::

    {
      "score": 0,
      "type": "Binwalk",
      "severity": "unknown",
      "tags": [
        "binwalk",
        "binwalk_signature"
      ],
      "extra": {
        "offset": 22739851,
        "module": "Signature"
      },
      "signature": "binwalk#22739851/19b0836a27c4872925e1df6d67b27790#/mnt/pypi_mirror/packages/0a/ae/90b6e7986c913c144793589db885516a42aad19eacba7b4c16e4117bc063/sourced-spark-api-0.0.12.tar.gz$sourced-spark-api-0.0.12/jars/spark-api-uber.jar",
      "message": "Signature: Zip archive data, at least v2.0 to extract, name: org/eclipse/jgit/transport/ReceiveCommand$1.class",  // Message from binwalk
      "location": "/mnt/pypi_mirror/packages/0a/ae/90b6e7986c913c144793589db885516a42aad19eacba7b4c16e4117bc063/sourced-spark-api-0.0.12.tar.gz$sourced-spark-api-0.0.12/jars/spark-api-uber.jar"
    }

CryptoKeyGeneration
^^^^^^^^^^^^^^^^^^^

Plugin detection that looks for crypto key generations to measure how they are generated

::

    {
      "score": 100,
      "type": "CryptoKeyGeneration",
      "severity": "critical",
      "extra": {
        "function": "Crypto.PublicKey.RSA.generate",
        "key_type": "rsa",
        "key_size": 1024
      },
      "signature": "crypto#gen_key#/mnt/pypi_mirror/packages/33/2f/ff513daa5da0bd81aac42650a377279547deebf79cfbe58868f0da179fe8/chval-0.6.7.tar.gz$chval-0.6.7/chval_core/crypto.py#45",
      "message": "Generation of cryptography key detected",
      "location": "/mnt/pypi_mirror/packages/33/2f/ff513daa5da0bd81aac42650a377279547deebf79cfbe58868f0da179fe8/chval-0.6.7.tar.gz$chval-0.6.7/chval_core/crypto.py"
    }


DataProcessing
^^^^^^^^^^^^^^

Detection informing about changes in the data processing pipeline, mostly used for indication of stopping further data processing such as when maximum depth is reached in recursive scans

::

    {
      "score": 0,
      "type": "DataProcessing",
      "severity": "unknown",
      "extra": {
        "reason": "max_depth",
        "location": "/mnt/pypi_mirror/packages/00/05/f8f48063cce63699734578b99ec4daba1ae6b4367071924d181d68af691f/codingsoho-auth-1.0.2.tar.gz$codingsoho-auth-1.0.2/authwrapper/urls.py:52$blob:53$blob"
      },
      "signature": "data_processing#max_depth#/mnt/pypi_mirror/packages/00/05/f8f48063cce63699734578b99ec4daba1ae6b4367071924d181d68af691f/codingsoho-auth-1.0.2.tar.gz$codingsoho-auth-1.0.2/authwrapper/urls.py:52$blob:53$blob",
      "message": "Maximum processing depth reached",
      "location": "/mnt/pypi_mirror/packages/00/05/f8f48063cce63699734578b99ec4daba1ae6b4367071924d181d68af691f/codingsoho-auth-1.0.2.tar.gz$codingsoho-auth-1.0.2/authwrapper/urls.py:52$blob:53$blob"
    }


Detection
^^^^^^^^^

Generic detection for semantic signatures that have not defined their custom name

::

    {
      "score": 0,
      "type": "Detection",
      "severity": "unknown",
      "extra": {
        "type": "high_entropy_string",
        "entropy": 5.832890014164737,
        "string": "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
      },
      "line": "chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'",
      "line_no": 10,
      "signature": "misc#high_entropy#/mnt/pypi_mirror/packages/2f/ee/6ad696ef6e59d46b26def2fe92ef17519047b9f24dc1443a84a9fa8ff85d/django_markdown_messaging-0.1.0-py3-none-any.whl$django_markdown_messaging/models.py#10",
      "message": "A string with high shanon entropy was found",
      "location": "/mnt/pypi_mirror/packages/2f/ee/6ad696ef6e59d46b26def2fe92ef17519047b9f24dc1443a84a9fa8ff85d/django_markdown_messaging-0.1.0-py3-none-any.whl$django_markdown_messaging/models.py"
    }


InvalidRequirement
^^^^^^^^^^^^^^^^^^

Detection triggered when a line in the requirements file could not be parsed/analyzed by Aura

::

    {
      "score": 0,
      "type": "InvalidRequirement",
      "severity": "unknown",
      "tags": [
        "cant_parse",
        "invalid_requirement"
      ],
      "extra": {
        "reason": "cant_parse",
        "line": "-r install.txt",
        "line_no": 1,
        "exc_message": "Parse error at \"'-r insta'\": Expected W:(abcd...)",
        "exc_type": "InvalidRequirement"
      },
      "signature": "req_invalid#/mnt/pypi_mirror/packages/e0/fc/bacea406af04cfbb6ae49ef9716ee8f696cbf0b4df37443fdf2fabcda15b/wagtailleafletwidget-1.0.1.tar.gz$wagtailleafletwidget-1.0.1/requirements/tests.txt/1",
      "message": "Could not parse the requirement for analysis",
      "location": "/mnt/pypi_mirror/packages/e0/fc/bacea406af04cfbb6ae49ef9716ee8f696cbf0b4df37443fdf2fabcda15b/wagtailleafletwidget-1.0.1.tar.gz$wagtailleafletwidget-1.0.1/requirements/tests.txt"
    }


LeakingSecret
^^^^^^^^^^^^^

Automatic detection of potential hardcoded passwords and other secrets such as API tokens, etc...

::

    {
      "score": 0,
      "type": "LeakingSecret",
      "severity": "critical",
      "tags": [
        "test_code"
      ],
      "extra": {
        "name": "Attribute(Call(Container(name='User', pointer=Import(names={'User': 'registration.ormmanager.tests.samodel.User', 'Group': 'registration.ormmanager.tests.samodel.Group', 'users_table': 'registration.ormmanager.tests.samodel.users_table', 'groups_table': 'registration.ormmanager.tests.samodel.groups_table', 'user_group_table': 'registration.ormmanager.tests.samodel.user_group_table', 'metadata': 'registration.ormmanager.tests.samodel.metadata'})))() . 'password')",
        "secret": "hammertime",
        "extra": {
          "type": "variable"
        }
      },
      "line": "u2.password='hammertime'",
      "line_no": 31,
      "signature": "leaking_secret#/mnt/pypi_mirror/packages/83/6f/c603de0b686d9e89b58b2bfc5875299955a48c5e423b8885c1c51a0b2c46/registration-0.50-py2.5.egg$registration/ormmanager/tests/testsa.py#31",
      "message": "Possible sensitive leaking secret",
      "location": "/mnt/pypi_mirror/packages/83/6f/c603de0b686d9e89b58b2bfc5875299955a48c5e423b8885c1c51a0b2c46/registration-0.50-py2.5.egg$registration/ormmanager/tests/testsa.py"
    }


MalformedXML
^^^^^^^^^^^^

Detection for XML files that did not pass strict checks which could cause issues when being parsed by an application or abused such as Billion laughs attack - DoS via resource exhaustion using expanding entities

::

    {
      "score": 100,
      "type": "MalformedXML",
      "severity": "critical",
      "tags": [
        "test_code",
        "malformed_xml",
        "xml_entities"
      ],
      "extra": {
        "type": "entities"
      },
      "signature": "malformed_xml#entities#/mnt/pypi_mirror/packages/ba/45/1211c364a62fc78bc7b20db8059854e9405c54f7648ede28ca30d508479f/diazo-1.4.0-py2.py3-none-any.whl$diazo/tests/entities/rules.xml",
      "message": "Malformed or malicious XML",
      "location": "/mnt/pypi_mirror/packages/ba/45/1211c364a62fc78bc7b20db8059854e9405c54f7648ede28ca30d508479f/diazo-1.4.0-py2.py3-none-any.whl$diazo/tests/entities/rules.xml"
    }


ArchiveAnomaly
^^^^^^^^^^^^^^

Triggered during the anomaly scan for supported archive formats. Could indicate in some cases a possible manipulation of archives (manual editing of a python package).
There are numerous reason this detection can be fired, such as:

- archive is corrupted and can't be successfully opened/extracted for analysis by Aura
- archive contains invalid references such as symlinks or absolute paths
- archive content is too big to be processed by Aura (zipbomb prevention)


::

    {
      "score": 100,
      "type": "ArchiveAnomaly",
      "severity": "critical",
      "extra": {
        "archive_path": "progressio-0.3.0/progressio/p",
        "reason": "member_is_link"
      },
      "signature": "archive_anomaly#link#/mnt/pypi_mirror/packages/4d/f5/0140cf9013b15574845120a71160c2684373944144204e2f2a1330d3d84c/progressio-0.3.0.tar.gz#progressio-0.3.0/progressio/p",
      "message": "Archive contain a member that is a link.",
      "location": "/mnt/pypi_mirror/packages/4d/f5/0140cf9013b15574845120a71160c2684373944144204e2f2a1330d3d84c/progressio-0.3.0.tar.gz"
    }

SuspiciousArchiveEntry
^^^^^^^^^^^^^^^^^^^^^^

Suspicious archive entry, detection is based on the name/path of the archive member such as the reference to parent directories and entries that do not fall under the `ArchiveAnomaly` because they have a higher severity

::

    {
      "score": 50,
      "type": "SuspiciousArchiveEntry",
      "severity": "high",
      "tags": [
        "test_code"
      ],
      "extra": {
        "entry_type": "parent_reference",
        "entry_path": "../../../../../../../../etc/passwd"
      },
      "signature": "suspicious_archive_entry#parent_reference#../../../../../../../../etc/passwd#/tmp/aura_pkg__sandbox0yvm6of9Archive-0.3.tar.gz/Archive-0.3/archive/test/evil.zip",
      "message": "Archive contains an item with parent reference",
      "location": "/mnt/pypi_mirror/packages/f7/37/bf86a96c30477011b6a48fa82cfdf0e6a616314ad229a4544b59b70dfd2f/Archive-0.3.tar.gz$Archive-0.3/archive/test/evil.zip"
    }

SuspiciousFile
^^^^^^^^^^^^^^

A suspicious file that is not expected to be inside the python package

::

    {
      "score": 5,
      "type": "SuspiciousFile",
      "severity": "unknown",
      "tags": [
        "ignore",
        "hidden_file"
      ],
      "extra": {
        "file_name": ".travis.yml",
        "file_type": "hidden_file"
      },
      "signature": "suspicious_file#/mnt/pypi_mirror/packages/1a/aa/4220d3089733c00d5edee8626f208b8abab0c995a084f6c04e56b17f0d9b/ib_insync-0.9.62.tar.gz$ib_insync-0.9.62/.travis.yml",
      "message": "A potentially suspicious file has been found",
      "location": "/mnt/pypi_mirror/packages/1a/aa/4220d3089733c00d5edee8626f208b8abab0c995a084f6c04e56b17f0d9b/ib_insync-0.9.62.tar.gz$ib_insync-0.9.62/.travis.yml"
    }


OutdatedPackage
^^^^^^^^^^^^^^^

Outdated package dependency in the requirements file

::

    {
      "score": 5,
      "type": "OutdatedPackage",
      "severity": "medium",
      "tags": [
        "outdated_package"
      ],
      "extra": {
        "package": "certifi",
        "specs": "==2020.4.5.1",
        "latest": "2020.6.20"
      },
      "signature": "req_outdated#/mnt/pypi_mirror/packages/7d/3b/b67e6ee05d19c5f20e7da853cf5d4f520e7cae087f03997907280f7472b6/searx-0.17.0.tar.gz$searx-0.17.0/requirements.txt#certifi#==2020.4.5.1#2020.6.20",
      "message": "Package certifi==2020.4.5.1 is outdated, newest version is 2020.6.20",
      "location": "/mnt/pypi_mirror/packages/7d/3b/b67e6ee05d19c5f20e7da853cf5d4f520e7cae087f03997907280f7472b6/searx-0.17.0.tar.gz$searx-0.17.0/requirements.txt"
    }

UnpinnedPackage
^^^^^^^^^^^^^^^

Unpinned python package dependency in the requirements file

::

    {
      "score": 10,
      "type": "UnpinnedPackage",
      "severity": "high",
      "tags": [
        "unpinned_package"
      ],
      "extra": {
        "package": "uuid"
      },
      "signature": "req_unpinned#/mnt/pypi_mirror/packages/b6/45/72372c1021a6e4fecca7487b8fde0f3e446beb311d97072be14c2a62c9b7/rdf2gremlin-0.1.38.tar.gz$rdf2gremlin-0.1.38/requirements.txt#uuid",
      "message": "Package uuid is unpinned",
      "location": "/mnt/pypi_mirror/packages/b6/45/72372c1021a6e4fecca7487b8fde0f3e446beb311d97072be14c2a62c9b7/rdf2gremlin-0.1.38.tar.gz$rdf2gremlin-0.1.38/requirements.txt"
    }

SQLInjection
^^^^^^^^^^^^

Potential SQL Injection vulnerability detected via AST patterns of string formatting and manipulation

::

    {
      "score": 50,
      "type": "SQLInjection",
      "severity": "high",
      "line": "cursor.execute('INSERT INTO subscribers VALUES (\\'{0}\\')'.format(subscriber))",
      "line_no": 124,
      "signature": "vuln#/mnt/pypi_mirror/packages/2f/b9/eaef4815a21e40dec0695497b6863bf6764b44854784dbe73f00ffdd43e4/trelloreporter-1.0.0.tar.gz$trelloreporter-1.0.0/trelloreporter/cmd/trelloreport.py#124",
      "message": "Possible SQL injection found",
      "location": "/mnt/pypi_mirror/packages/2f/b9/eaef4815a21e40dec0695497b6863bf6764b44854784dbe73f00ffdd43e4/trelloreporter-1.0.0.tar.gz$trelloreporter-1.0.0/trelloreporter/cmd/trelloreport.py"
    }

TaintAnomaly
^^^^^^^^^^^^

Potential vulnerability detected via taint analysis

::

    {
      "score": 10,
      "type": "TaintAnomaly",
      "severity": "critical",
      "extra": {
        "taint_log": [
          {
            "line_no": 167,
            "message": "Taint propagated by return/yield statement",
            "path": "/tmp/aura_pkg__sandboxpp6qf9opdisco-dop-0.5.2.tar.gz/disco-dop-0.5.2/web/treesearch.py",
            "taint_level": "TAINTED"
          }
        ]
      },
      "line": "return Response(stream_template('searchresults.html', **args))",
      "line_no": 167,
      "signature": "taint_anomaly#/mnt/pypi_mirror/packages/d5/0f/c7e6849af5f1619e563f0bfd735310bb3b1f07e853774382f34af5cb50bb/disco-dop-0.5.2.tar.gz$disco-dop-0.5.2/web/treesearch.py#167",
      "message": "Tainted input is passed to the sink",
      "location": "/mnt/pypi_mirror/packages/d5/0f/c7e6849af5f1619e563f0bfd735310bb3b1f07e853774382f34af5cb50bb/disco-dop-0.5.2.tar.gz$disco-dop-0.5.2/web/treesearch.py"
    }

SensitiveFile
^^^^^^^^^^^^^

Potentially sensitive file leaked inside the scanned input

::

    {
      "score": 100,
      "type": "SensitiveFile",
      "severity": "critical",
      "tags": [
        "pypirc",
        "sensitive_file"
      ],
      "extra": {
        "file_name": ".pypirc"
      },
      "signature": "<... censored ...>/.pypirc",
      "message": "A potentially sensitive file has been found",
      "location": "/mnt/pypi_mirror/packages/<... censored ...>/.pypirc"
    }

SetupScript
^^^^^^^^^^^

Anomaly found in a setup.py scripts, this is often triggered by doing highly suspicious operations such as eval/exec or network connections inside the setup.py

::

    {
      "score": 100,
      "type": "SetupScript",
      "severity": "critical",
      "tags": [
        "obfuscation",
        "taint_sink",
        "code_execution"
      ],
      "line": "exec(open(\"./osmwriter/_version.py\").read())",
      "line_no": 5,
      "signature": "setup_analyzer#code_execution#ast_pattern#python_code_execution/5#/mnt/pypi_mirror/packages/2a/bc/4f391615c35e15d8d4906a331215fa00b255c32b07ed2d5a3c7968070f36/openstreetmap-writer-0.2.1.tar.gz$openstreetmap-writer-0.2.1/setup.py",
      "message": "Code execution capabilities found in a setup.py script",
      "location": "/mnt/pypi_mirror/packages/2a/bc/4f391615c35e15d8d4906a331215fa00b255c32b07ed2d5a3c7968070f36/openstreetmap-writer-0.2.1.tar.gz$openstreetmap-writer-0.2.1/setup.py"
    }

Wheel
^^^^^

Anomaly found inside the wheel python package, this could in some cases indicate manual editing of a python package or a different suspicious manipulation

::

    {
      "score": 100,
      "type": "Wheel",
      "severity": "critical",
      "tags": [
        "wheel",
        "wheel_missing_file",
        "anomaly"
      ],
      "extra": {
        "record": "ezfnSetup\\__init__.pyc"
      },
      "signature": "wheel#missing_file#ezfnSetup\\__init__.pyc#/tmp/aura_pkg__sandboxwbx3f43cezfnSetup-0.0.5-py3-none-any.whl/ezfnSetup\\__init__.pyc",
      "message": "Wheel anomaly detected, file listed in RECORDs but not present in wheel",
      "location": "/mnt/pypi_mirror/packages/01/0a/a209c9c9fb8a45da3e067913dca7d58d6465908295a588ef0d83428741e5/ezfnSetup-0.0.5-py3-none-any.whl$ezfnSetup-0.0.5.dist-info/WHEEL"
    }


StringMatch
^^^^^^^^^^^

Triggered by one of the string patterns in semantic signatures

::

    {
      "score": 10,
      "type": "StringMatch",
      "severity": "low",
      "tags": [
        "test_code"
      ],
      "extra": {
        "signature_id": "tmp_folder",
        "string": "/tmp"
      },
      "line": "pw_dir='/tmp',",
      "line_no": 36,
      "signature": "string_finder#tmp_folder#d42b9c57d24cf5db3bd8d332dc35437f#/mnt/pypi_mirror/packages/30/1e/918ba8f49475be66b1a15eb92d965e4807c3c925be3840fb6e76bdb51c23/dhcpkit-1.0.7-py3.4.egg$dhcpkit/tests/common/privileges/test_privileges.py/36",
      "message": "regex match: Hardcoded tmp folder in the source code",
      "location": "/mnt/pypi_mirror/packages/30/1e/918ba8f49475be66b1a15eb92d965e4807c3c925be3840fb6e76bdb51c23/dhcpkit-1.0.7-py3.4.egg$dhcpkit/tests/common/privileges/test_privileges.py"
    }


File stats
^^^^^^^^^^

Generated for every input scanned by Aura. Can be used to reconstruct the (directory) structure of the input or pair several detections to the same input via generated hashes.

::

    {
      "score": 0,
      "type": "FileStats",
      "severity": "unknown",
      "extra": {
        "mime": "application/x-dosexec",
        "size": 1785344,
        "tlsh": "EE853994EBC760F1E9970872958BF76F5A3197028434CDFAEB586E8DFD33A32101A254",
        "md5": "7ea894b2e4945a75264f67d47340e697",
        "sha1": "6cb0be4b981dc34c0ea1197a87af09f3d4bcc74d",
        "sha256": "f7efde37940048fbcf6e4acb61cc9e62263e4b5bd8df291cdcfe1921d1f49579",
        "sha512": "1899ec854f95c76e7d4dfb51e2fd4f722848db9b76d273d2e9b746ae50dcfb97bd0b1b878ed87e5b3f9c9841b3c4556634a826afe1d2d4862bbc8a7b98c0f9e8"
      },
      "signature": "file_stats#/mnt/pypi_mirror/packages/21/d6/9c823de448276abb8d125bb81f20475eb1d8eb82e4365deb201916a8bcf9/pocsuite3-1.6.5-py2.py3-none-any.whl$pocsuite3/shellcodes/tools/objdump.exe",
      "message": "Statistics about files scanned by aura",
      "location": "/mnt/pypi_mirror/packages/21/d6/9c823de448276abb8d125bb81f20475eb1d8eb82e4365deb201916a8bcf9/pocsuite3-1.6.5-py2.py3-none-any.whl$pocsuite3/shellcodes/tools/objdump.exe"
    }


YaraMatch
^^^^^^^^^

Detection triggered by the Yara integration on the RAW input

::

    {
      "score": 0,  // copied from the Yara rule metadata `score`
      "type": "YaraMatch",
      "severity": "unknown",
      "tags": [
        "windows_executable"   // copied from the native Yara rule tags
      ],
      "extra": {
        "rule": "WindowsExecutable2",
        "strings": [
          "This program cannot"
        ],
        "meta": {}  // copy of the Yara rule metadata
      },
      "signature": "yara#/mnt/pypi_mirror/packages/21/d6/9c823de448276abb8d125bb81f20475eb1d8eb82e4365deb201916a8bcf9/pocsuite3-1.6.5-py2.py3-none-any.whl$pocsuite3/shellcodes/tools/ld.exe#WindowsExecutable2#2200139803858809946",
      "message": "Yara match 'WindowsExecutable2' signature",
      "location": "/mnt/pypi_mirror/packages/21/d6/9c823de448276abb8d125bb81f20475eb1d8eb82e4365deb201916a8bcf9/pocsuite3-1.6.5-py2.py3-none-any.whl$pocsuite3/shellcodes/tools/ld.exe"
    }

YaraError
^^^^^^^^^

Error triggered by the Yara integration when scanning the RAW input with Yara

::

    {
      "score": 0,
      "type": "YaraError",
      "severity": "unknown",
      "tags": [
        "yara_error"
      ],
      "signature": "yara_error#/mnt/pypi_mirror/packages/a8/04/8dc84a5005912983594883f458621d787345da6583c6143b598800b6909f/radiant-2.4.tar.gz$radiant-2.4/radiant/framework/static/radiant/fonts/mdi/fonts/materialdesignicons-webfont.svg",
      "message": "internal error: 30",
      "location": "/mnt/pypi_mirror/packages/a8/04/8dc84a5005912983594883f458621d787345da6583c6143b598800b6909f/radiant-2.4.tar.gz$radiant-2.4/radiant/framework/static/radiant/fonts/mdi/fonts/materialdesignicons-webfont.svg"
    }

ASTAnalysisError
^^^^^^^^^^^^^^^^

Problem encountered during the AST analysis

::

    {
      "score": 0,
      "type": "ASTAnalysisError",
      "severity": "unknown",
      "extra": {
        "iterations": 500
      },
      "signature": "ast_analysis_error#max_iterations#/mnt/pypi_mirror/packages/94/25/63519ece651e2849b3c9b66d88f2a189c1a75889382015abab1393e4fef1/retki-0.12.1.tar.gz$retki-0.12.1/retki/compiler.py",
      "message": "Maximum AST tree iterations reached",
      "location": "/mnt/pypi_mirror/packages/94/25/63519ece651e2849b3c9b66d88f2a189c1a75889382015abab1393e4fef1/retki-0.12.1.tar.gz$retki-0.12.1/retki/compiler.py"
    }

ASTParseError
^^^^^^^^^^^^^

A problem encountered when attempting to parse the input as a python source code via AST

::

    {
      "score": 0,
      "type": "ASTParseError",
      "severity": "unknown",
      "extra": {
        "stdout": "",
        "stderr": "Traceback (most recent call last):\n  File \"/home/intense/aura/aura/analyzers/python_src_inspector.py\", line 206, in main\n    src_dump = collect(source_code=source_code, encoding=encoding)\n  File \"/home/intense/aura/aura/analyzers/python_src_inspector.py\", line 176, in collect\n    src = ast.parse(source_code)\n  File \"/usr/lib/python2.7/ast.py\", line 37, in parse\n    return compile(source, filename, mode, PyCF_ONLY_AST)\n  File \"<unknown>\", line 14\n    from ${package}.registration.widgets import (NewUserFields, NewUserSchema, RegTableForm,\n         ^\nSyntaxError: invalid syntax\n"
      },
      "signature": "ast_parse_error#/mnt/pypi_mirror/packages/83/6f/c603de0b686d9e89b58b2bfc5875299955a48c5e423b8885c1c51a0b2c46/registration-0.50-py2.5.egg$registration/template/+package+/registration/controllers.py_tmpl",
      "message": "Unable to parse the source code",
      "location": "/mnt/pypi_mirror/packages/83/6f/c603de0b686d9e89b58b2bfc5875299955a48c5e423b8885c1c51a0b2c46/registration-0.50-py2.5.egg$registration/template/+package+/registration/controllers.py_tmpl"
    }


Misc
^^^^

Uncategorized detections

::

    {
      "score": 0,
      "type": "Misc",
      "severity": "unknown",
      "extra": {
        "regex": "<... very long data ...>"
      },
      "line": "<... very long data ...>",
      "line_no": 23,
      "signature": "misc#redos_recursion_error#/mnt/pypi_mirror/packages/8e/14/9ba339b75c6741764f206aa44d9a04cdace9670b6f54b2002a58c12024ac/ms_api-0.8.125-py3-none-any.whl$ms/protocol_pb2.py#23",
      "message": "Recursion limit exceeded when scanning regex pattern for ReDoS",
      "location": "/mnt/pypi_mirror/packages/8e/14/9ba339b75c6741764f206aa44d9a04cdace9670b6f54b2002a58c12024ac/ms_api-0.8.125-py3-none-any.whl$ms/protocol_pb2.py"
    }
