# Project Aura: Security assessment for package managers

**Warning: This project is still in Alpha state and under heavy development so expect changes that will break compatibility. Not recommended for production use yet**

This code is a PoC implementation part of my thesis. It aims to provide a framework for the monitoring and inspection of potentially malicious packages with a focus on detecting potentially malicious packages via typosquatting. The current implementation is targeting primarily PyPi although it tries to be universal with possibilities of adding other package managers such as npmjs, RubyGems, etc.

# About the problem

As a long time security researcher and developer, I noticed a big security gap in package managers used by developers. These days, developers tend to search often for packages that provide specific functionality and include them in their projects without thinking. Honestly, who these days audit the source code of the project dependencies that you use? It's extremely easy to just create a small package and publish it on PyPi with a small bonus included: backdoor, malware or crypto miner... Or perhaps you can't remember the exact name of a package and you blindly type `pip install setup-tools` and you just fell prey to the typosquatting attack because the real package is called `setuptools`. You might not even notice that because it provides the functionality of the original (legitimate) package.

Due to the nature of "GitHub style" economy of package repositories, there are almost no security controls in place to prevent the spread of malicious (or insecure) code. It is often by sheer luck when security incidents in which malicious actors were targetting developers by [creating fake packages using typosquatting techniques](http://www.nbu.gov.sk/skcsirt-sa-20170909-pypi/) with embedded backdoors or [compromising/hijacking existing packages by including malicious code](https://www.reddit.com/r/Python/comments/8hvzja/backdoor_in_sshdecorator_package/) are discovered. 

This project aims to improve this by providing a framework for security assessments of packages and monitoring of software repositories to detect malicious behavior. It is a PoC implementation part of my thesis based on research of previous infamous incidents with the following core parts:

### Package scanner

Attempts to perform a scan of a package as is distributed by the package manager in a safe environment (no code execution). Files are scanned using Yara signatures and in case of python source code, additional more semantic scan takes place which includes lookup of imported modules (such as network libraries used for exfiltrating data), using specific function calls (such as `eval`, `os.system`, etc...) and also tries to defeat some simple obfuscation techniques. The package is then categorized by assigning labels using characteristics such as:

* network communication - used commonly in backdoors for data exfiltration or communication with CnC
* calling system commands - the malicious code is often a hybrid of the script itself & executing OS native commands or commonly installed applications to achieve its objective
* accessing sensitive files - malware often look for "juicy" files to exfiltrate or spread to other devices such as ssh keys, passwords, bitcoin wallets
* persistence - malware usually want to survive reboots/shutdowns by using persistence mechanisms
* and many other, new characteristics are being added to help categorize the code behavior

After the scan is completed, the risk score is calculated (we call it "security aura" in this context), that express the safety of a package and it's attack surface. Please note that this score is not a definitive yes/no answer to the question if a package is malicious but merely just aids in judging the safety and should be used only as a reference. For example, it's perfectly normal for a package that is designed to be a wrapper around public API to use network communication mechanisms but a package that deals with colorized output in a terminal should not do that or look for your bitcoin wallet.

### Typosquatting finder

Using common typosquatting techniques, this module tries to find potential candidates for typosquatting in a package repository that attempts to lure developers in installing them, thinking they are legitimate. The output of this module is then used with the security package scanner and differ to analyze potential malicious candidates.

### Package differ
Enhanced diff on steroids for analyzing differences between given packages which works on two levels:

1. Metadata analyzer - malicious packages try to imitate the target using its metadata such as project description, homepage, documentation, GitHub link, etc.
2. Content analyzer - very similar to `diff` utility on file level that looks for differences in the source code which could be used to find modifications such as embedded backdoor or other malicious code

This module is used to further research typosquatting packages or hijacked packages by providing an audit trail of modifications.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

It is highly recommended that you have a full local PyPI mirror which is around ~1.4TB at the time of writing if you want to monitor the whole repository or do further research. You can do that easily with tools like [bandersnatch](https://bitbucket.org/pypa/bandersnatch). 
In the bandersnatch configuration under the *mirror* section, enable also the JSON metadata using the `json = true` option.

Most of the core modules support also the option of not having a local mirror and will download packages on-demand as needed directly from the online repository.

### Installing

Supported Python version for this project is **3.6+** and should be inside a virtual environment. In addition this default interpreter, you need to these symlinks:

- `python3` -> Points to the Python 3.6+ interpreter (could be the same as the one in a virtual environment)
- `python2` -> Points to the Python 2.7 interpreter

These symlinks are necessary for semantic code analysis as python 3 AST parser can't parse Python 2 code and vice versa. As it's used only for code analysis, these interpreters don't need any sandboxing/isolation (neither any dependencies installed) as there is no code execution done from the analyzed sample.

You would also need to install yara-python which is not included in the requirements itself. The reason is that yara API bindings will most likely not be compatible if you already have yara installed in your system. Follow the instructions [located here](https://yara.readthedocs.io/en/v3.4.0/gettingstarted.html#compiling-yara)  to install yara python bindings inside the virtualenv and verify that you can import yara module from within the environment.

To finish the installation, just install the project dependencies and the framework itself:

```
pip install -Ur requirements.txt
python setup.py install
```

It's recommended to run tests afterward:
```
pytest tests/
```
You would also need to configure signatures that the framework is using to compute the risk score saved as "signatures.json" and "rules.yara" in the CWD from where you run the security audit. This repository has examples of rules attached to get you started.


## Using the framework

Since the project is currently under heavy development in the alpha version, you should run all commands from the directory where you pushed the repository due to lookup of additional files.

### Scanning a package

Audit scanner supports several different protocols (called URI handlers) such as pulling packages directly from pypi/local files or PyPI mirrors. To list all the protocols as well as examples run `python -m aura.cli scan --help`

Example scan:

```
python -m aura.cli scan pypi://requests2
```

```
---[ Scan results for 'requests2-2.16.0-py2.py3-none-any.whl' ]---
Scan score: 45
Code categories: windows, network, obfuscation
Imported modules: socket, _winreg, base64, urllib3
- Rules hits:
 * ModuleImport(name='socket', location='requests2-2.16.0-py2.py3-none-any.whl$requests/utils.py', score=10, category='network')
 * ModuleImport(name='_winreg', location='requests2-2.16.0-py2.py3-none-any.whl$requests/utils.py', score=5, category='windows')
 * ModuleImport(name='base64', location='requests2-2.16.0-py2.py3-none-any.whl$requests/auth.py', score=20, category='obfuscation')
 * ModuleImport(name='socket', location='requests2-2.16.0-py2.py3-none-any.whl$requests/adapters.py', score=10, category='network')
 * ModuleImport(name='urllib3', location='requests2-2.16.0-py2.py3-none-any.whl$requests/__init__.py', score=10, category='network')

---[ Scan results for 'requests2-2.16.0.tar.gz' ]---
Scan score: 265
Code categories: windows, network, obfuscation, code_execution
Imported modules: socket, requests, _winreg, pickle, urllib3, base64
- Rules hits:
 * ModuleImport(name='socket', location='requests2-2.16.0.tar.gz$requests2-2.16.0/tests/testserver/server.py', score=10, category='network')
 * ModuleImport(name='requests', location='requests2-2.16.0.tar.gz$requests2-2.16.0/tests/test_utils.py', score=10, category='network')
 * ModuleImport(name='_winreg', location='requests2-2.16.0.tar.gz$requests2-2.16.0/tests/test_utils.py', score=5, category='windows')
 * ModuleImport(name='socket', location='requests2-2.16.0.tar.gz$requests2-2.16.0/tests/test_testserver.py', score=10, category='network')
 * ModuleImport(name='requests', location='requests2-2.16.0.tar.gz$requests2-2.16.0/tests/test_testserver.py', score=10, category='network')
 * ModuleImport(name='pickle', location='requests2-2.16.0.tar.gz$requests2-2.16.0/tests/test_requests.py', score=10, category='code_execution')
 * ModuleImport(name='requests', location='requests2-2.16.0.tar.gz$requests2-2.16.0/tests/test_requests.py', score=10, category='network')
 * ModuleImport(name='requests', location='requests2-2.16.0.tar.gz$requests2-2.16.0/tests/test_lowlevel.py', score=10, category='network')
 * ModuleImport(name='requests', location='requests2-2.16.0.tar.gz$requests2-2.16.0/tests/test_hooks.py', score=10, category='network')
 * ModuleImport(name='urllib3', location='requests2-2.16.0.tar.gz$requests2-2.16.0/tests/__init__.py', score=10, category='network')
 * FunctionCall(function='exec', location='requests2-2.16.0.tar.gz$requests2-2.16.0/setup.py', score=100)
 * ModuleImport(name='socket', location='requests2-2.16.0.tar.gz$requests2-2.16.0/requests/utils.py', score=10, category='network')
 * ModuleImport(name='_winreg', location='requests2-2.16.0.tar.gz$requests2-2.16.0/requests/utils.py', score=5, category='windows')
 * ModuleImport(name='base64', location='requests2-2.16.0.tar.gz$requests2-2.16.0/requests/auth.py', score=20, category='obfuscation')
 * ModuleImport(name='socket', location='requests2-2.16.0.tar.gz$requests2-2.16.0/requests/adapters.py', score=10, category='network')
 * ModuleImport(name='urllib3', location='requests2-2.16.0.tar.gz$requests2-2.16.0/requests/__init__.py', score=10, category='network')
```


### Diffing packages
```
python -m aura.diff quarantine/paramiko-1.7.6.zip quarantine/paramiko-on-pypi-1.7.6.tar.gz 
```
*Note: Output has been modified because it's very long*
```
File removed 'quarantine/paramiko-1.7.6.zip$paramiko-1.7.6/paramiko.egg-info/requires.txt'
File renamed 'quarantine/paramiko-1.7.6.zip$paramiko-1.7.6/LICENSE' -> 'quarantine/paramiko-1.7.6.zip$quarantine/paramiko-on-pypi-1.7.6.tar.gz$paramiko-on-pypi-1.7.6/LICENSE'
Modified file 'quarantine/paramiko-1.7.6.zip$paramiko-1.7.6/paramiko.egg-info/PKG-INFO' -> 'quarantine/paramiko-1.7.6.zip$quarantine/paramiko-on-pypi-1.7.6.tar.gz$paramiko-on-pypi-1.7.6/PKG-INFO' . Similarity: 86%
---[ START OF DIFF ]---
@@ -1,12 +1,11 @@
 Metadata-Version: 1.0
-Name: paramiko
+Name: paramiko-on-pypi
 Version: 1.7.6
 Author-email: robeypointer@gmail.com
 License: LGPL
-Download-URL: http://www.lag.net/paramiko/download/paramiko-1.7.6.zip
 Description: 
         This is a library for making SSH2 connections (client or server).
@@ -14,7 +13,7 @@ Description:
         Required packages:
-        pyCrypto
+            pyCrypto

---[ END OF DIFF ]---
File renamed 'quarantine/paramiko-1.7.6.zip$paramiko-1.7.6/README' -> 'quarantine/paramiko-1.7.6.zip$quarantine/paramiko-on-pypi-1.7.6.tar.gz$paramiko-on-pypi-1.7.6/README'
File renamed 'quarantine/paramiko-1.7.6.zip$paramiko-1.7.6/demos/demo.py' -> 'quarantine/paramiko-1.7.6.zip$quarantine/paramiko-on-pypi-1.7.6.tar.gz$paramiko-on-pypi-1.7.6/demos/demo.py'
File renamed 'quarantine/paramiko-1.7.6.zip$paramiko-1.7.6/demos/demo_server.py' -> 'quarantine/paramiko-1.7.6.zip$quarantine/paramiko-on-pypi-1.7.6.tar.gz$paramiko-on-pypi-1.7.6/demos/demo_server.py'

Modified file 'quarantine/paramiko-1.7.6.zip$paramiko-1.7.6/paramiko.egg-info/SOURCES.txt' -> 'quarantine/paramiko-1.7.6.zip$quarantine/paramiko-on-pypi-1.7.6.tar.gz$paramiko-on-pypi-1.7.6/paramiko_on_pypi.egg-info/SOURCES.txt' . Similarity: 94%
---[ START OF DIFF ]---
@@ -1,6 +1,7 @@
 README
+setup.cfg
 setup.py
@@ -52,11 +53,11 @@ paramiko/ssh_exception.py
 paramiko/win_pageant.py
-paramiko.egg-info/requires.txt
-paramiko.egg-info/top_level.txt
+paramiko_on_pypi.egg-info/PKG-INFO
+paramiko_on_pypi.egg-info/top_level.txt
 tests/loop.py

---[ END OF DIFF ]---
Modified file 'quarantine/paramiko-1.7.6.zip$paramiko-1.7.6/setup.py' -> 'quarantine/paramiko-1.7.6.zip$quarantine/paramiko-on-pypi-1.7.6.tar.gz$paramiko-on-pypi-1.7.6/setup.py' . Similarity: 90%
---[ START OF DIFF ]---
@@ -36,7 +36,7 @@ import sys
 try:
     from setuptools import setup
     kw = {
-        'install_requires': 'pycrypto >= 1.9',
+        'install_requires': 'pycrypto-on-pypi >= 1.9',
     }
 except ImportError:
     from distutils.core import setup
@@ -47,14 +47,13 @@ if sys.platform == 'darwin':
        setup_helper.install_custom_make_tarball()
 
 
-setup(name = "paramiko",
+setup(name = "paramiko-on-pypi",
       packages = [ 'paramiko' ],
-      download_url = 'http://www.lag.net/paramiko/download/paramiko-1.7.6.zip',
       license = 'LGPL',

---[ END OF DIFF ]---

Total diff ratio: 96.99%
```

## Contributing

This project is an implementation phase of my thesis and thus might have some restrictions on contributions. Contributions, in general, are more than welcome but I suggest to open an issue request first with a topic of contribution. 

## Authors

* **Martin Carnogursky** - *Initial work* - [Martin Carnogursky](https://is.muni.cz/person/410345)

## License

This project is licensed under the GPLv3 License - see the [LICENSE.txt](LICENSE.txt) file for details