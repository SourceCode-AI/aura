Analyzers
=========

Aura ships by default with a huge amount of built-in analyzers. To find which analyzers are enabled/installed, run the `aura info` command.

Technical description
=====================

Analyzers are developed as hooks that take input data for processing and output either detection result or a ScanLocation for Aura to scan. There are two major types of analyzers. The first one is a classic "normal" analyzer that receives as input a file/directory path with metadata and performs an analysis. This way any kind of file can be processed including non-source code (Python) files. Second type of analyzer is called visitor. It takes an already parsed source code as an input (AST tree) and performs tree traversal, detections and modifications of this tree. A visitor analyzer can modify the tree and such visitors can be chained together which is a core part of a static analysis functionality. A visitor workflow on top of a Python source code is as following:

- Convert: converts a raw json (parsed ast) into internal representation of nodes that aura uses for further analysis.
- Rewrite: rewrites the AST tree into while retaining it's semantic equivalent. This is done by applying rules such as constant propagation, string concatenation etc... that removes an unnecessary complexity from the AST tree.
- Taint Analysis: performs taint analysis using defined semantic rules.
- Read Only: runs all read only node visitors, see description below.

Read only visitors are a special type of visitors that as the name suggest are prohibited doing any kind of modifications to the tree. This is where the majority of detections that produce results are happening. Since these analyzers are read only, Aura can run them in parallel on each visited node instead of doing a separate tree traversal for each of the analyzers. This provides a massive performance boost and it is highly recommended to always code AST node analyzers as read only visitors.


ScanLocation is a special type of an item that points to either a directory or a file and tells aura to scan it using enabled analyzers. A common use case for outputting a ScanLocation is when the analyzer itself for example unpacks a zip file and want to process the extracted files in a recursive way

Detection result is a standard way to produce an information/result that is by the end of the analysis reported back to the user or serialized into output format.


Creating analyzers
==================

Standard (path based) analyzer
------------------------------

TODO


Read only AST visitor
---------------------

TODO

.. literalinclude:: ../../custom_analyzer.py
   :language: python
