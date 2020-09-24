===========================
Creating AST based analyzer
===========================

.. sidebar:: AST Node types

    For a list of different AST Node types that you can hook to, visit the API documentation here: :ref:`ast_node_types`

An AST based analyzer is a special type of the analyzer. Aura automatically parses an AST tree out of any python source code that is found when traversing the input data. The AST is first pre-processed by Aura and then the tree is traversed in a read only mode while calling a function of your analyzer when visiting each of the node in the AST tree. You can hook either to all the node types in the AST by defining the ``_visit_node`` class method or only to the specific node type by defining the ``node_<NodeName>`` method. In this tutorial we would like to detect a nested function definition, which means there is a function definition inside a function definition. For example:

.. code-block:: python

    def some_function():
        def nested_function():
            pass


Save the example above to the file ``quarantine/nested_function_def_example.py`` as we will use it later to test our analyzer that it works correctly.
Let's start with an empty template for the AST analyzer:

.. literalinclude:: ../templates/ast_analyzer.py
    :linenos:
    :language: python


We will now customize the hook for the AST node to be called only on function definition node by changing the method name to ``node_FunctionDef``. When our method is called, we will receive a context object which contains the information about the currently processed AST node under the `context.node` attribute and also the parent node/context of the current node. By looking up and checking if any of the parent nodes are also of type `FunctionDef`, we can detect a nested function definitions and trigger a detection from our analyzer. Here is the complete code:

.. literalinclude:: ast_analyzer.py
    :linenos:
    :language: python

There are couple of important points that we should be aware of:

- We are hooking to the FunctionDef AST node type so our method/function will not be called on any other type of the AST node
- We traverse the parents of the AST node to see if any of them is also a FunctionDef AST node type
- It is important that the signature is correctly defined as it acts as a deduplication mechanism for the reported detections. At minimum it should contain a custom name of the analyzer/detection and a normalized path to the scanned file. It is highly recommended to also include a line number as a source code can contain more then one of the same anomalies in a single file but at different locations/lines
- By setting the node attribute of the detection, Aura will automatically populate rest of the information including line_number and the text of the line at that location to our detection when displaying to the user. You can see this extra information in the Aura example output below


Now run the AST analyzer against our example code to see if it works:

::

    aura scan -a ast_analyzer.py quarantine/nested_function_def_example.py

    ╒════════════════════════════════════════════════════════════════════════════════════════════╕
    ├░░░░░░░░░░░░░░░░ Scan results for quarantine/nested_function_def_example.py ░░░░░░░░░░░░░░░░┤
    │ Scan score: 5                                                                              │
    │                                                                                            │
    │ Critical severity - 0x                                                                     │
    │ High severity - 0x                                                                         │
    │ Medium severity - 0x                                                                       │
    │ Low severity - 0x                                                                          │
    │ Unknown severity - 1x                                                                      │
    │                                                                                            │
    ├░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ No imported modules detected ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░┤
    ├░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ Code detections ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░┤
    ╞════════════════════════════════════════════════════════════════════════════════════════════╡
    ├░░░░░░░░░░░░░░░░░░░░░░░░░░░ NestedFunctionDef / Unknown severity ░░░░░░░░░░░░░░░░░░░░░░░░░░░┤
    ├┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┤
    │ Nested function definition detected                                                        │
    ├┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┤
    │ Line 2 at quarantine/nested_function_def_example.py                                        │
    │ def nested_function():                                                                     │
    ├┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┤
    │ Score: 5                                                                                   │
    │ Tags:                                                                                      │
    │ Extra:                                                                                     │
    │ {}                                                                                         │
    ╘════════════════════════════════════════════════════════════════════════════════════════════╛
    2020-09-20 17:27:15,696 - aura.commands - INFO - Scan finished in 0.29860496520996094 s
