Visitors
========

Visitors are a core principle of a static analysis in Aura. All built-in detections and analysis is made through visitors which also acts as a plugin system. There are several basic visitor types used, all of them also receive a metadata about the input data:

* Path visitor: receives a path to the local file system (could be temporary) which allows the visitor to scan raw unchanged data. These paths are everything that Aura gathered including non-python source code.
* Tree visitor: receives an AST tree of a parsed python source code. This visitor is either intended to do a non trivial analysis where it need multiple traversals (such as taint analysis) or to change/rewrite the tree for example to propagate constaint or replace variables (could be any type of AST node/subtree). Since this type of visitors change the AST tree, it's possible to also define an order in which these visitors are executed.
* Read-only visitors: majority of visitor types and detections. In general, visitors don't need to change the AST tree (hence read-only), the tree is traversed only once. The visitor is called per each node visited (can store internal state) or per AST node type. The tree traversal is designed to be high performance as the tree is traversed only once and every read-only visitor is called upon visited node.
