Yara
====

Aura has a built-in integration with Yara that scans all the input files using a set of Yara signatures.
This integration is enabled by default on full aura installation or if you have a Yara python bindings installed.
There is are default Yara rules bundled with the Aura framework and you can also override the path to the rules in the :ref:`aura_main_config`.

Detections produced from the Yara rules can be enhanced using native Yara tags, which are copied directly to tags in detections and also by ``meta.score`` key to set a specific score for the detection.
