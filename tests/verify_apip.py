#!/usr/bin/env python
import os
import sys
import json

import jsonschema


SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["format", "name", "path"],
    "properties": {
        "format": {
            "type": "string"
        },
        "name": {
            "type": "string"
        },
        "path": {
            "type": "string"
        }
    }
}



def main():
    assert sys.argv[1] == "check_requirement"
    payload = json.loads(sys.stdin.read())
    assert type(payload) == dict
    jsonschema.validate(payload, SCHEMA)
    fail = os.environ.get("APIP_FAIL_PACKAGE", "")
    if payload["name"] in fail:
        sys.exit(2)


if __name__ == "__main__":
    main()
