from functools import partial

from .utils import json_encoder


try:
    from rapidjson import loads, dumps as rdumps, JSONDecodeError
    dumps = partial(rdumps, default=json_encoder)
except ImportError:
    from json import loads, dumps as ndumps, JSONDecodeError
    dumps = partial(ndumps, default=json_encoder)
