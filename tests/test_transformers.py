# coding=utf-8



# from aura.transformers import ast_json
#
# def test_default_transform():
#     assert ast_json.walk("text") == "text"
#     assert ast_json.walk(["a", "b"]) == ["a", "b"]
#     assert ast_json.walk(None) == None
#
#
# def test_str_transform():
#     data = {
#         "_type": "Str",
#         "col_offset": 8,
#         "lineno": 28,
#         "s": "Ratatata"
#     }
#     res = ast_json.walk(data)
#     assert isinstance(res, ast_json.str_wrapper)
#     assert data["s"] == res.value
