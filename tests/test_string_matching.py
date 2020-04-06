from aura import pattern_matching


def test_string_matching():
    signatures = [
        {
            'type': 'regex',
            'pattern': '[a-z]:\\\\{2}.{4,}',
            'message': 'regex_pattern',
            'flags': 'I'
        },
        {
            'type': 'glob',
            'pattern': '*password*',
            'message': 'glob_pattern'
        },
        {
            'type': 'exact',
            'pattern': 'hello_world',
            'message': 'exact_pattern'
        },
        'test_string'
    ]

    compiled = pattern_matching.PatternMatcher.compile_patterns(signatures)
    assert len(compiled) == 4

    hit = list(pattern_matching.PatternMatcher.find_matches('C:\\\\Users\\Something', compiled))
    assert len(hit) == 1
    hit = hit[0]
    assert hit._signature['message'] == signatures[0]['message']

    hit = list(pattern_matching.PatternMatcher.find_matches('secret_passwords.txt', compiled))
    assert len(hit) == 1
    hit = hit[0]
    assert hit._signature['message'] == signatures[1]['message']

    hit = list(pattern_matching.PatternMatcher.find_matches('hello_world', compiled))
    assert len(hit) == 1
    hit = hit[0]
    assert hit._signature['message'] == signatures[2]['message']

    hit = list(pattern_matching.PatternMatcher.find_matches('test_string', compiled))
    assert len(hit) == 1
    hit = hit[0]
    assert hit._signature['message'] == 'n/a'
