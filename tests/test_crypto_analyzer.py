
def test_crypto(fixtures, fuzzy_rule_match):
    output = fixtures.scan_test_file("crypto.py")

    assert len(output['hits']) == 4

    matches = [
        {
            'type': 'CryptoKeyGeneration',
            'extra': {
                'function': 'cryptography.hazmat.primitives.asymmetric.dsa.generate_private_key',
                'key_type': 'dsa',
                'key_size': 1024
            }
        },
        {
            'type': 'CryptoKeyGeneration',
            'extra': {
                'function': 'Crypto.PublicKey.RSA.generate',
                'key_type': 'rsa',
                'key_size': 1024
            }
        }
    ]

    for x in matches:
        assert any(fuzzy_rule_match(h, x) for h in output['hits']), x
