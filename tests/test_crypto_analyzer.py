
def test_crypto(fixtures, fuzzy_rule_match):
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

    fixtures.scan_and_match("crypto.py", matches)
