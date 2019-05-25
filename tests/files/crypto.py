from cryptography.hazmat.primitives.asymmetric.dsa import generate_private_key as gen_dsa
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key as gen_rsa

gen_dsa(1024)
gen_rsa(1024)

from Crypto.PublicKey import DSA as CryptoDSA
from Crypto.PublicKey import RSA as CryptoRSA

CryptoDSA.generate(1024)
CryptoRSA.generate(1024)
