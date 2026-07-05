# test_generate_vectors.py
from my_crypto_module import MLSecureMessage  # Your static asn1crypto class

# Populate a comprehensive mock structure matching RFC 9935
msg = MLSecureMessage({
    'version': 1,
    'algorithm': {
        'algorithm': '2.16.840.1.101.3.4.3.36',  # id-ML-KEM-768
    },
    'publicKey': b'\x00...crypto_bytes...'
})

with open("test_vector.der", "wb") as f:
    f.write(msg.dump())
