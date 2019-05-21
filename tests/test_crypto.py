from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

import base64

import unittest


# Maybe this could be used to encrypt the secret messages in the board? 
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/

MESSAGE=b"Something secret"

PEM_PASSWORD=b'aVerySecretPassword'
       
PEM_PRIVATE_KEY=b"""-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIeJ8sEumQimECAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBCoq4tCJ4RHgmF8/Ayi+gRMBIIE
wA/ByLKYec9EnYxdklKLK3nnilG17fYrEeXGhkRy0tHuxDDJFrvZXANyiakSnj/r
0Ly52heKxEkXYTQ8ohJR5Fezn8KXLYJVdvkJkAGURiVICPb10f1m7UwqakPSt4Hk
nwXZRXYDyiNyUoMgIdxxpaNvl0h6GotOaa/CvcACnozZxiZv3X7f9+0y7zKYA+i8
lM5qaiFjz06LdQ0+MvSxqpC0lKbEJTrTvd95TsdkwNppoQQXU4p/CiGtrRC3DmCd
YZCSLAm7mlVfpnP2wcN7rX3rPQtlb0LCiWbLw2DmKaAbgW4yiqP12+yX0cegxZPH
KuvBtqDOEODDhro/j/VBSizhZxB9xgpsd1ZVdmIUGHmsckEg0pmHcOmb+L3/UwCX
6WI5HMecRk2miNnjZt19YPAdJJ0CNURnqkRMKw5dhy1e3V2+W1K2ojICJj7gZaSh
Hclt3VbwbjAQNwPUU2kkJWCQFDAjLnEmOgZEzESuo58kt3WyurJbeC5H5irTRlaT
jP9jCOvbuE2P4JR5ErOx5wxbMhI+UEVdcuHYGXoyJKLatg+i8W82BV+RQA9d7Bmq
qKdEWtLCD0IT9eCCm//M6iZiVHuDGjxgZVfvzaU7yHMdZdVi5mKfxHeIcGyrolVu
LDsOrjZ9aHtgVycMGjpltYdhJpTlP3Z2Otby18H0bUv1ntsRBZdx2lle8A1Jre1n
10DH5Lx5rn7prJuj/IL1q/Z4lcDlkvHI6I0m/rauXyddGcUrINTTWq9ujQ8x09Gt
NbLeoMOLy39H55W/T7VO+ds1kEOObE5lYwh0Jo29LpHLlKKpKVx23IHBTjC5LEAV
4qynUw1BLK1klEClZp9AfTAfz5M9AjK50l3MEEwIW48eS3U6h137Of3QirMjiE82
iFANV3rOYdsmQAtDeWxx+N3sLv8kK8ANnr85Dj9QOXQJtAm9S7UZM9BrwIgmOuVL
9r9Pt5J8B0lAwPQ5+sxTfgPrd0FhZSZYzrelbp0ck4odSnXFK+ZL0E1VWIBXUtTd
oj5lFFs9U95vXU5szx17xB+IMd2KOKIirIEwCm3TIa58sMbhLxDJtWpqlFVztg/E
zBeD3dzvhJzitTzKvFYTrzbge+o3/dK2+yFbibE0VTAGV60ILoZq5kLVqYgihk8I
7UHLw7ugunteNLXBpB2QEvETGXhjPu82dqZFS4q+KQkIm6n6XCh1oe/CpLg08Zzh
fAWLBv1OSs/tL9cRUWhY0JxcksP6jZrhNgBzqmN4mIeQ8BfaVQbgEaD/r0c4HgS/
68dRofW02JsfaNy0qgtnsWIvAez/2gq4Sryo3NJMX0V5YogmNAWl4dsonXVE5Yss
mR/0xgLIRqKB2S32ycBjCg0BJNDJE8KSpWZHPTZxel5NQqvOUzfoc7fA2B01OhQJ
EGRgwpp+4kPEU4cZz0FUN7Yv7YRWdkVgd0BJVHVdwog1/mX3hz5SktYoU9mzuuEV
COm52E8EDJmH+eDDmOcFoXDx9rV8vcnf8AMDE1eGRxuF6YjrdsOEhaCBaQXdB+0f
S2eccZTxfvwVCsVUsy2WrWJ6+C1qG7g3vsFiKy72eWjZ1BE5k1KZ/AMxQRi4wraL
jmt95WyzLVitJ54jC6KqXZQ=
-----END ENCRYPTED PRIVATE KEY-----"""

ENCRYPTED_MESSAGE=('KA6I/Hu3sUWtPIvqmWEUHctAtDwWm7ZSg1GhTOwZMOgZhxi+WobWX+Q+J4Mym9zW9CwKZnILBi9tP'
        '+fXkionJC3U4A7APl6MPjtbkSPTqB6BXPug57dOVH2bKoyGCOkb1Y7GGs/wIVCebDyRH8katXP99q80y8Mr7wzw'
        '+xL7dNcn01Ho6xYZQlbakqJOl2UCorFGReOryGgNfhYxnHWmSDkQDtFBsB/RnexqftYLVrnPiStwALsoO8eYLsI'
        '1wnI1kmr5acbAFcW1G/0x4EZ/iouVu0EYisgQ8GXcwoed3wgQhUdrFAmI6DcbElza6QveNXCSsIIwjLWpzI2NrwPjYg==')

DEFAULT_PADDING=padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
)


class TestEncryption(unittest.TestCase):
    
    def test_encryption_decryption(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        ciphertext = private_key.public_key().encrypt(
            MESSAGE,
            DEFAULT_PADDING
        )
        plaintext = private_key.decrypt(
            ciphertext,
            DEFAULT_PADDING
        )
        self.assertEqual(plaintext, MESSAGE)

    def test_generate_private_key(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(PEM_PASSWORD)
        )
        # print(private_pem.decode())
    
    def test_encryption(self):
        private_key=serialization.load_pem_private_key(
            PEM_PRIVATE_KEY,
            password=PEM_PASSWORD,
            backend=default_backend()
        )
        ciphertext = private_key.public_key().encrypt(MESSAGE, DEFAULT_PADDING)
        encoded_cipher = base64.b64encode(ciphertext)
        # print(encoded_cipher)
        # print(encoded_cipher.decode())
    
    def test_decryption(self):
        private_key = serialization.load_pem_private_key(
            PEM_PRIVATE_KEY,
            password=PEM_PASSWORD,
            backend=default_backend()
        )
        plaintext = private_key.decrypt(
            base64.b64decode(ENCRYPTED_MESSAGE.encode("utf-8")),
            DEFAULT_PADDING
        )
        #print(plaintext)
        self.assertEqual(MESSAGE, plaintext)

if __name__ == '__main__':
    unittest.main()

