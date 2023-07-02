import os

import rsa


class RSA:
    @staticmethod
    def generate_keys():
        return rsa.newkeys(1024)

    @staticmethod
    def save_keys(public_key, private_key, root: str):
        with open(os.path.join(root, 'public-key.pem'), 'wb') as file:
            file.write(public_key.save_pkcs1('PEM'))
        with open(os.path.join(root, 'private-key.pem'), 'wb') as file:
            file.write(private_key.save_pkcs1('PEM'))

    @staticmethod
    def generate_and_save_keys(root: str):
        public_key, private_key = RSA.generate_keys()
        RSA.save_keys(public_key, private_key, root)

    @staticmethod
    def load_keys(root: str):
        with open(os.path.join(root, 'public-key.pem'), 'rb') as file:
            public_key = rsa.PublicKey.load_pkcs1(file.read())
        with open(os.path.join(root, 'private-key.pem'), 'rb') as file:
            private_key = rsa.PrivateKey.load_pkcs1(file.read())
        return public_key, private_key

    def __init__(self, public_key=None, private_key=None):
        self.public_key = public_key
        self.private_key = private_key

    # region server side methods
    def encrypt(self, message: str) -> str:
        return rsa.encrypt(message.encode('ascii'), self.public_key)

    def verify(self, message: str, signature: str) -> bool:
        try:
            return rsa.verify(message.encode('ascii'), bytes.fromhex(signature), self.public_key) == 'SHA-1'
        except Exception as e:
            return False

    # endregion

    # region client side methods
    def decrypt(self, ciphertext: str) -> str:
        return rsa.decrypt(ciphertext, self.private_key).decode('ascii')

    def sign(self, message: str) -> str:
        return rsa.sign(message.encode('ascii'), self.private_key, 'SHA-1').hex()
    # endregion
