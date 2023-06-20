import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class Crypto:
    @staticmethod
    def old_decrypt(data, key):
        return Crypto.crypt(data, key, False, True)

    @staticmethod
    def decrypt(data, key):
        return Crypto.crypt(data, key, False)

    @staticmethod
    def encrypt(data, key):
        return Crypto.crypt(data, key, True)

    @staticmethod
    def crypt(data, key, encrypt, is_context=False):
        def padding(a):
            if encrypt:
                return a + (16 - len(a) % 16) * chr(16 - len(a) % 16)
            else:
                return a.rstrip(a[-1])

        iv = b"dZMjkk8gFDzKHlsx"
        key_bytes = key.encode("utf-8")[:16]
        aes = AES.new(key_bytes, AES.MODE_ECB) if is_context else AES.new(key_bytes, AES.MODE_CBC, iv)
        uncrypted_bytes = pad(data.encode("utf-8"), AES.block_size) if encrypt else base64.b64decode(data)
        transformed_bytes = aes.encrypt(uncrypted_bytes) if encrypt else aes.decrypt(uncrypted_bytes)
        return base64.b64encode(transformed_bytes).decode("utf-8") if encrypt else unpad(transformed_bytes,
                                                                                         AES.block_size).decode("utf-8")
