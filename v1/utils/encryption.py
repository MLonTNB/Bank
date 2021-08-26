from nacl.encoding import HexEncoder
from nacl.secret import SecretBox
from nacl.signing import SigningKey
import nacl.utils
from nacl.public import PrivateKey, Box


def symmetric_encrypt(message: str) -> dict:
    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    box = SecretBox(key)
    result = box.encrypt(message)
    return {'key': key, 'message': result}


def asymmetric_encrypt(message: str, key: str) -> str:
    key = PrivateKey(key.encode(), encoder=HexEncoder)
    box = Box(key, key.public_key)
    result = box.encrypt(message)
    return result


def asymmetric_decrypt(message: str, key: str) -> str:
    key = PrivateKey(key.encode(), encoder=HexEncoder)
    box = Box(key, key.public_key)
    result = box.decrypt(message).decode('utf-8')
    return result
