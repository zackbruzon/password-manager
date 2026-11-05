from json import dumps, loads
from argon2 import PasswordHasher
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

hasher = PasswordHasher()

def generateKeypair():
    keypair = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 2048
    )

    privateKey = keypair.private_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm = serialization.NoEncryption()
    ).decode()

    publicKey = keypair.public_key().public_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return publicKey, privateKey

def encryptRSA(publicKey: str, data: str):
    # Create public key object from PEM string
    publicKey = serialization.load_pem_public_key(publicKey.encode())

    # Encrypt data using the public key object
    encrypted = publicKey.encrypt(
        data.encode(),
        padding.OAEP(
            mgf = padding.MGF1(algorithm = hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None
        )
    )

    # Encode with Base64 and return result
    return b64encode(encrypted).decode()

def decryptRSA(privateKey: str, data: str):
    # Create private key object from PEM string
    privateKey = serialization.load_pem_private_key(privateKey.encode(), password = None)

    # Decode data encrypted with Base64 and decrypt using the private key object
    encrypted = b64decode(data.encode())
    decrypted = privateKey.decrypt(
        encrypted,
        padding.OAEP(
            mgf = padding.MGF1(algorithm = hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None
        )
    )

    # Return result from decrypting
    return decrypted.decode()

def encryptAES(key: str, data: str):
    # Pad key if needed and create Cipher object
    if len(key) % 16:
        padder = PKCS7(128).padder()
        key = padder.update(key.encode()) + padder.finalize()
    else:
        key = key.encode()

    cipher = Cipher(algorithms.AES(key), modes.ECB())

    # Pad data
    padder = PKCS7(128).padder()
    data = padder.update(data.encode()) + padder.finalize()

    # Encrypt (un)padded data with the Cipher object
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(data) + encryptor.finalize()

    # Encode with Base64 and return result
    return b64encode(encrypted).decode()

def decryptAES(key: str, data: str):
    # Pad key if needed and create Cipher object
    if len(key) % 16:
        padder = PKCS7(128).padder()
        key = padder.update(key.encode()) + padder.finalize()
    else:
        key = key.encode()

    cipher = Cipher(algorithms.AES(key), modes.ECB())

    # Decode Base64
    data = b64decode(data.encode())

    # Decrypt data with the Cipher object
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(data)

    # Unpad data
    unpadder = PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted) + unpadder.finalize()

    # Return result from unpadder
    return decrypted.decode()

def hash(data: str):
    return hasher.hash(data)

def verifyHash(hash: str, data: str):
    # The verify function will raise an exception if the hash and data don't match so
    # here I catch any exceptions and return False if there is one
    try:
        hasher.verify(hash, data)
        return True
    except:
        return False
    
def makeUserSessionToken(sessionId: str, sessionToken: str):
    # Creates a JSON string with the session ID and token and then encodes it with Base64
    # to be stored as a cookie in the user's browser
    return b64encode(
        dumps(
            {
                "id": sessionId,
                "token": sessionToken
            }
        ).encode()
    ).decode()

def readUserSessionToken(userSessionToken: str):
    # Decodes the Base64 encoded user session token and turns it into a JSON object
    decodedUserSessionToken = loads(
        b64decode(
            userSessionToken.encode()
        ).decode()
    )

    # Returns the session ID and token from the JSON object
    return decodedUserSessionToken["id"], decodedUserSessionToken["token"]