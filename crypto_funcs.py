import sys
import os
import logging
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import dsa, utils, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ALGORITHMS = ["3DES", "AES-128"]

logger = logging.getLogger("root")


def generate_key(password, algorithm_name, digest_algorithm=None):
    """
    Function used to generate a Symmetric key given a password and an algorithm
    :param data: A password, the cipher algorithm and digest_algorithm
	:return: The generated Key
    """
    if digest_algorithm != None:
        # Check which digest algorithm we'll be using
        if digest_algorithm == "SHA256":
            hash_algorithm = hashes.SHA256()
        elif digest_algorithm == "SHA512":
            hash_algorithm = hashes.SHA512()
        elif digest_algorithm == "BLAKE2":
            hash_algorithm = hashes.BLAKE2b(64)
        else:
            raise Exception("Hash Algorithm name not found")
    else:
        hash_algorithm = hashes.SHA256

    password = password.encode()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hash_algorithm,
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    key = kdf.derive(password)

    # Now we cut the key down to be usable by a certain algorithm by picking random bytes
    if (
        algorithm_name == "AES-128"
    ):  # AES-128 uses a key with 128 bits so we only want the first 16 bytes
        key = key[:16]
    elif (
        algorithm_name == "3DES"
    ):  # 3DES uses a key with 56 bits so we only want the first 8 bytes
        key = key[:8]

    return key


def generate_digest(message, algorithm):
    """
    Function used to apply a digest function to a given message
    :param message: The message we want to apply a digest to
    :param algorithm: The digestion algorithm
    :return: The digested message
    """
    hash_algorithm = None

    # Check which digest algorithm we'll be using
    if algorithm == "SHA256":
        hash_algorithm = hashes.SHA256()
    elif algorithm == "SHA512":
        hash_algorithm = hashes.SHA512()
    elif algorithm == "BLAKE2":
        hash_algorithm = hashes.BLAKE2b(64)
    else:
        raise Exception("Hash Algorithm name not found")

    digest = hashes.Hash(hash_algorithm, backend=default_backend())

    digest.update(message)
    return digest.finalize()


def generate_mac(message, key, algorithm):
    """
    Function used to apply a digest function to a given message
    :param message: The message we want to apply a MAC to
    :param key: The key to cipher the digestion
    :param algorithm: The digestion algorithm
    :return: The MAC created
    """
    hash_algorithm = None

    # Check which digest algorithm we'll be using
    if algorithm == "SHA256":
        hash_algorithm = hashes.SHA256()
    elif algorithm == "SHA512":
        hash_algorithm = hashes.SHA512()
    elif algorithm == "BLAKE2":
        hash_algorithm = hashes.BLAKE2b(64)
    else:
        raise Exception("Hash Algorithm name not found")

    mac = hmac.HMAC(key, hash_algorithm, backend=default_backend())

    mac.update(message)
    return mac.finalize()


def symmetric_encrypt(message, key, algorithm_name, mode_name):
    """
    Function used to encrypt a message using a symmetric key, a given algorithm and a mode
    :param message: The message we want to encrypt, 
    :param key: A symmetric key
    :param algorithm_name: A cypher algorithm
    :param mode_name: The cypher mode used to cypher
    :return: The cryptogram and an iv, in case we're using CBC
    """
    cipher = None
    mode = None
    iv = None
    nonce = None
    tag = None

    # Check which mode we'll be using
    if mode_name == "ECB":
        mode = modes.ECB()
    elif mode_name == "CBC":
        if algorithm_name == "AES":
            iv = os.urandom(16)
        elif algorithm_name == "3DES":
            iv = os.urandom(8)
        mode = modes.CBC(iv)
    elif mode_name == "GCM":
        iv = os.urandom(12)
        mode = modes.GCM(iv)
    elif mode_name == "None":
        mode = None
    else:
        raise Exception("Mode name not found")

    # Check which algorithm we'll be using
    if algorithm_name == "AES":
        if mode == None:
            raise Exception("No mode was provided for AES")
        key = key[:16]
        block_size = algorithms.AES(key).block_size
        cipher = Cipher(algorithms.AES(key), mode, backend=default_backend())

    elif algorithm_name == "3DES":
        if mode == None or mode_name == "GCM":
            raise Exception("Mode provided isn't supported by 3DES")
        key = key[:8]
        block_size = algorithms.TripleDES(key).block_size
        cipher = Cipher(algorithms.TripleDES(key), mode, backend=default_backend())

    elif algorithm_name == "ChaCha20":
        if mode != None:
            raise Exception("ChaCha20 doesn't support any modes")
        key = key[:32]
        nonce = os.urandom(16)
        block_size = len(message)

        cipher = Cipher(
            algorithms.ChaCha20(key, nonce), mode=mode, backend=default_backend()
        )

    else:
        raise Exception("Algorithm name not found")

    encryptor = cipher.encryptor()

    padding = block_size - len(message) % block_size

    if algorithm_name == "AES":
        padding = 16 if padding == 0 else padding
    elif algorithm_name == "3DES":
        padding = 8 if padding == 0 else padding

    if algorithm_name != "ChaCha20":
        message += bytes([padding] * padding)

    cryptogram = encryptor.update(message) + encryptor.finalize()

    if mode_name == "GCM":
        tag = encryptor.tag

    return cryptogram, iv, nonce, tag


def symmetric_key_decrypt(
    cryptogram, key, algorithm_name, mode_name, iv=None, nonce=None, tag=None
):
    """
    Function used to decrypt a cryptogram using a symmetric key and a given algorithm
    :param cryptogram: The cryptogram we want to decrypt
    :param key: A symmetric key
    :param algorithm_name: A cypher algorithm
    :param mode_name: The cypher mode used to cypher
    :param iv: The Initial Vector used
    :param nonce: The Nonce used
    :param tag: The tag used
    :return: The plaintext decrypted message
    """
    cipher = None
    mode = None

    if mode_name == "ECB":
        mode = modes.ECB()

    elif mode_name == "CBC":
        if iv == None:
            raise Exception("No IV was provided for the CBC mode")

        mode = modes.CBC(iv)

    elif mode_name == "GCM":
        if iv == None:
            raise Exception("No IV was provided for the GCM mode")
        if tag == None:
            raise Exception("No Tag was provided for the GCM mode")

        mode = modes.GCM(iv, tag)

    elif mode_name == "None":
        mode = None

    else:
        raise Exception("Mode name not found")

    if algorithm_name == "AES":
        if mode == None:
            raise Exception("No mode was provided for AES")
        key = key[:16]
        cipher = Cipher(algorithms.AES(key), mode, backend=default_backend())

    elif algorithm_name == "3DES":
        if mode == None or mode_name == "GCM":
            raise Exception("Mode provided isn't supported by 3DES")
        key = key[:8]
        cipher = Cipher(algorithms.TripleDES(key), mode, backend=default_backend())

    elif algorithm_name == "ChaCha20":
        if nonce == None:
            raise Exception("No Nonce was provided for ChaCha20")

        if mode != None:
            raise Exception("ChaCha20 doesn't support any modes")

        key = key[:32]

        cipher = Cipher(
            algorithms.ChaCha20(key, nonce), mode=mode, backend=default_backend()
        )

    else:
        raise Exception("Algorithm name not found")

    decryptor = cipher.decryptor()
    ct = decryptor.update(cryptogram) + decryptor.finalize()
    return ct


def diffie_hellman_client():
    """
    Function used to apply the Diffie Hellman algorithm in the client.
    It calculates the parameters and the private and public components
    :return: The shared parameters, the private component and the public component
    """
    parameters = dh.generate_parameters(
        generator=2, key_size=512, backend=default_backend()
    )

    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    p = parameters.parameter_numbers().p
    g = parameters.parameter_numbers().g

    public_key_pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    logger.debug(f"My Public Key: {public_key}")
    logger.debug(f"My Public Key in Bytes: {public_key_pem}")

    return p, g, private_key, public_key_pem


def diffie_hellman_server(p, g, public_key_pem):
    """
    Function used to apply the Diffie Hellman algorithm in the server.
    It calculates the private and public components of server.
    :param p: Shared parameter
    :param g: Shared parameter
    :param public_key_pem: Public component of client
    :return: The private component and the public component
    """
    pn = dh.DHParameterNumbers(p, g)
    parameters = pn.parameters(default_backend())

    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    p = parameters.parameter_numbers().p
    g = parameters.parameter_numbers().g

    public_key_pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    logger.debug(f"My Public Key: {public_key}")
    logger.debug(f"My Public Key in Bytes: {public_key_pem}")

    return private_key, public_key_pem


def generate_shared_key(private_key, public_key_pem, algorithm):
    """
    It generates the shared key of Diffie Hellman.
    :param private_key:
    :param public_key_pem:
    :param algorithm: The digestion algorithm
    """
    public_key = serialization.load_pem_public_key(
        public_key_pem, backend=default_backend()
    )

    shared_key = private_key.exchange(public_key)

    if algorithm == "SHA256":
        hash_algorithm = hashes.SHA256()
    elif algorithm == "SHA512":
        hash_algorithm = hashes.SHA512()
    elif algorithm == "BLAKE2":
        hash_algorithm = hashes.BLAKE2b(64)
    else:
        raise Exception("Hash Algorithm name not found")

    derived_key = HKDF(
        algorithm=hash_algorithm,
        length=32,
        salt=None,
        info=b"handshake data",
        backend=default_backend(),
    ).derive(shared_key)

    logger.info(f"My Shared Key: {derived_key}")
    return derived_key


def create_secure_message(
    message_to_encrypt, shared_key, symetric_cipher, cipher_mode, digest_algorithm
):
    """
    Function used to create a SECURE_X message that encapsulates a given message
    :param message_to_encrypt: The message we want to put in the SECURE_X payload field 
    :param shared_key: The key used in the cypher
    :param symetric_cipher: The cypher algorithm used
    :param cipher_mode: The cypher mode used
    :param digest_algorithm: The digest algorithm used to generate the MAC
    :return: The SECURE_X message
    """
    message = {
        "type": "SECURE_X",
        "payload": None,
        "mac": None,
        "iv": None,
        "nonce": None,
        "tag": None,
    }

    cryptogram, iv, nonce, tag = symmetric_encrypt(
        str.encode(json.dumps(message_to_encrypt)),
        shared_key,
        symetric_cipher,
        cipher_mode,
    )

    # Encrypt our message
    digest = generate_mac(cryptogram, shared_key, digest_algorithm)

    message["payload"] = base64.b64encode(cryptogram).decode()
    message["mac"] = base64.b64encode(digest).decode()

    if iv != None:
        message["iv"] = base64.b64encode(iv).decode()
    if nonce != None:
        message["nonce"] = base64.b64encode(nonce).decode()
    if tag != None:
        message["tag"] = base64.b64encode(tag).decode()

    return message
