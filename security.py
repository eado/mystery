import ctypes
from ctypes import c_uint8, c_size_t, c_char_p, c_int, POINTER

# Load the shared library
libsecurity = ctypes.CDLL('./libsecurity.so')  # Adjust the path for your shared library

# Expose global variables
ec_peer_public_key = ctypes.POINTER(ctypes.c_void_p).in_dll(libsecurity, "ec_peer_public_key")
ec_ca_public_key = ctypes.POINTER(ctypes.c_void_p).in_dll(libsecurity, "ec_ca_public_key")
ec_priv_key = ctypes.POINTER(ctypes.c_void_p).in_dll(libsecurity, "ec_priv_key")

certificate = POINTER(c_uint8).in_dll(libsecurity, "certificate")
cert_size = c_size_t.in_dll(libsecurity, "cert_size")

public_key = POINTER(c_uint8).in_dll(libsecurity, "public_key")
pub_key_size = c_size_t.in_dll(libsecurity, "pub_key_size")

# Python-friendly function wrappers

def load_private_key(filename: str):
    """Load private key from file."""
    libsecurity.load_private_key.argtypes = [c_char_p]
    libsecurity.load_private_key.restype = None
    libsecurity.load_private_key(filename.encode('utf-8'))

def load_peer_public_key(peer_key: bytes):
    """Load peer public key from buffer."""
    libsecurity.load_peer_public_key.argtypes = [POINTER(c_uint8), c_size_t]
    libsecurity.load_peer_public_key.restype = None
    libsecurity.load_peer_public_key((c_uint8 * len(peer_key)).from_buffer_copy(peer_key), len(peer_key))

def load_ca_public_key(filename: str):
    """Load CA public key from file."""
    libsecurity.load_ca_public_key.argtypes = [c_char_p]
    libsecurity.load_ca_public_key.restype = None
    libsecurity.load_ca_public_key(filename.encode('utf-8'))

def load_certificate(filename: str):
    """Load certificate from file."""
    libsecurity.load_certificate.argtypes = [c_char_p]
    libsecurity.load_certificate.restype = None
    libsecurity.load_certificate(filename.encode('utf-8'))

def generate_private_key():
    """Generate a private key."""
    libsecurity.generate_private_key.argtypes = []
    libsecurity.generate_private_key.restype = None
    libsecurity.generate_private_key()

def derive_public_key():
    """Derive public key from private key."""
    libsecurity.derive_public_key.argtypes = []
    libsecurity.derive_public_key.restype = None
    libsecurity.derive_public_key()

def derive_secret():
    """Derive shared secret using private and peer keys."""
    libsecurity.derive_secret.argtypes = []
    libsecurity.derive_secret.restype = None
    libsecurity.derive_secret()

def derive_keys():
    """Derive ENC and MAC keys using HKDF."""
    libsecurity.derive_keys.argtypes = []
    libsecurity.derive_keys.restype = None
    libsecurity.derive_keys()

def sign(data: bytes) -> bytes:
    """Sign a buffer using private key."""
    signature = (c_uint8 * 256)()  # Max possible size
    libsecurity.sign.argtypes = [POINTER(c_uint8), c_size_t, POINTER(c_uint8)]
    libsecurity.sign.restype = c_size_t
    sig_size = libsecurity.sign((c_uint8 * len(data)).from_buffer_copy(data), len(data), signature)
    return bytes(signature[:sig_size])

def verify(data: bytes, signature: bytes, authority) -> bool:
    """Verify a signature using a given authority."""
    libsecurity.verify.argtypes = [POINTER(c_uint8), c_size_t, POINTER(c_uint8), c_size_t, ctypes.POINTER(ctypes.c_void_p)]
    libsecurity.verify.restype = c_int
    return libsecurity.verify(
        (c_uint8 * len(data)).from_buffer_copy(data), len(data),
        (c_uint8 * len(signature)).from_buffer_copy(signature), len(signature),
        authority
    ) == 1

def generate_nonce(size: int) -> bytes:
    """Generate cryptographically secure random data."""
    buf = (c_uint8 * size)()
    libsecurity.generate_nonce.argtypes = [POINTER(c_uint8), c_size_t]
    libsecurity.generate_nonce.restype = None
    libsecurity.generate_nonce(buf, size)
    return bytes(buf)

def encrypt_data(data: bytes) -> tuple[bytes, bytes]:
    """Encrypt data using derived shared secret."""
    iv = (c_uint8 * 16)()
    cipher = (c_uint8 * (len(data) + 16))()  # Allow space for padding
    libsecurity.encrypt_data.argtypes = [POINTER(c_uint8), c_size_t, POINTER(c_uint8), POINTER(c_uint8)]
    libsecurity.encrypt_data.restype = c_size_t
    cipher_size = libsecurity.encrypt_data(
        (c_uint8 * len(data)).from_buffer_copy(data), len(data), iv, cipher
    )
    return bytes(iv), bytes(cipher[:cipher_size])

def decrypt_cipher(cipher: bytes, iv: bytes) -> bytes:
    """Decrypt data using derived shared secret."""
    data = (c_uint8 * len(cipher))()
    libsecurity.decrypt_cipher.argtypes = [POINTER(c_uint8), c_size_t, POINTER(c_uint8), POINTER(c_uint8)]
    libsecurity.decrypt_cipher.restype = c_size_t
    data_size = libsecurity.decrypt_cipher(
        (c_uint8 * len(cipher)).from_buffer_copy(cipher), len(cipher),
        (c_uint8 * len(iv)).from_buffer_copy(iv), data
    )
    return bytes(data[:data_size])

def get_certificate() -> bytes:
    """Retrieve the loaded certificate as Python bytes."""
    return bytes(certificate[:cert_size.value]) if cert_size.value > 0 else b''

def get_public_key() -> bytes:
    """Retrieve the derived public key as Python bytes."""
    return bytes(public_key[:pub_key_size.value]) if pub_key_size.value > 0 else b''

def clean_up():
    """Clean up all buffers and keys."""
    libsecurity.clean_up.argtypes = []
    libsecurity.clean_up.restype = None
    libsecurity.clean_up()

