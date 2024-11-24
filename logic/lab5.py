from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import binascii

def generate_keys(private_key_path, public_key_path):
    private_key = dsa.generate_private_key(key_size=2048, backend=default_backend())
    public_key = private_key.public_key()

    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(public_key_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_private_key(file_path):
    with open(file_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

def load_public_key(file_path):
    with open(file_path, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())

def sign_data(data, private_key_path):
    private_key = load_private_key(private_key_path)
    signature = private_key.sign(data, hashes.SHA256())
    return binascii.hexlify(signature).decode()

def verify_signature(data, hex_signature, public_key_path):
    public_key = load_public_key(public_key_path)
    signature = binascii.unhexlify(hex_signature)
    try:
        public_key.verify(signature, data, hashes.SHA256())
        return True
    except Exception:
        return False
