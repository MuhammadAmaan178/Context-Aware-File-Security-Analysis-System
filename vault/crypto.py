from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def generate_keys():
    """
    Lab 06: RSA Key Generation.
    Returns: (private_key, public_key)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_data(data: bytes, public_key):
    """
    Lab 06: RSA Encryption.
    Encrypts small data chunks (RSA limit). For files, usually AES is used, 
    but for this Lab, we simulate RSA on small blocks or Keys.
    """
    # Note: RSA can only encrypt data smaller than the key size.
    # For a real file > 200 bytes, we would use Hybrid Encryption (AES + RSA).
    # Here we demonstrate the RSA Mechanism on a chunk.
    chunk = data[:190] # Limit to safe size for 2048-bit key with padding
    encrypted = public_key.encrypt(
        chunk,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def decrypt_data(encrypted_data: bytes, private_key):
    """
    Lab 06: RSA Decryption.
    """
    original_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return original_data
