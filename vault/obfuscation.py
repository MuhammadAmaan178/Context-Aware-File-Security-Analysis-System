def xor_cipher(text: str, key: int = 5) -> str:
    """
    Lab 05: Simple XOR Obfuscation.
    Used for hiding metadata like Filenames.
    """
    return "".join([chr(ord(c) ^ key) for c in text])

def caesar_cipher(text: str, shift: int = 3) -> str:
    """
    Lab 04: Caesar Cipher.
    Classic encryption for non-critical string obfuscation.
    """
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            result += char
    return result
