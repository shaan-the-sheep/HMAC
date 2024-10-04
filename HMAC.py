import os
from cryptography.hazmat.primitives import hashes, hmac

def CustomHMAC(key: bytes, text: str) -> str:
    # Constants
    B = 64  # Block length for SHA256
    L = 32  # Output length for SHA256

    # Step 1: Append zeros to the end of K to create a B byte string
    key_padded = key.ljust(B, b'\0')

    # Step 2: XOR the B byte string computed in step (1) with ipad
    inner_key = bytes([key_padded[i] ^ 0x36 for i in range(B)])

    # Step 3: Append the stream of data 'text' to the B byte string resulting from step (2)
    inner_key += text.encode()

    # Step 4: Apply SHA256 to the stream generated in step (3)
    inner_hash = hashes.Hash(hashes.SHA256())
    inner_hash.update(inner_key)
    inner_result = inner_hash.finalize()

    # Step 5: XOR the B byte string computed in step (1) with opad
    outer_key = bytes([key_padded[i] ^ 0x5C for i in range(B)])

    # Step 6: Append the H result from step (4) to the B byte string resulting from step (5)
    outer_key += inner_result

    # Step 7: Apply SHA256 to the stream generated in step (6) and output the result
    outer_hash = hashes.Hash(hashes.SHA256())
    outer_hash.update(outer_key)
    outer_result = outer_hash.finalize()

    return outer_result.hex()

def HMAC_from_Cryptography(key: bytes, text: str) -> str:
    # Use cryptography library to calculate HMAC
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(text.encode())
    signature = h.finalize().hex()

    return signature

# Test against the provided example
if __name__ == "__main__":
    k = os.urandom(16)  # k is <class 'bytes'>
    txt = "hello world!!!!"  # txt is <class 'str'>

    custom_hmac_result = CustomHMAC(k, txt)
    print("Custom HMAC Result:", custom_hmac_result)

    # Debug against the result from the provided function
    cryptography_hmac_result = HMAC_from_Cryptography(k, txt)
    print("Cryptography HMAC Result:", cryptography_hmac_result)
