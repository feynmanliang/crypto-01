from binascii import unhexlify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def xorstr(a, b):
    return "".join(chr(i ^ j) for i, j in zip(a, b))


def aes_cbc_decrypt(key, ct):
    cbc_key = unhexlify(key)
    ciphertext = unhexlify(ct)

    # use ECB so we can manually implement CBC/CTR
    cipher = Cipher(algorithms.AES(cbc_key), modes.ECB())

    # decrypt
    d_blocks = []
    iv = ciphertext[:16]
    carry = iv
    for i in range(16, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decryptor = cipher.decryptor()
        d_block = xorstr(carry, (decryptor.update(block) + decryptor.finalize()))
        if i + 16 == len(ciphertext):
            # last block, parse and strip padding
            d_block = d_block[:-ord(d_block[-1])]
        d_blocks.append(d_block)
        carry = block

    return "".join(d_blocks) + "<EOF>"


print(aes_cbc_decrypt("140b41b22a29beb4061bda66b6747e14", "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"))

print(aes_cbc_decrypt("140b41b22a29beb4061bda66b6747e14", "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"))


def aes_ctr_decrypt(key, ct):
    ciphertext = unhexlify(ct)
    cipher = Cipher(algorithms.AES(unhexlify(key)), modes.ECB())

    # decrypt
    d_blocks = []
    counter = int.from_bytes(ciphertext[:16])
    for i in range(16, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        encryptor = cipher.encryptor()
        d_block = xorstr(block, (encryptor.update(counter.to_bytes(16)) + encryptor.finalize()))
        d_blocks.append(d_block)
        counter += 1


    return "".join(d_blocks) + "<EOF>"


print(aes_ctr_decrypt(
    "36f18357be4dbd77f050515c73fcf9f2",
    "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329",
))

print(aes_ctr_decrypt(
    "36f18357be4dbd77f050515c73fcf9f2",
    "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451",
))
