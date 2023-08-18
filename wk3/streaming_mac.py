from cryptography.hazmat.primitives import hashes
from binascii import hexlify


#f = open("./6.2.birthday.mp4_download", "rb")
f = open("./6.1.intro.mp4_download", "rb")
blocks = []
while block := f.read(1024):
    blocks.append(block)

prev = blocks[-1]
for i in reversed(range(len(blocks)-1)):
    block = blocks[i]
    digest = hashes.Hash(hashes.SHA256())
    digest.update(prev)
    h = digest.finalize()
    blocks[i] = block + h
    prev = blocks[i]

print(i)
digest = hashes.Hash(hashes.SHA256())
digest.update(prev)
h = digest.finalize()
print(hexlify(h))
