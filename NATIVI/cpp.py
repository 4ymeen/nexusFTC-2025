# Define the arrays from the C++ code
fakeflag = [0xB8, 0xBE, 0xC1, 0xA6, 0xBB, 0xB6, 0xC2]
key = [0x6B, 0xE3, 0x53, 0x43, 0x83, 0x6B, 0x32]
affus = [0x72, 0x61, 0xD3, 0xC2, 0x42, 0x33, 0x02]
key2 = [0x1A, 0x00, 0x0B, 0x04, 0x1A, 0x0F, 0x0B, 0x5D, 0x0E, 0x05, 0x50, 0x04, 
        0x4B, 0x1D, 0x2B, 0x2B, 0x1D, 0x2E, 0x3D, 0x47, 0x3A, 0x23, 0x25, 0x45, 
        0x0C, 0x4C, 0x07]

# Define bit rotation functions for 8-bit bytes
def bitRotateRight(b, n):
    """Rotate bits of byte b to the right by n positions."""
    return ((b >> n) | (b << (8 - n))) & 0xFF

def bitRotateLeft(b, n):
    """Rotate bits of byte b to the left by n positions."""
    return ((b << n) | (b >> (8 - n))) & 0xFF

# Step 1: Compute the filename from fakeflag
filename = ''.join(chr((b - 70) ^ 0x19) for b in fakeflag)
print("Filename:", filename)

# Step 2: Compute v26 from key
v26 = [bitRotateRight(b, 3) ^ 0x19 for b in key]
v26_str = ''.join(chr(c) for c in v26)
print("v26:", v26_str)

# Step 3: Compute v25 from affus
v25 = [bitRotateLeft(b, 4) ^ 0x49 for b in affus]
v25_str = ''.join(chr(c) for c in v25)
print("v25:", v25_str)

# Step 4: Compute v24 as the concatenation of v26 and v25
v24 = v26 + v25
v24_str = v26_str + v25_str
print("v24 (file content):", v24_str)

# Step 5: Compute v23 by XORing key2 with v24 cycled
v23 = [key2[i] ^ v24[i % len(v24)] for i in range(len(key2))]
flag = ''.join(chr(c) for c in v23)
print("Flag:", flag)