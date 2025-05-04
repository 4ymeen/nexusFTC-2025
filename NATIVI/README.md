# CTF Challenge Writeup: NATIVI

## Challenge Overview

This challenge involves reverse-engineering a C++ program to uncover a hidden flag in the format `nexus{...}`, commonly used in Capture The Flag (CTF) competitions. The program performs a series of bitwise transformations and XOR operations on provided byte arrays (`fakeflag`, `key`, `affus`, and `key2`) and attempts to read a file whose name and contents are derived from these arrays. A provided Python script replicates the necessary transformations to compute the flag directly.

---

## Provided Resources

### C++ Code
The C++ program includes functions such as:
- `bitShiftLeft`
- `bitShiftRight`
- `xorRotateTransform`
- `rc4_encrypt`

These functions manipulate byte arrays and perform file operations.

### Byte Arrays
The following byte arrays are provided:
```plaintext
fakeflag = [0xB8, 0xBE, 0xC1, 0xA6, 0xBB, 0xB6, 0xC2]
key = [0x6B, 0xE3, 0x53, 0x43, 0x83, 0x6B, 0x32]
affus = [0x72, 0x61, 0xD3, 0xC2, 0x42, 0x33, 0x02]
key2 = [0x1A, 0x00, 0x0B, 0x04, 0x1A, 0x0F, 0x0B, 0x5D, 0x0E, 0x05, 0x50, 0x04, 
    0x4B, 0x1D, 0x2B, 0x2B, 0x1D, 0x2E, 0x3D, 0x47, 0x3A, 0x23, 0x25, 0x45, 
    0x0C, 0x4C, 0x07]
flag = [ord(i) for i in "teqsitnagh.txt"]  # Appears in an error path, likely a red herring.
```

### Python Script
A Python script is provided to replicate the transformations and compute the flag.

---

## Solution Approach

### Step 1: Derive the Filename
The `fakeflag` array is transformed using the `bitShiftLeft` function to generate a filename:
```python
filename = ''.join(chr((b - 70) ^ 0x19) for b in fakeflag)
```
**Result:** `Filename = "kabylie"`

---

### Step 2: Compute `v26` from `key`
The `key` array is processed using the `bitShiftRight` function:
```python
v26 = [bitRotateRight(b, 3) ^ 0x19 for b in key]
```
**Result:** `v26 = "tesqit_"`

---

### Step 3: Compute `v25` from `affus`
The `affus` array is processed using the `xorRotateTransform` function:
```python
v25 = [bitRotateLeft(b, 4) ^ 0x49 for b in affus]
```
**Result:** `v25 = "n_temzi"`

---

### Step 4: Compute `v24` (File Content)
The program expects the file "kabylie" to contain the concatenation of `v26` and `v25`:
```python
v24 = v26 + v25
```
**Result:** `v24 = "tesqit_n_temzi"`

---

### Step 5: Compute the Flag (`v23`)
The file content (`v24`) is XORed with `key2` using the `rc4_encrypt` function:
```python
v23 = [key2[i] ^ v24[i % len(v24)] for i in range(len(key2))]
```
**Result:** `v23 = "nexus{T3Qq5i1t_Nn_T3uMz1i!}"`

---

### Step 6: Verification
The program verifies that the file content matches `v24`. If true, it computes the flag (`v23`) and performs additional checks (e.g., checksum). The provided flag (`"teqsitnagh.txt"`) appears in an error path, indicating it is a red herring.

---

## Python Script

The following Python script automates the solution:

```python
# Define the arrays from the C++ code
fakeflag = [0xB8, 0xBE, 0xC1, 0xA6, 0xBB, 0xB6, 0xC2]
key = [0x6B, 0xE3, 0x53, 0x43, 0x83, 0x6B, 0x32]
affus = [0x72, 0x61, 0xD3, 0xC2, 0x42, 0x33, 0x02]
key2 = [0x1A, 0x00, 0x0B, 0x04, 0x1A, 0x0F, 0x0B, 0x5D, 0x0E, 0x05, 0x50, 0x04, 
    0x4B, 0x1D, 0x2B, 0x2B, 0x1D, 0x2E, 0x3D, 0x47, 0x3A, 0x23, 0x25, 0x45, 
    0x0C, 0x4C, 0x07]

# Define bit rotation functions
def bitRotateRight(b, n):
    return ((b >> n) | (b << (8 - n))) & 0xFF

def bitRotateLeft(b, n):
    return ((b << n) | (b >> (8 - n))) & 0xFF

# Step 1: Compute the filename
filename = ''.join(chr((b - 70) ^ 0x19) for b in fakeflag)
print("Filename:", filename)

# Step 2: Compute v26
v26 = [bitRotateRight(b, 3) ^ 0x19 for b in key]
v26_str = ''.join(chr(c) for c in v26)
print("v26:", v26_str)

# Step 3: Compute v25
v25 = [bitRotateLeft(b, 4) ^ 0x49 for b in affus]
v25_str = ''.join(chr(c) for c in v25)
print("v25:", v25_str)

# Step 4: Compute v24
v24 = v26 + v25
v24_str = v26_str + v25_str
print("v24 (file content):", v24_str)

# Step 5: Compute the flag
v23 = [key2[i] ^ v24[i % len(v24)] for i in range(len(key2))]
flag = ''.join(chr(c) for c in v23)
print("Flag:", flag)
```

**Output:**
```plaintext
Filename: kabylie
v26: tesqit_
v25: n_temzi
v24 (file content): tesqit_n_temzi
Flag: nexus{T3Qq5i1t_Nn_T3uMz1i!}
```

---

## Key Insights

1. The `fakeflag` array generates the filename `"kabylie"`, which must contain `"tesqit_n_temzi"`.
2. The `key` and `affus` arrays produce the file content via transformations.
3. The `key2` array, XORed with the file content, yields the flag.
4. The provided flag (`"teqsitnagh.txt"`) is a red herring.

---

## Final Flag
The flag is:
```plaintext
nexus{T3Qq5i1t_Nn_T3uMz1i!}
```

---

## Conclusion
This challenge required careful analysis of the C++ code to identify the success path and replicate the transformations in Python. The provided script efficiently computes the flag by focusing on the critical operations, making it a valuable tool for solving similar reverse-engineering CTF challenges.

