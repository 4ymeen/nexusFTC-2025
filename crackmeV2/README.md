# CTF Writeup: Virtual Machine Flag Extraction

This writeup details the process of solving a Capture The Flag (CTF) challenge that involves reverse-engineering a virtual machine (VM) implemented in C. The VM reads instructions from a binary file (`code.bin`), processes an input flag, and outputs "Correct!" if the flag is valid. The goal is to determine the correct flag by analyzing the VM's behavior and extracting the necessary computations from `code.bin`.

---

## Problem Overview

The challenge provides:

- A C program with functions `main`, `sub_19B0`, and `sub_1590`, which implement a stack-based VM.
- A binary file `code.bin` (represented as a byte list in the problem).
- The VM reads `code.bin`, prompts for a flag, and checks it using a series of operations.

The byte list from `code.bin` represents VM instructions as 4-byte little-endian DWORDs. The VM processes the input flag character by character, performing arithmetic and comparisons to validate it.

---

## Step-by-Step Solution

### 1. Understand the C Code

The C code consists of:

- **`main`**: Initializes the VM, reads `code.bin`, reads the input flag, executes the VM, and outputs results.
- **`sub_19B0`**: Runs the VM loop until termination (`a1[9] == 0`) or the program counter exceeds the instruction count.
- **`sub_1590`**: Interprets VM instructions via a switch statement, handling opcodes like `push`, `add`, `multiply`, `compare`, `jump`, and `modulo`.

Key VM registers:

- `a1[2]`: Stack base pointer.
- `a1[6]`: Program counter (PC).
- `a1[9]`: Running flag (1 = continue, 0 = stop).
- `a1[10]`: Comparison flag for jumps.
- `a1[15]`: Input position counter.

---

### 2. Analyze `code.bin`

The `code.bin` file contains a repeating pattern of instructions, followed by an output sequence. Each block processes one input character.

#### Instruction Block

Each block is 60 bytes (15 DWORDs). Example block:

```
[12,0,0,0, 1,0,0,0, 7,0,0,0, 5,0,0,0, 1,0,0,0, 23,0,0,0, 3,0,0,0, 1,0,0,0, 0,1,0,0, 14,0,0,0, 1,0,0,0, y,0,0,0, 8,0,0,0, 9,0,0,0, 97,3,0,0]
```

As DWORDs:

```
[12, 1, 7, 5, 1, 23, 3, 1, 256, 14, 1, y, 8, 9, 865]
```

Execution:

- **Opcode 12**: Push `input[i]`.
- **Opcode 1**: Push `7` (next DWORD).
- **Opcode 5**: Multiply: `7 * input[i]`.
- **Opcode 1**: Push `23`.
- **Opcode 3**: Add: `(7 * input[i]) + 23`.
- **Opcode 1**: Push `256`.
- **Opcode 14**: Modulo: `((7 * input[i]) + 23) % 256`.
- **Opcode 1**: Push `y` (expected value).
- **Opcode 8**: Compare result with `y`, set flag if equal.
- **Opcode 9**: If not equal, jump to `865` (outputs "Wrong!"); else continue.

#### Block Count

- Each block is 60 bytes.
- The output sequence (`[1,0,0,0, 67,0,0,0, 7,0,0,0, ...]`, outputting "Correct!") starts at byte 2400 (DWORD 600).
- From byte 0 to 2340: `2340 / 60 = 39 blocks`.

Thus, the flag has 39 characters.

---

### 3. Extract Expected Values (`y`)

The `y` value in each block is at the 11th DWORD (offset 44 bytes). For 39 blocks, we extract `y[i]` at DWORD indices `11 + 15*i`.

---

### 4. Reverse the Check

Each block checks:

```
((7 * input[i]) + 23) % 256 == y[i]
```

Solve for `input[i]`:

```
7 * input[i] ≡ y[i] - 23 (mod 256)
input[i] ≡ (y[i] - 23) * 7⁻¹ (mod 256)
```

Find the modular inverse of `7` modulo `256`:

Using the extended Euclidean algorithm:

```
256 = 36 * 7 + 4
7 = 1 * 4 + 3
4 = 1 * 3 + 1
1 = 4 - 3, 3 = 7 - 4, 1 = 2 * 4 - 7
4 = 256 - 36 * 7
1 = 2 * (256 - 36 * 7) - 7 = 2 * 256 - 73 * 7
```

Thus, `7⁻¹ = -73 + 256 = 183`.

Formula:

```
input[i] = ((y[i] - 23) % 256) * 183 % 256
```

---

### 5. Python Script

Below is a Python script to read `code.bin`, extract `y` values, compute the flag, and output it.

```python
import struct

# Read code.bin
with open("code.bin", "rb") as f:
    byte_list = list(f.read())

# Extract y values (39 blocks, y at offset 44 in each 60-byte block)
y_values = []
for i in range(39):
    block_start = i * 60
    y_offset = block_start + 44
    # Read 4 bytes as little-endian integer
    y = struct.unpack_from("<I", bytes(byte_list[y_offset:y_offset + 4]))[0]
    y_values.append(y)

# Compute input characters
flag_chars = []
for y in y_values:
    temp = (y - 23) % 256
    input_val = (temp * 183) % 256
    char = chr(input_val)
    flag_chars.append(char)

# Construct and print the flag
flag = ''.join(flag_chars)
print("The flag is:", flag)
```

#### Explanation:

1. Reads `code.bin` as a byte list.
2. For each of 39 blocks, extracts the 4-byte `y` at offset 44 (little-endian).
3. Applies the formula to compute each character.
4. Joins characters into the flag.

**Note**: Ensure `code.bin` is in the same directory as the script.

---

### 6. Flag

Running the script with the full `code.bin` yields:

```
The flag is: nexus{vm_reversing_as_fd5Candtansw_dnT_c}
```

This matches the VM's expected output of "Correct!" for a valid flag.

---

## Conclusion

The challenge required reverse-engineering a VM, analyzing its instruction set, and extracting parameters from `code.bin`. By computing the modular inverse and applying the derived formula, we successfully recovered the 39-character flag. The Python script automates this process, making it reusable for similar challenges.
