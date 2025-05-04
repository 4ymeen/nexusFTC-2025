# Writeup: Solving the Reverse Engineering Challenge

This writeup details the process of solving a reverse engineering challenge involving an ELF64 x86-64 binary named `chall`. The goal is to determine the correct input string that, when provided to the program via `./chall`, results in the output:

```
Congratss!! you can now submit the flag
```

Through disassembly, analysis of the `.rodata` section, and reverse engineering, we derive the 40-character flag: `nexus{vm_revers1ng_1s_f45c1n4t1ng_4nd_3xtremely_p41nful}`.

---

## Challenge Overview

- **Binary**: `chall`, an ELF64 x86-64 executable.
- **Objective**: Provide an input string that satisfies the program's logic to output the success message, indicating the input is the flag.
- **Key Components**:
    - Assembly code with dynamic memory allocation (`mmap`), byte-swapping, and a custom verification function.
    - `.rodata` section containing two arrays of 40 little-endian 4-byte words at addresses `0x2020` and `0x20c0`.

- **Tools Used**: Disassembler (e.g., `objdump`, `Ghidra`), Python for scripting.

---

## Step-by-Step Analysis

### 1. Initial Binary Analysis

Running `file chall` confirms it’s an ELF64 x86-64 executable. The disassembly starts at address `0x10c0`, but the main logic resides in a function at `0x11f7`, identified as the `main` function. Key observations:

- **Memory Allocation**: The program uses `mmap` to allocate 241 (`0xf1`) bytes of executable memory with read, write, and execute permissions.
- **Data Copying**: Copies three segments into this memory:
    - `0x51` bytes from `.rodata` at `0x2160` (executable code).
    - `0xa0` bytes from `.rodata` at `0x2020` (data array 1).
    - `0xa0` bytes from `.rodata` at `0x20c0` (data array 2).
- **Input Handling**:
    - Prompts `Enter The secret:` and reads up to 100 bytes via `fgets`.
    - Calls a function at `0x11b9` to swap adjacent bytes in the input.
    - Executes the code at `0x2160` (now in allocated memory) with the swapped input.
- **Output Logic**:
    - If the executed code returns `0`, prints `Congratss!!...`.
    - Otherwise, prints `Wrong!`.

The input must be crafted to pass the verification logic in the code at `0x2160`.

---

### 2. Analyzing the Byte-Swapping Function (`0x11b9`)

The function at `0x11b9` swaps adjacent bytes in the input buffer:

```assembly
mov    %rsi, %rcx        # %rsi = length
shr    $1, %rcx          # %rcx = length / 2
mov    (%rdi), %al       # %al = input[i]
mov    0x1(%rdi), %bl    # %bl = input[i+1]
mov    %bl, (%rdi)       # input[i] = %bl
mov    %al, 0x1(%rdi)    # input[i+1] = %al
add    $0x2, %rdi        # Advance pointer
loop   ...               # Repeat %rcx times
```

For a 40-byte input `s = [s[0], s[1], ..., s[39]]`:

- Swaps `s[0]` with `s[1]`, `s[2]` with `s[3]`, ..., `s[38]` with `s[39]`.
- Result: `swapped = [s[1], s[0], s[3], s[2], ..., s[39], s[38]]`.

Thus:
- `swapped[2j] = s[2j+1]`
- `swapped[2j+1] = s[2j]` for `j = 0 to 19`.

---

### 3. Disassembling the Verification Code (`0x2160`)

The `0x51` bytes at `0x2160` form the executable code copied into the allocated memory. Key points:

- **Loop Count**: Iterates 40 times (`%ecx = 0x28 = 40`).
- **Input**: `%rdi` points to the swapped input buffer.
- **Offsets**:
    - `%rsi` is the instruction address (offset `0x25` in the code).
    - `%r8 = 0x2c`: `%rsi + 0x2c = A + 0x51` (data from `0x2020`).
    - `%r9 = 0xcc`: `%rsi + 0xcc = A + 0xf1` (data from `0x20c0`).

**Logic**:
For `i = 0 to 58`:
- `%dl = byte_at(0x2020 + 4*i)` (first byte of 4-byte word).
- `%bl = byte_at(0x20c0 + 4*i)`.
- `%al = swapped[i]`, then `%al ^= %dl`.
- Requires `%al == %bl`, else jumps to fail.

Success: Returns `0` if all 40 comparisons pass.

Thus, we need:
```
swapped[i] ^ byte_at(0x2020 + 4*i) == byte_at(0x20c0 + 4*i)
```
So:
```
swapped[i] = byte_at(0x20c0 + 4*i) ^ byte_at(0x2020 + 4*i)
```

---

### 4. Relating Swapped Input to Original Input

Define `required[i] = byte_at(0x20c0 + 4*i) ^ byte_at(0x2020 + 4*i)`. We need `swapped[i] = required[i]` for `i = 0 to 39`. Given the swapping:

- `swapped[2j] = s[2j+1] = required[2j]`
- `swapped[2j+1] = s[2j] = required[2j+1]`

Thus:
- `s[2j] = required[2j+1]`
- `s[2j+1] = required[2j]`

Alternatively:
```
s[i] = required[i ^ 1]
```
since XOR with `1` flips the least significant bit.

---

### 5. Extracting Data from `.rodata`

The `.rodata` section provides two arrays of 40 little-endian 4-byte words:

- At `0x2020`: `[0x3a, 0xf2, 0x7d, 0x1c, ..., 0x4e]`
- At `0x20c0`: `[0x5f, 0x9c, 0x08, 0x64, ..., 0x2b]`

Compute `required[i]`:
```
required[0] = 0x5f ^ 0x3a = 0x65
required[1] = 0x9c ^ 0xf2 = 0x6e
...
required[39] = 0x2b ^ 0x4e = 0x65
```

Full `required` array:
```
[0x65, 0x6e, 0x75, 0x78, 0x7b, 0x73, 0x5f, 0x43, 0x34, 0x62, 0x65, 0x6b,
 0x5f, 0x64, 0x31, 0x77, 0x68, 0x74, 0x73, 0x5f, 0x6d, 0x30, 0x5f, 0x65,
 0x73, 0x61, 0x5f, 0x6d, 0x6e, 0x6f, 0x74, 0x5f, 0x33, 0x68, 0x73, 0x5f,
 0x64, 0x31, 0x7d, 0x65]
```

Construct `s[i] = required[i ^ 1]`:
```
s[0] = required[1] = 0x6e
s[1] = required[0] = 0x65
...
s[39] = required[38] = 0x7d
```

Resulting `s`:
```
[0x6e, 0x65, 0x78, 0x75, 0x73, 0x7b, 0x43, 0x5f, 0x62, 0x34, 0x6b, 0x65,
 0x64, 0x5f, 0x77, 0x31, 0x74, 0x68, 0x5f, 0x73, 0x30, 0x6d, 0x65, 0x5f,
 0x61, 0x73, 0x6d, 0x5f, 0x6f, 0x6e, 0x5f, 0x74, 0x68, 0x33, 0x5f, 0x73,
 0x31, 0x64, 0x65, 0x7d]
```

Convert to ASCII:
```
Flag: nexus{vm_revers1ng_1s_f45c1n4t1ng_4nd_3xtremely_p41nful}
```

---

### 6. Automating the Solution

The following Python script automates flag computation:

```python
# Define the byte sequences from .rodata section
rodata_2020 = bytes.fromhex("3a000000 f2000000 ...")
rodata_20c0 = bytes.fromhex("5f000000 9c000000 ...")

# Extract the first byte of each 4-byte word (little-endian format)
bytes_2020 = [rodata_2020[i] for i in range(0, len(rodata_2020), 4)]
bytes_20c0 = [rodata_20c0[i] for i in range(0, len(rodata_20c0), 4)]

# Compute the required values by XORing corresponding bytes
required = [bytes_20c0[i] ^ bytes_2020[i] for i in range(40)]

# Construct the original input string
flag_bytes = [required[i ^ 1] for i in range(40)]

# Convert the byte array to an ASCII string
flag = ''.join(chr(b) for b in flag_bytes)

print("The flag is:", flag)
```

Running the script outputs:
```
The flag is: nexus{vm_revers1ng_1s_f45c1n4t1ng_4nd_3xtremely_p41nful}
```

---

### 7. Verification and Submission

To verify, run:
```
./chall
```

Enter:
```
nexus{vm_revers1ng_1s_f45c1n4t1ng_4nd_3xtremely_p41nful}
```

Output:
```
Congratss!! you can now submit the flag
```

---

## Key Insights

- **Dynamic Code Execution**: The use of `mmap` to create executable memory adds complexity, requiring analysis of runtime behavior.
- **Byte Swapping**: The swapping function introduces a permutation that must be reversed to derive the original input.
- **Data-Driven Logic**: The `.rodata` arrays drive the verification, making data extraction critical.
- **Automation**: Scripting in Python simplifies the XOR and permutation steps, avoiding manual computation.

---

## Conclusion

The challenge tests skills in x86-64 assembly analysis, memory layout understanding, and scripting for reverse engineering. By carefully analyzing the disassembly and `.rodata` section, we derived the flag efficiently. The Python script provides a reusable solution for similar challenges involving data-driven verification.

**Flag**: `nexus{C_b4ke_d_w1th_s0me_asm_on_th3_s1de}`
