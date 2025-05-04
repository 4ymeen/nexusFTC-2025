# Writeup: Patching `pong.com` with Python Script

## Overview

The provided Python script, `patch_pong.py`, modifies the MS-DOS COM executable `pong.com` to reveal a hidden flag in a Capture The Flag (CTF) challenge. The script applies two byte patches to ensure the program jumps directly to the flag-displaying routine and exits cleanly, displaying the flag when run in DOSBox. This writeup explains the problem, the script's functionality, and its effect.

---

## Problem Context

The `pong.com` binary is a DOS-based game (likely Pong) containing a hidden flag. The flag is displayed when the game state byte at memory address `0x086B` (referred to as `byte_1086B`, file offset `0x086B - 0x0100 = 0x076B`) is set to `0x03`. This triggers a routine at `0x0796` that prints:

```
"HERE IS YOUR FLAG :"
```

and renders the flag (as text or pixel graphics). However, an infinite loop at `0x07DD` (file offset `0x07DD - 0x0100 = 0x06DD`) with the instruction `EB FE` prevents clean termination. The script patches these locations to show the flag and exit.

---

## Script Analysis

The script automates patching by modifying `pong.com` at specific offsets and saving the result to a new file. Below is a detailed breakdown.

### Script Code

```python
import sys

# Check if input and output file names are provided
if len(sys.argv) != 3:
    print("Usage: python patch_pong.py <input_file> <output_file>")
    sys.exit(1)

input_file = sys.argv[1]
output_file = sys.argv[2]

# Define the patches: (offset, bytes)
patches = [
    (0x076B, b'\x03'),      # Set game state to 0x03
    (0x06DD, b'\xCD\x20')   # Replace infinite loop with INT 20h
]

# Calculate the minimum required file size
required_size = max(offset + len(data) for offset, data in patches)

try:
    # Read the original file
    with open(input_file, 'rb') as f:
        data = bytearray(f.read())

    # Check if the file is large enough
    if len(data) < required_size:
        print(f"Error: File is too small. Expected at least {required_size} bytes, got {len(data)}.")
        sys.exit(1)

    # Apply the patches
    for offset, new_bytes in patches:
        data[offset:offset + len(new_bytes)] = new_bytes

    # Write the patched file
    with open(output_file, 'wb') as f:
        f.write(data)

    print(f"Successfully patched {input_file} to {output_file}")

except FileNotFoundError:
    print(f"Error: Input file '{input_file}' not found.")
    sys.exit(1)
except Exception as e:
    print(f"Error: An unexpected error occurred: {e}")
    sys.exit(1)
```

---

### Key Components

#### Command-Line Arguments

- Expects two arguments: input file (`pong.com`) and output file (e.g., `patched_pong.com`).
- Prints usage instructions and exits if arguments are incorrect.

#### Patch Definitions

- Two patches:
  1. **Offset `0x076B`**: Set to `0x03` (1 byte). Sets `byte_1086B` to `0x03`, directing the program to the flag-display routine.
  2. **Offset `0x06DD`**: Set to `CD 20` (2 bytes). Replaces the infinite loop (`EB FE`) at `0x07DD` with `INT 20h`, terminating the program.

#### File Size Check

- Ensures the file is at least `0x076C` bytes (highest offset `0x076B + 1`).
- `pong.com` is `0x101F` bytes (4127), so it passes.

#### Patching Process

1. Reads `pong.com` into a `bytearray`.
2. Overwrites bytes at specified offsets.
3. Writes the modified `bytearray` to the output file.

#### Error Handling

- Catches `FileNotFoundError` for missing input files.
- Handles unexpected errors with descriptive messages.

---

## Why These Patches?

- **Offset `0x076B`**: Setting `byte_1086B` to `0x03` makes the program’s state check (e.g., at `0x010E`) jump to `loc_10796` (`0x0796`), which displays the flag.
- **Offset `0x06DD`**: Replacing `EB FE` with `CD 20` ensures the program exits after showing the flag, avoiding the infinite loop.

---

## Usage

### Save the Script

Save the script as `patch_pong.py`.

### Run the Script

From `/mnt/default-linux/Downloads/nexus`:

```bash
python patch_pong.py pong.com patched_pong.com
```

### Run the Patched Binary

In DOSBox:

```bash
dosbox
mount c /mnt/default-linux/Downloads/nexus
C:
patched_pong.com
```

The flag will be printed on the screen.

---

## Technical Details

### COM File

- COM files load at `0x0100` in memory. File offsets are `memory_address - 0x0100`.
- File size: `0x101F` bytes, sufficient for patches at `0x076B` and `0x06DD`.

### Offsets

- `0x076B = 0x086B - 0x0100` (game state).
- `0x06DD = 0x07DD - 0x0100` (infinite loop).

### Patch Effects

- **`0x076B`**: Modifies data to trigger flag display.
- **`0x06DD`**: Changes code to terminate the program.

---

## Verification

Check patches with:

```bash
xxd patched_pong.com | grep "0760\|06d0"
```

Expected output:

```
00006d0: xx xx xx xx xx xx xx xx xx xx xx xx xx cd 20 xx  ............. ..
0000760: xx xx xx xx xx xx xx xx xx xx xx 03 xx xx xx xx  ...............x
```

---

## Conclusion

The `patch_pong.py` script efficiently patches `pong.com` by setting the game state to `0x03` at `0x076B` and replacing the infinite loop with `INT 20h` at `0x06DD`. Running `patched_pong.com` in DOSBox will display the flag directly, solving the CTF challenge.
