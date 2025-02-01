# OrthoCrypt

symmetric encryption algorithm that combines orthogonal matrix transformations, finite field operations (Galois Field), and non-linear substitution techniques to ensure security and efficiency. The algorithm operates on 64-byte blocks and uses the CBC (Cipher Block Chaining) mode of operation to enhance security for long texts.

## Features

- **Matrix Transformations**: Uses orthogonal matrices for data diffusion and confusion.
- **Non-Linear Substitution**: Applies a non-linear function to increase the complexity of the algorithm.
- **Finite Field Operations**: Performs multiplications in \( \text{GF}(2^8) \) to mix the bytes of the block.
- **CBC Mode**: Ensures that identical plaintext blocks produce different ciphertext blocks.

## How to Use

1. Run the Python script:
   ```bash
   python main.py
   ```

## Example Usage

```python
from crypto_lib import generate_orthogonal_matrix, encrypt_cbc, decrypt_cbc
from Crypto.Random import get_random_bytes

# Generate key and orthogonal matrix
key = get_random_bytes(64)
orthogonal_matrix = generate_orthogonal_matrix(16)

# Plaintext
plaintext = b"This is a secret message!"

# Encrypt
ciphertext = encrypt_cbc(plaintext, key, orthogonal_matrix)
print(f"Encrypted text (hex): {ciphertext.hex()}")

# Decrypt
decrypted_text = decrypt_cbc(ciphertext, key, orthogonal_matrix)
print(f"Decrypted text: {decrypted_text.decode()}")
```

## Known Bugs

The code still has some bugs that need to be resolved:

1. **64-Byte Block Issue**:
   - The `orthogonal_transform` function is generating errors when processing 64-byte blocks. The matrix transformation needs to be adjusted to ensure the block has the correct size.

2. **Orthogonal Matrix Inversion**:
   - The inversion of the orthogonal matrix in \( \mathbb{Z}_{256} \) is not working correctly in some cases. This affects data decryption.

3. **Computational Efficiency**:
   - The algorithm is computationally intensive for large blocks. Optimizations are needed to improve performance.

4. **Inconsistent Padding**:
   - Padding blocks to multiples of 64 bytes is causing inconsistencies in some scenarios.
