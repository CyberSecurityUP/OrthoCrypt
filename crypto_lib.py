import numpy as np
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Tamanho do bloco em bytes
BLOCK_SIZE = 64  # 64 bytes (16 palavras de 4 bytes cada)

# Função para gerar uma matriz ortogonal aleatória
def generate_orthogonal_matrix(size):
    while True:
        matrix = np.random.randint(0, 256, (size, size))
        det = int(round(np.linalg.det(matrix)))
        if det != 0:  # Garantir que a matriz seja invertível
            return matrix % 256

# Função para aplicar uma transformação matricial ortogonal
def orthogonal_transform(block, matrix):
    # Garantir que o bloco tenha 64 bytes
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"O bloco deve ter exatamente {BLOCK_SIZE} bytes. Tamanho recebido: {len(block)}")
    # Converter o bloco em uma matriz 16x4 (16 palavras de 4 bytes cada)
    block_array = np.array(list(block)).reshape(16, 4)
    # Aplicar a transformação matricial
    transformed_block = np.dot(matrix, block_array) % 256
    return bytes(transformed_block.flatten())

# Função para aplicar uma transformação não linear (exponencial modular)
def non_linear_transform(block):
    return bytes([pow(b, 3, 257) % 256 for b in block])

# Função para multiplicação em Galois Field (GF(2^8))
def gf_multiply(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B  # Polinômio irredutível para AES
        b >>= 1
    return p

# Função para cifrar um bloco
def encrypt_block(plaintext_block, key, orthogonal_matrix):
    if len(plaintext_block) != BLOCK_SIZE:
        raise ValueError(f"O bloco de texto plano deve ter exatamente {BLOCK_SIZE} bytes. Tamanho recebido: {len(plaintext_block)}")
    block = plaintext_block
    for _ in range(10):  # 10 rodadas
        block = non_linear_transform(block)  # Transformação não linear
        block = orthogonal_transform(block, orthogonal_matrix)  # Transformação matricial
        block = bytes([gf_multiply(b, key[i % len(key)]) for i, b in enumerate(block)])  # Multiplicação em GF
        block = bytes([b ^ key[i % len(key)] for i, b in enumerate(block)])  # XOR com a chave
    return block

# Função para decifrar um bloco
def decrypt_block(ciphertext_block, key, orthogonal_matrix):
    if len(ciphertext_block) != BLOCK_SIZE:
        raise ValueError(f"O bloco de texto cifrado deve ter exatamente {BLOCK_SIZE} bytes. Tamanho recebido: {len(ciphertext_block)}")
    block = ciphertext_block
    for _ in range(10):  # 10 rodadas (inverso)
        block = bytes([b ^ key[i % len(key)] for i, b in enumerate(block)])  # XOR com a chave
        block = bytes([gf_multiply(b, pow(key[i % len(key)], -1, 256)) for i, b in enumerate(block)])  # Multiplicação inversa em GF
        block = orthogonal_transform(block, np.linalg.inv(orthogonal_matrix).astype(int) % 256)  # Transformação matricial inversa
        block = non_linear_transform(block)  # Transformação não linear inversa
    return block

# Função para cifrar usando CBC mode
def encrypt_cbc(plaintext, key, orthogonal_matrix):
    iv = get_random_bytes(BLOCK_SIZE)
    ciphertext = iv
    previous_block = iv
    plaintext_padded = pad(plaintext, BLOCK_SIZE)  # Preencher o texto plano para múltiplo de 64 bytes
    print(f"Texto plano preenchido: {plaintext_padded.hex()}")  # Depuração
    for i in range(0, len(plaintext_padded), BLOCK_SIZE):
        block = plaintext_padded[i:i + BLOCK_SIZE]
        print(f"Bloco {i // BLOCK_SIZE + 1}: {block.hex()}")  # Depuração
        block = bytes([b ^ p for b, p in zip(block, previous_block)])
        encrypted_block = encrypt_block(block, key, orthogonal_matrix)
        ciphertext += encrypted_block
        previous_block = encrypted_block
    return ciphertext

# Função para decifrar usando CBC mode
def decrypt_cbc(ciphertext, key, orthogonal_matrix):
    iv = ciphertext[:BLOCK_SIZE]
    plaintext = b''
    previous_block = iv
    for i in range(BLOCK_SIZE, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        print(f"Bloco cifrado {i // BLOCK_SIZE}: {block.hex()}")  # Depuração
        decrypted_block = decrypt_block(block, key, orthogonal_matrix)
        plaintext_block = bytes([b ^ p for b, p in zip(decrypted_block, previous_block)])
        plaintext += plaintext_block
        previous_block = block
    return unpad(plaintext, BLOCK_SIZE)  # Remover o preenchimento
