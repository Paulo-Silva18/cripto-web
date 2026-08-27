# -*- coding: utf-8 -*-
"""
Implementação MANUAL do algoritmo DES (Data Encryption Standard).

Nenhuma biblioteca de criptografia é utilizada. Todas as permutações,
substituições (S-Boxes), o escalonamento de chaves e a rede de Feistel
são implementados diretamente com base na especificação FIPS 46-3.

O módulo também implementa:
  - Modo de operação CBC (Cipher Block Chaining), com IV aleatório
    gerado manualmente (os.urandom é usado apenas como fonte de
    aleatoriedade do sistema operacional, não é uma função de
    criptografia).
  - Preenchimento (padding) PKCS#7, necessário porque o DES opera
    sobre blocos fixos de 64 bits (8 bytes) e arquivos binários
    raramente têm tamanho múltiplo de 8.

Autor: Paulo (IFTM - Segurança da Informação)
"""

import os

# =========================================================================
# 1. TABELAS FIXAS DO ALGORITMO DES (definidas pela especificação FIPS 46-3)
# =========================================================================

# Permutação Inicial (IP) - aplicada ao bloco de 64 bits antes das rodadas
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# Permutação Inicial Inversa (IP^-1) - aplicada após as 16 rodadas
FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

# Tabela de Expansão (E) - expande metade direita de 32 para 48 bits
E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

# Permutação P - aplicada após a substituição pelas S-Boxes
P = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]

# Permutação de Escolha 1 (PC-1) - reduz a chave de 64 para 56 bits
PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

# Permutação de Escolha 2 (PC-2) - gera as 16 subchaves de 48 bits
PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

# Número de deslocamentos à esquerda (rotação) por rodada, no key schedule
SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# As 8 S-Boxes (substituição não-linear), núcleo da segurança do DES
SBOX = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    # S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    # S3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    # S4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    # S5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    # S6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    # S7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    # S8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

BLOCK_SIZE = 8  # DES trabalha com blocos de 64 bits = 8 bytes


# =========================================================================
# 2. FUNÇÕES AUXILIARES DE MANIPULAÇÃO DE BITS
# =========================================================================

def bytes_to_bits(data: bytes):
    """Converte uma sequência de bytes em uma lista de bits (0/1)."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits):
    """Converte uma lista de bits (0/1) de volta para bytes."""
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | b
        out.append(byte)
    return bytes(out)


def permute(bits, table):
    """Aplica uma tabela de permutação/seleção a uma lista de bits.
    A tabela usa índices baseados em 1 (convenção do padrão DES)."""
    return [bits[i - 1] for i in table]


def xor(bits1, bits2):
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]


def left_shift(bits, n):
    return bits[n:] + bits[:n]


# =========================================================================
# 3. ESCALONAMENTO DE CHAVES (KEY SCHEDULE)
# =========================================================================

def generate_subkeys(key_bytes: bytes):
    """Gera as 16 subchaves de 48 bits (uma para cada rodada) a partir
    da chave mestra de 64 bits (8 bytes, sendo 56 bits efetivos)."""
    key_bits = bytes_to_bits(key_bytes)
    key_56 = permute(key_bits, PC1)  # PC-1: 64 -> 56 bits

    c = key_56[:28]
    d = key_56[28:]

    subkeys = []
    for shift in SHIFTS:
        c = left_shift(c, shift)
        d = left_shift(d, shift)
        combined = c + d
        subkey = permute(combined, PC2)  # PC-2: 56 -> 48 bits
        subkeys.append(subkey)
    return subkeys


# =========================================================================
# 4. FUNÇÃO F (FEISTEL) E S-BOXES
# =========================================================================

def sbox_substitution(bits48):
    """Aplica as 8 S-Boxes sobre os 48 bits, produzindo 32 bits de saída."""
    output = []
    for i in range(8):
        block6 = bits48[i * 6:(i + 1) * 6]
        row = (block6[0] << 1) | block6[5]
        col = (block6[1] << 3) | (block6[2] << 2) | (block6[3] << 1) | block6[4]
        val = SBOX[i][row][col]
        for j in range(3, -1, -1):
            output.append((val >> j) & 1)
    return output


def feistel(right32, subkey48):
    """Função F: expande, faz XOR com a subchave, substitui (S-Box)
    e permuta o resultado."""
    expanded = permute(right32, E)          # 32 -> 48 bits
    xored = xor(expanded, subkey48)         # XOR com a subchave da rodada
    substituted = sbox_substitution(xored)  # 48 -> 32 bits (S-Boxes)
    return permute(substituted, P)          # permutação final P


# =========================================================================
# 5. CIFRAGEM/DECIFRAGEM DE UM ÚNICO BLOCO DE 64 BITS
# =========================================================================

def des_encrypt_block(block8: bytes, subkeys):
    """Cifra um único bloco de 8 bytes (64 bits) usando as 16 subchaves,
    aplicando a rede de Feistel clássica do DES."""
    bits = bytes_to_bits(block8)
    bits = permute(bits, IP)

    left, right = bits[:32], bits[32:]
    for round_num in range(16):
        new_right = xor(left, feistel(right, subkeys[round_num]))
        left = right
        right = new_right

    # Troca final (pré-permutação final) - característica do DES
    pre_output = right + left
    cipher_bits = permute(pre_output, FP)
    return bits_to_bytes(cipher_bits)


def des_decrypt_block(block8: bytes, subkeys):
    """Decifra um bloco usando as mesmas subchaves em ordem inversa."""
    return des_encrypt_block(block8, list(reversed(subkeys)))


# =========================================================================
# 6. PADDING PKCS#7 (implementado manualmente)
# =========================================================================

def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Adiciona preenchimento PKCS#7: cada byte adicionado tem o valor
    igual à quantidade de bytes de preenchimento necessária.
    Se os dados já forem múltiplos do tamanho do bloco, um bloco
    inteiro de padding é adicionado (regra do PKCS#7)."""
    pad_len = block_size - (len(data) % block_size)
    padding = bytes([pad_len] * pad_len)
    return data + padding


def pkcs7_unpad(data: bytes) -> bytes:
    """Remove o preenchimento PKCS#7, validando sua consistência."""
    if not data:
        raise ValueError("Dados vazios: não é possível remover padding.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Padding PKCS#7 inválido.")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Padding PKCS#7 inconsistente (chave errada?).")
    return data[:-pad_len]


# =========================================================================
# 7. MODO DE OPERAÇÃO CBC (Cipher Block Chaining)
# =========================================================================

def _prepare_key(key: bytes) -> bytes:
    """Normaliza a chave informada pelo usuário para exatamente 8 bytes
    (64 bits), truncando ou preenchendo com zeros conforme necessário."""
    if len(key) < BLOCK_SIZE:
        key = key + bytes(BLOCK_SIZE - len(key))
    return key[:BLOCK_SIZE]


def encrypt_cbc(plaintext: bytes, key: bytes) -> bytes:
    """Cifra dados arbitrários (ex.: um arquivo binário) usando DES no
    modo CBC. Retorna: IV (8 bytes) + dados cifrados.
    O IV é gerado aleatoriamente para cada operação de cifragem."""
    key = _prepare_key(key)
    subkeys = generate_subkeys(key)

    padded = pkcs7_pad(plaintext)
    iv = os.urandom(BLOCK_SIZE)  # apenas fonte de aleatoriedade do SO

    ciphertext = bytearray()
    previous = iv
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i + BLOCK_SIZE]
        xored_block = bytes(b ^ p for b, p in zip(block, previous))
        enc_block = des_encrypt_block(xored_block, subkeys)
        ciphertext.extend(enc_block)
        previous = enc_block

    return iv + bytes(ciphertext)


def decrypt_cbc(data: bytes, key: bytes) -> bytes:
    """Decifra dados no formato IV(8 bytes) + blocos cifrados, produzidos
    por encrypt_cbc, e remove o padding PKCS#7 ao final."""
    if len(data) < BLOCK_SIZE:
        raise ValueError("Dados cifrados inválidos (menores que o IV).")

    key = _prepare_key(key)
    subkeys = generate_subkeys(key)

    iv, ciphertext = data[:BLOCK_SIZE], data[BLOCK_SIZE:]
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Dados cifrados corrompidos: tamanho inválido.")

    plaintext = bytearray()
    previous = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        dec_block = des_decrypt_block(block, subkeys)
        xored_block = bytes(b ^ p for b, p in zip(dec_block, previous))
        plaintext.extend(xored_block)
        previous = block

    return pkcs7_unpad(bytes(plaintext))
