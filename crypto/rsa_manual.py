# -*- coding: utf-8 -*-
"""
Implementação MANUAL do protocolo RSA.

Nenhuma biblioteca de criptografia (como `cryptography`, `pycryptodome`
ou `rsa`) é utilizada. Apenas o módulo padrão `os` (para obter bytes
aleatórios do sistema operacional, usados como semente de sorteio de
números ímpares candidatos a primos) e `random`.

Etapas implementadas manualmente, conforme exigido pela atividade:
  1. Geração de dois números primos grandes (teste de primalidade de
     Miller-Rabin, implementado do zero).
  2. Cálculo de n = p * q e do totiente de Euler φ(n) = (p-1)(q-1).
  3. Escolha do expoente público e (coprimo com φ(n)).
  4. Cálculo do expoente privado d através do Algoritmo de Euclides
     Estendido (inverso modular de e em relação a φ(n)).
  5. Conversão de texto <-> número (via representação em bytes/big
     integer) para permitir a exponenciação modular.
  6. Cifragem/decifragem com quebra da mensagem em blocos, já que o
     RSA "puro" só cifra números menores que n.

Autor: Paulo (IFTM - Segurança da Informação)
"""

import os
import random


# =========================================================================
# 1. TESTE DE PRIMALIDADE (Miller-Rabin) - implementado manualmente
# =========================================================================

def _is_probably_prime(n: int, rounds: int = 20) -> bool:
    """Teste de primalidade probabilístico de Miller-Rabin.
    Quanto maior `rounds`, menor a probabilidade de falso positivo
    (erro menor que 4^-rounds)."""
    if n < 2:
        return False
    # pequenos primos conhecidos, para descartar rapidamente não-primos
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for sp in small_primes:
        if n == sp:
            return True
        if n % sp == 0:
            return False

    # escreve n-1 = 2^r * d, com d ímpar
    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)  # exponenciação modular rápida
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """Gera um número primo aleatório com exatamente `bits` bits,
    usando sorteio de candidatos ímpares seguido do teste de
    Miller-Rabin (do zero)."""
    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1))  # garante o bit mais significativo
        candidate |= 1                  # garante que seja ímpar
        if _is_probably_prime(candidate):
            return candidate


# =========================================================================
# 2. ALGORITMO DE EUCLIDES ESTENDIDO (mdc + inverso modular)
# =========================================================================

def extended_gcd(a: int, b: int):
    """Retorna (g, x, y) tais que a*x + b*y = g = mdc(a, b).
    Implementação manual e recursiva do Algoritmo de Euclides
    Estendido."""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return g, x, y


def mod_inverse(e: int, phi: int) -> int:
    """Calcula o inverso modular de `e` em relação a `phi`, ou seja,
    o `d` tal que (e * d) mod phi == 1. Usa o Algoritmo de Euclides
    Estendido — é assim que o RSA obtém o expoente privado d a partir
    do expoente público e."""
    g, x, _ = extended_gcd(e, phi)
    if g != 1:
        raise ValueError("e e φ(n) não são coprimos: escolha outro e.")
    return x % phi


# =========================================================================
# 3. GERAÇÃO DO PAR DE CHAVES RSA
# =========================================================================

def generate_keypair(bits: int = 512):
    """Gera um par de chaves RSA (pública e privada).

    Etapas (todas manuais):
      1. Sorteia dois primos p e q distintos.
      2. Calcula n = p * q  (módulo usado nas duas chaves).
      3. Calcula φ(n) = (p-1)(q-1)  (totiente de Euler).
      4. Escolhe e = 65537 (padrão da indústria) se for coprimo com
         φ(n); caso contrário, busca o próximo ímpar coprimo.
      5. Calcula d = inverso modular de e em relação a φ(n), via
         Euclides Estendido.

    Retorna um dicionário com p, q, n, phi, e, d — os valores
    intermediários também são devolvidos para fins didáticos
    (o vídeo/README pode mostrar o passo a passo).
    """
    half_bits = bits // 2
    p = generate_prime(half_bits)
    q = generate_prime(half_bits)
    while q == p:
        q = generate_prime(half_bits)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if e >= phi or extended_gcd(e, phi)[0] != 1:
        e = 3
        while extended_gcd(e, phi)[0] != 1:
            e += 2

    d = mod_inverse(e, phi)

    return {
        "p": p, "q": q, "n": n, "phi": phi,
        "e": e, "d": d,
        "public_key": (e, n),
        "private_key": (d, n),
    }


# =========================================================================
# 4. CONVERSÃO TEXTO <-> NÚMERO
# =========================================================================

def text_to_int(text: str) -> int:
    """Converte uma string (UTF-8) em um único inteiro grande,
    interpretando os bytes como um número em base 256."""
    data = text.encode("utf-8")
    return int.from_bytes(data, byteorder="big")


def int_to_text(number: int) -> str:
    """Converte um inteiro de volta para a string original."""
    length = max(1, (number.bit_length() + 7) // 8)
    data = number.to_bytes(length, byteorder="big")
    return data.decode("utf-8")


# =========================================================================
# 5. CIFRAGEM/DECIFRAGEM COM QUEBRA EM BLOCOS
# =========================================================================
# O RSA "de livro-texto" só consegue cifrar um número M tal que M < n.
# Como uma mensagem de texto pode gerar um inteiro maior que n, a
# mensagem é quebrada em blocos de bytes cujo tamanho garante que cada
# bloco, convertido em inteiro, seja sempre menor que n.

def _max_block_bytes(n: int) -> int:
    """Calcula quantos bytes cabem em um bloco de forma que o inteiro
    resultante seja sempre < n (com uma margem de segurança de 1 byte)."""
    n_bytes = (n.bit_length() + 7) // 8
    return max(1, n_bytes - 1)


def rsa_encrypt(message: str, public_key) -> list:
    """Cifra uma mensagem de texto com a chave pública (e, n).
    Retorna uma lista de inteiros cifrados (um por bloco)."""
    e, n = public_key
    data = message.encode("utf-8")
    block_size = _max_block_bytes(n)

    cipher_blocks = []
    for i in range(0, len(data), block_size):
        chunk = data[i:i + block_size]
        m = int.from_bytes(chunk, byteorder="big")
        c = pow(m, e, n)  # cifragem: C = M^e mod n
        cipher_blocks.append(c)
    return cipher_blocks


def rsa_decrypt(cipher_blocks: list, private_key) -> str:
    """Decifra uma lista de blocos cifrados com a chave privada (d, n),
    reconstruindo a mensagem de texto original.

    Cada bloco decifrado M = C^d mod n é convertido de volta para bytes
    usando o número mínimo de bytes necessário (evitando zeros à
    esquerda espúrios que a exponenciação modular não preserva), e
    todos os bytes são concatenados e decodificados como UTF-8."""
    d, n = private_key
    plain_bytes = bytearray()
    for c in cipher_blocks:
        m = pow(c, d, n)  # decifragem: M = C^d mod n
        length = max(1, (m.bit_length() + 7) // 8)
        chunk = m.to_bytes(length, byteorder="big")
        plain_bytes.extend(chunk)
    return plain_bytes.decode("utf-8")
