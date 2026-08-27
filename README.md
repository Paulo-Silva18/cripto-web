# Implementação Web de Algoritmos Criptográficos

Aplicação Web (Flask) que implementa **manualmente, do zero**, dois algoritmos
criptográficos clássicos — sem uso de nenhuma biblioteca pronta de
criptografia (`cryptography`, `pycryptodome`, `hashlib` para cifra, `rsa`,
etc.):

- **Módulo Simétrico:** cifra de bloco **DES** (Data Encryption Standard),
  operando em modo **CBC**, com preenchimento **PKCS#7**, aplicada a
  arquivos binários (imagens `.jpg`/`.png`, documentos `.pdf`, ou qualquer
  outro arquivo).
- **Módulo Assimétrico:** protocolo **RSA** completo — geração de chaves,
  cifragem e decifragem de mensagens de texto.

> Disciplina: Segurança da Informação — IFTM Campus Patrocínio
> Avaliação: Prova 01 — Implementação Web de Algoritmos Criptográficos

---

## Sumário

1. [Como executar o projeto](#como-executar-o-projeto)
2. [Estrutura do repositório](#estrutura-do-repositório)
3. [Fundamentação teórica e matemática — DES](#fundamentação-teórica-e-matemática--des)
4. [Fundamentação teórica e matemática — RSA](#fundamentação-teórica-e-matemática--rsa)
5. [Como usar a aplicação](#como-usar-a-aplicação)
6. [Limitações conhecidas e decisões de projeto](#limitações-conhecidas-e-decisões-de-projeto)

---

## Como executar o projeto

### Pré-requisitos

- Python 3.9 ou superior
- `pip`

### Passo a passo

```bash
# 1. Clone o repositório
git clone https://github.com/Paulo-Silva18/cripto-web.git
cd cripto-web

# 2. (Recomendado) crie um ambiente virtual
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows

# 3. Instale as dependências (apenas o Flask — framework Web,
#    NÃO é usado para nenhum cálculo criptográfico)
pip install -r requirements.txt

# 4. Execute a aplicação
python app.py

# 5. Acesse no navegador
http://127.0.0.1:5000
```

A única dependência externa do projeto é o **Flask**, usado exclusivamente
como framework Web (rotas HTTP, upload de arquivos, renderização de
templates). Toda a lógica criptográfica — manipulação de bits e bytes,
permutações, S-Boxes, geração de primos, aritmética modular, Algoritmo de
Euclides Estendido — está implementada em Python puro, nos arquivos
`crypto/des.py` e `crypto/rsa_manual.py`.

---

## Estrutura do repositório

```
├── app.py                    # Rotas Flask (menu, módulo simétrico, módulo assimétrico)
├── requirements.txt          # Única dependência: Flask
├── crypto/
│   ├── des.py                # Implementação manual do DES (CBC + PKCS#7)
│   └── rsa_manual.py         # Implementação manual do RSA
├── templates/
│   ├── base.html             # Layout base (menu de navegação)
│   ├── index.html            # Menu principal
│   ├── simetrico.html        # Tela do módulo DES
│   └── assimetrico.html      # Tela do módulo RSA
└── static/
    ├── style.css
    └── script.js              # Chamadas AJAX (fetch) para os endpoints Flask
```

---

## Fundamentação teórica e matemática — DES

O **DES** é uma cifra de bloco simétrica que opera sobre blocos fixos de
**64 bits (8 bytes)**, usando uma chave de 64 bits (dos quais 56 bits são
efetivamente usados; os 8 restantes historicamente serviam de bits de
paridade). O algoritmo é uma **rede de Feistel** de 16 rodadas.

### 1. Permutação Inicial (IP) e Final (IP⁻¹)

Antes da primeira rodada, os 64 bits do bloco passam por uma permutação
fixa (tabela `IP`), que reordena os bits sem alterar seu valor. Ao final
das 16 rodadas, a permutação inversa (`FP`, equivalente a IP⁻¹) é aplicada.
Essas permutações não agregam segurança criptográfica por si só — sua
função original era facilitar a implementação em hardware da época.

### 2. Escalonamento de chaves (Key Schedule)

A partir da chave de 64 bits:

1. **PC-1** (Permuted Choice 1) descarta os 8 bits de paridade e reordena
   os 56 bits restantes, dividindo-os em duas metades `C₀` (28 bits) e
   `D₀` (28 bits).
2. Para cada uma das 16 rodadas, `C` e `D` sofrem uma **rotação circular
   à esquerda** (1 ou 2 posições, conforme a tabela `SHIFTS` — regra
   original do padrão FIPS 46-3).
3. **PC-2** (Permuted Choice 2) seleciona e reordena 48 dos 56 bits de
   `Cᵢ‖Dᵢ`, gerando a subchave `Kᵢ` daquela rodada.

Isso produz 16 subchaves de 48 bits, uma para cada rodada.

### 3. A rede de Feistel (16 rodadas)

Em cada rodada `i`, o bloco de 64 bits (após IP) é dividido em metades
`Lᵢ` e `Rᵢ` de 32 bits cada:

```
L(i) = R(i-1)
R(i) = L(i-1) XOR F(R(i-1), K(i))
```

A **função F** (coração da segurança do DES) faz:

1. **Expansão (E):** expande `R` de 32 para 48 bits, duplicando alguns
   bits (tabela `E`), para que possa ser combinado com a subchave de 48
   bits.
2. **XOR com a subchave:** `E(R) XOR Kᵢ`.
3. **Substituição (S-Boxes):** os 48 bits resultantes são divididos em
   oito grupos de 6 bits. Cada grupo passa por uma das 8 **S-Boxes**
   (tabelas de substituição não-lineares fixas), que o reduzem para 4
   bits. Os 2 bits das extremidades (primeiro e último) definem a
   **linha** da tabela; os 4 bits do meio definem a **coluna**. As
   S-Boxes são a única parte não-linear do algoritmo e são responsáveis
   por sua resistência à criptoanálise diferencial e linear.
4. **Permutação P:** os 32 bits resultantes (8 grupos × 4 bits) são
   novamente permutados pela tabela `P`.

Após as 16 rodadas, ocorre uma **troca final** (`R₁₆‖L₁₆`, e não
`L₁₆‖R₁₆`) seguida da permutação final `IP⁻¹`, produzindo o bloco
cifrado de 64 bits.

A **decifragem** usa exatamente o mesmo algoritmo, mas com as 16
subchaves aplicadas em **ordem inversa** — propriedade elegante da rede
de Feistel, que dispensa a implementação de um algoritmo separado para
decifrar.

### 4. Preenchimento PKCS#7 (Padding)

Como o DES só cifra blocos de exatamente 8 bytes, e um arquivo binário
raramente tem tamanho múltiplo de 8, é necessário completar o último
bloco. O **PKCS#7** faz isso de forma reversível:

- Calcula-se `n = tamanho_do_bloco - (tamanho_dos_dados mod tamanho_do_bloco)`.
- Adicionam-se `n` bytes ao final dos dados, **cada um com o valor `n`**.
- Se os dados já forem múltiplos do tamanho do bloco, um bloco inteiro de
  padding (8 bytes, todos com valor `8`) é adicionado — isso evita
  ambiguidade na hora de remover o padding.

Na decifragem, basta ler o valor do **último byte** do bloco decifrado:
ele informa exatamente quantos bytes remover.

Exemplo: dados terminando em `..., 0xA1` e faltando 3 bytes para completar
o bloco → `..., 0xA1, 0x03, 0x03, 0x03`.

### 5. Modo de operação CBC (Cipher Block Chaining)

Cifrar cada bloco de 8 bytes independentemente (modo ECB) é inseguro,
pois blocos de texto claro idênticos geram blocos cifrados idênticos
(padrões visíveis, por exemplo, em imagens). O modo **CBC** resolve isso:

```
C(0) = IV                              (vetor de inicialização aleatório)
C(i) = DES_encrypt( P(i) XOR C(i-1), K )
```

Cada bloco de texto claro é combinado (XOR) com o bloco cifrado
**anterior** antes de ser cifrado — encadeando os blocos e garantindo que
o mesmo texto claro produza cifrados diferentes a cada execução (pois o
IV é aleatório).

Na decifragem:

```
P(i) = DES_decrypt( C(i), K ) XOR C(i-1)
```

Nesta implementação, o **IV** (8 bytes aleatórios, gerados com
`os.urandom`) é gravado nos **primeiros 8 bytes** do arquivo de saída, e
extraído automaticamente no momento da decifragem — por isso o usuário
não precisa informá-lo manualmente.

---

## Fundamentação teórica e matemática — RSA

O **RSA** (Rivest–Shamir–Adleman) é um criptossistema **assimétrico**:
usa um par de chaves matematicamente relacionadas — uma **pública** (para
cifrar) e uma **privada** (para decifrar) — cuja segurança se baseia na
dificuldade computacional de **fatorar o produto de dois números primos
grandes**.

### 1. Geração dos números primos (p e q)

São sorteados dois números primos grandes e distintos, `p` e `q`. Para
isso, a implementação usa o **teste de primalidade de Miller-Rabin**
(`crypto/rsa_manual.py`, função `_is_probably_prime`): um teste
probabilístico que, dado um número ímpar candidato, verifica repetidas
vezes (por padrão, 20 rodadas) se ele se comporta como um primo através
da relação `a^d mod n`, com `n - 1 = 2^r · d`. A cada rodada que passa no
teste, a probabilidade de `n` ser composto (não-primo) cai para menos de
`1/4`; com 20 rodadas, o erro é desprezível (~4⁻²⁰).

### 2. Cálculo do módulo n

```
n = p × q
```

`n` faz parte tanto da chave pública quanto da privada. Seu tamanho em
bits (ex.: 256, 512...) define a "força" da chave RSA — quebrar o
sistema exigiria fatorar `n` de volta em `p` e `q`, algo
computacionalmente inviável para números grandes o suficiente com os
algoritmos clássicos conhecidos atualmente.

### 3. Totiente de Euler φ(n)

```
φ(n) = (p - 1) × (q - 1)
```

A **função totiente de Euler** φ(n) conta quantos números entre `1` e
`n` são coprimos com `n`. Para `n = p·q` com `p` e `q` primos, essa
fórmula simplificada vale graças a propriedades da teoria dos números
(multiplicatividade da função totiente).

### 4. Escolha do expoente público e

Escolhe-se `e` tal que `1 < e < φ(n)` e `mdc(e, φ(n)) = 1` (isto é, `e` e
`φ(n)` são **coprimos**). A implementação usa o valor convencional da
indústria, **`e = 65537`** (= 2¹⁶ + 1, escolhido por ser primo e por
tornar a exponenciação modular eficiente), voltando a um valor menor
apenas se `65537` não for coprimo com o `φ(n)` sorteado (caso raro).

### 5. Cálculo do expoente privado d — Algoritmo de Euclides Estendido

O expoente privado `d` é o **inverso modular** de `e` em relação a
`φ(n)`:

```
d ≡ e⁻¹ (mod φ(n))         ⟺        e × d ≡ 1 (mod φ(n))
```

Para calcular esse inverso, a implementação usa o **Algoritmo de
Euclides Estendido** (`extended_gcd`, em `crypto/rsa_manual.py`), que
encontra, para dois números `a` e `b`, coeficientes inteiros `x` e `y`
tais que:

```
a·x + b·y = mdc(a, b)
```

Aplicando isso a `a = e` e `b = φ(n)`, como `mdc(e, φ(n)) = 1`, obtemos:

```
e·x + φ(n)·y = 1   ⟹   e·x ≡ 1 (mod φ(n))   ⟹   d = x mod φ(n)
```

O algoritmo é implementado recursivamente, aplicando repetidamente a
identidade `mdc(a, b) = mdc(b, a mod b)` e "desfazendo" as divisões para
reconstruir os coeficientes `x` e `y`.

### 6. Chaves resultantes

- **Chave pública:** `(e, n)`
- **Chave privada:** `(d, n)`

### 7. Conversão texto ↔ número

Como o RSA opera sobre **números inteiros**, cada bloco da mensagem de
texto (codificada em UTF-8) é interpretado como um único inteiro grande,
tratando os bytes como dígitos em **base 256**
(`int.from_bytes(..., "big")`). Na decifragem, o processo inverso
(`int.to_bytes(...)`) reconstrói os bytes originais, decodificados de
volta para texto UTF-8.

### 8. Cifragem, decifragem e quebra em blocos

O RSA "de livro-texto" só consegue cifrar um número `M` menor que `n`.
Como a mensagem completa costuma gerar um inteiro maior que `n`, ela é
dividida em **blocos de bytes**, calculados para que cada bloco,
convertido em inteiro, seja sempre menor que `n`:

```
C = M^e mod n        (cifragem, com a chave pública)
M = C^d mod n        (decifragem, com a chave privada)
```

Essa exponenciação modular é calculada com `pow(base, exp, mod)`, que
implementa internamente o algoritmo de **exponenciação rápida** (fast
modular exponentiation / square-and-multiply) — essencial, pois `e`, `d`
e `n` podem ter centenas de dígitos, tornando inviável calcular
`M**e` por completo antes do módulo.

A correção matemática do RSA (por que decifrar recupera exatamente a
mensagem original) decorre do **Teorema de Euler**: como
`e·d ≡ 1 (mod φ(n))`, existe um inteiro `k` tal que `e·d = 1 + k·φ(n)`,
e portanto:

```
C^d mod n = (M^e)^d mod n = M^(1 + k·φ(n)) mod n = M · (M^φ(n))^k mod n = M mod n
```

(usando que `M^φ(n) ≡ 1 (mod n)` quando `mdc(M, n) = 1`, pelo Teorema de
Euler-Fermat generalizado.)

---

## Como usar a aplicação

### Módulo Simétrico (DES)

1. Acesse **Módulo Simétrico (DES)** no menu.
2. Informe uma chave secreta (texto livre) e selecione um arquivo
   binário (imagem `.jpg`/`.png`, `.pdf`, ou qualquer outro).
3. Clique em **"Cifrar e baixar (.des)"** — o navegador baixa o arquivo
   cifrado (`nome_original.des`). Repare que ele não abre mais como
   imagem/PDF.
4. No formulário de decifrar, envie esse mesmo arquivo `.des` com a
   **mesma chave** usada na cifragem.
5. O arquivo original é reconstruído byte a byte e deve abrir
   perfeitamente no seu formato original.

### Módulo Assimétrico (RSA)

1. Acesse **Módulo Assimétrico (RSA)** no menu.
2. Escolha o tamanho da chave (em bits) e clique em **"Gerar chaves"** —
   a aplicação mostra `p`, `q`, `n`, `φ(n)` e as chaves pública/privada.
3. Digite uma mensagem de texto e clique em **"Cifrar"** — os campos `e`
   e `n` já vêm preenchidos automaticamente com a chave gerada.
4. O resultado cifrado (uma lista de números) é copiado automaticamente
   para o formulário de decifrar. Clique em **"Decifrar"** para
   recuperar a mensagem original usando a chave privada `(d, n)`.

---

## Limitações conhecidas e decisões de projeto

- **DES foi escolhido** entre as opções da atividade (AES, DES, 3DES) por
  ser mais viável de implementar manualmente do zero, mantendo a
  fidelidade ao algoritmo original (todas as tabelas e a rede de Feistel
  seguem a especificação FIPS 46-3). É importante frisar que o **DES é
  considerado inseguro para uso real** hoje em dia (chave efetiva de
  apenas 56 bits, quebrável por força bruta) — seu uso aqui é
  exclusivamente didático.
- A chave do DES informada pelo usuário é normalizada para 8 bytes
  (truncada ou preenchida com zeros), já que o DES exige exatamente 64
  bits de chave.
- No módulo RSA, o tamanho de chave disponível na interface (128–512
  bits) é reduzido em relação ao padrão de mercado (2048+ bits) para que
  a geração de primos e a demonstração no vídeo ocorram em tempo hábil
  em uma aplicação Web pura Python, sem otimizações de baixo nível. O
  algoritmo em si (Miller-Rabin, Euclides Estendido, exponenciação
  modular) é o mesmo utilizado em implementações de produção.
- Toda a criptografia roda no **servidor** (Flask); o front-end (HTML/
  CSS/JS) apenas envia os dados via `fetch`/`FormData` e exibe os
  resultados — nenhuma biblioteca de criptografia de terceiros é
  utilizada em nenhuma camada da aplicação.
