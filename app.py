# -*- coding: utf-8 -*-
"""
Aplicação Web (Flask) - Implementação de Algoritmos Criptográficos

Integra dois módulos:
  - /simetrico   -> Cifra de bloco DES (modo CBC + padding PKCS#7),
                     com suporte a upload/download de arquivos binários.
  - /assimetrico -> Protocolo RSA completo (geração de chaves,
                     cifragem e decifragem de mensagens de texto).

A criptografia em si (crypto/des.py e crypto/rsa_manual.py) é
implementada inteiramente do zero, sem bibliotecas prontas de
criptografia. O Flask é usado apenas como framework Web (rotas,
templates, upload de arquivos) - ele não participa dos cálculos
criptográficos.
"""

import io
import base64

from flask import Flask, render_template, request, send_file, jsonify

from crypto import des
from crypto import rsa_manual as rsa

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # limite de 32 MB por upload


# =========================================================================
# ROTAS DE PÁGINAS (menu principal e telas dos módulos)
# =========================================================================

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/simetrico")
def simetrico():
    return render_template("simetrico.html")


@app.route("/assimetrico")
def assimetrico():
    return render_template("assimetrico.html")


# =========================================================================
# MÓDULO SIMÉTRICO (DES) - cifrar/decifrar arquivos binários
# =========================================================================

def _key_from_form() -> bytes:
    key_text = request.form.get("chave", "")
    if not key_text:
        raise ValueError("Informe uma chave.")
    return key_text.encode("utf-8")


@app.route("/simetrico/cifrar", methods=["POST"])
def simetrico_cifrar():
    try:
        arquivo = request.files.get("arquivo")
        if not arquivo or arquivo.filename == "":
            return jsonify({"erro": "Nenhum arquivo selecionado."}), 400

        key = _key_from_form()
        dados = arquivo.read()

        cifrado = des.encrypt_cbc(dados, key)

        nome_saida = arquivo.filename + ".des"
        return send_file(
            io.BytesIO(cifrado),
            as_attachment=True,
            download_name=nome_saida,
            mimetype="application/octet-stream",
        )
    except Exception as exc:
        return jsonify({"erro": str(exc)}), 400


@app.route("/simetrico/decifrar", methods=["POST"])
def simetrico_decifrar():
    try:
        arquivo = request.files.get("arquivo")
        if not arquivo or arquivo.filename == "":
            return jsonify({"erro": "Nenhum arquivo selecionado."}), 400

        key = _key_from_form()
        dados = arquivo.read()

        decifrado = des.decrypt_cbc(dados, key)

        nome_saida = arquivo.filename
        if nome_saida.endswith(".des"):
            nome_saida = nome_saida[:-4]
        else:
            nome_saida = "decifrado_" + nome_saida

        return send_file(
            io.BytesIO(decifrado),
            as_attachment=True,
            download_name=nome_saida,
            mimetype="application/octet-stream",
        )
    except Exception as exc:
        return jsonify({"erro": f"Falha ao decifrar: {exc}"}), 400


# =========================================================================
# MÓDULO ASSIMÉTRICO (RSA) - geração de chaves, cifrar/decifrar texto
# =========================================================================

@app.route("/assimetrico/gerar-chaves", methods=["POST"])
def assimetrico_gerar_chaves():
    try:
        bits = int(request.form.get("bits", 256))
        bits = max(64, min(bits, 1024))  # limite de segurança para a demo web

        chaves = rsa.generate_keypair(bits=bits)
        return jsonify({
            "p": str(chaves["p"]),
            "q": str(chaves["q"]),
            "n": str(chaves["n"]),
            "phi": str(chaves["phi"]),
            "e": str(chaves["e"]),
            "d": str(chaves["d"]),
        })
    except Exception as exc:
        return jsonify({"erro": str(exc)}), 400


@app.route("/assimetrico/cifrar", methods=["POST"])
def assimetrico_cifrar():
    try:
        mensagem = request.form.get("mensagem", "")
        e = int(request.form.get("e"))
        n = int(request.form.get("n"))

        if not mensagem:
            return jsonify({"erro": "Informe uma mensagem."}), 400

        blocos = rsa.rsa_encrypt(mensagem, (e, n))
        return jsonify({"cifrado": [str(b) for b in blocos]})
    except Exception as exc:
        return jsonify({"erro": str(exc)}), 400


@app.route("/assimetrico/decifrar", methods=["POST"])
def assimetrico_decifrar():
    try:
        cifrado_texto = request.form.get("cifrado", "")
        d = int(request.form.get("d"))
        n = int(request.form.get("n"))

        if not cifrado_texto:
            return jsonify({"erro": "Informe o texto cifrado."}), 400

        blocos = [int(x.strip()) for x in cifrado_texto.split(",") if x.strip()]
        mensagem = rsa.rsa_decrypt(blocos, (d, n))
        return jsonify({"decifrado": mensagem})
    except Exception as exc:
        return jsonify({"erro": f"Falha ao decifrar: {exc}"}), 400


if __name__ == "__main__":
    app.run(debug=True)
