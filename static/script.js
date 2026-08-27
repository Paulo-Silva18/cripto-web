// Front-end simples: apenas orquestra chamadas para o back-end Flask.
// Toda a criptografia acontece no servidor (crypto/des.py e crypto/rsa_manual.py).

function setStatus(el, msg, type) {
    el.textContent = msg;
    el.className = "status" + (type ? " " + type : "");
}

// ---------------------------------------------------------------------
// MÓDULO SIMÉTRICO (DES)
// ---------------------------------------------------------------------

async function downloadFromResponse(response, fallbackName) {
    const blob = await response.blob();
    const disposition = response.headers.get("Content-Disposition") || "";
    const match = disposition.match(/filename="?([^"]+)"?/);
    const filename = match ? match[1] : fallbackName;

    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
}

const formCifrar = document.getElementById("form-cifrar");
if (formCifrar) {
    formCifrar.addEventListener("submit", async (ev) => {
        ev.preventDefault();
        const statusEl = document.getElementById("status-cifrar");
        setStatus(statusEl, "Cifrando...", "");
        try {
            const resp = await fetch("/simetrico/cifrar", {
                method: "POST",
                body: new FormData(formCifrar),
            });
            if (!resp.ok) {
                const err = await resp.json();
                throw new Error(err.erro || "Erro ao cifrar.");
            }
            await downloadFromResponse(resp, "arquivo.des");
            setStatus(statusEl, "Arquivo cifrado com sucesso! Download iniciado.", "success");
        } catch (e) {
            setStatus(statusEl, e.message, "error");
        }
    });
}

const formDecifrar = document.getElementById("form-decifrar");
if (formDecifrar) {
    formDecifrar.addEventListener("submit", async (ev) => {
        ev.preventDefault();
        const statusEl = document.getElementById("status-decifrar");
        setStatus(statusEl, "Decifrando...", "");
        try {
            const resp = await fetch("/simetrico/decifrar", {
                method: "POST",
                body: new FormData(formDecifrar),
            });
            if (!resp.ok) {
                const err = await resp.json();
                throw new Error(err.erro || "Erro ao decifrar.");
            }
            await downloadFromResponse(resp, "arquivo_decifrado");
            setStatus(statusEl, "Arquivo decifrado com sucesso! Download iniciado.", "success");
        } catch (e) {
            setStatus(statusEl, e.message, "error");
        }
    });
}

// ---------------------------------------------------------------------
// MÓDULO ASSIMÉTRICO (RSA)
// ---------------------------------------------------------------------

const formGerarChaves = document.getElementById("form-gerar-chaves");
if (formGerarChaves) {
    formGerarChaves.addEventListener("submit", async (ev) => {
        ev.preventDefault();
        const statusEl = document.getElementById("status-gerar");
        setStatus(statusEl, "Gerando primos e calculando chaves (pode levar alguns segundos)...", "");
        try {
            const resp = await fetch("/assimetrico/gerar-chaves", {
                method: "POST",
                body: new FormData(formGerarChaves),
            });
            const data = await resp.json();
            if (!resp.ok) throw new Error(data.erro || "Erro ao gerar chaves.");

            document.getElementById("out-p").textContent = data.p;
            document.getElementById("out-q").textContent = data.q;
            document.getElementById("out-n").textContent = data.n;
            document.getElementById("out-phi").textContent = data.phi;
            document.getElementById("out-e").textContent = data.e;
            document.getElementById("out-n2").textContent = data.n;
            document.getElementById("out-d").textContent = data.d;
            document.getElementById("out-n3").textContent = data.n;
            document.getElementById("resultado-chaves").hidden = false;

            // Preenche automaticamente os campos de cifrar/decifrar
            document.getElementById("input-e").value = data.e;
            document.getElementById("input-n").value = data.n;
            document.getElementById("input-d").value = data.d;
            document.getElementById("input-n2").value = data.n;

            setStatus(statusEl, "Par de chaves gerado com sucesso!", "success");
        } catch (e) {
            setStatus(statusEl, e.message, "error");
        }
    });
}

const formCifrarRsa = document.getElementById("form-cifrar-rsa");
if (formCifrarRsa) {
    formCifrarRsa.addEventListener("submit", async (ev) => {
        ev.preventDefault();
        const statusEl = document.getElementById("status-cifrar-rsa");
        setStatus(statusEl, "Cifrando...", "");
        try {
            const resp = await fetch("/assimetrico/cifrar", {
                method: "POST",
                body: new FormData(formCifrarRsa),
            });
            const data = await resp.json();
            if (!resp.ok) throw new Error(data.erro || "Erro ao cifrar.");

            document.getElementById("out-cifrado").value = data.cifrado.join(", ");
            // já deixa pronto para colar no formulário de decifrar
            document.getElementById("input-cifrado").value = data.cifrado.join(", ");
            setStatus(statusEl, "Mensagem cifrada com sucesso!", "success");
        } catch (e) {
            setStatus(statusEl, e.message, "error");
        }
    });
}

const formDecifrarRsa = document.getElementById("form-decifrar-rsa");
if (formDecifrarRsa) {
    formDecifrarRsa.addEventListener("submit", async (ev) => {
        ev.preventDefault();
        const statusEl = document.getElementById("status-decifrar-rsa");
        setStatus(statusEl, "Decifrando...", "");
        try {
            const resp = await fetch("/assimetrico/decifrar", {
                method: "POST",
                body: new FormData(formDecifrarRsa),
            });
            const data = await resp.json();
            if (!resp.ok) throw new Error(data.erro || "Erro ao decifrar.");

            document.getElementById("out-decifrado").value = data.decifrado;
            setStatus(statusEl, "Mensagem decifrada com sucesso!", "success");
        } catch (e) {
            setStatus(statusEl, e.message, "error");
        }
    });
}
