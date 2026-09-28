#!/usr/bin/env python3
"""
Constrói (ou reconstrói) a base de conhecimento vetorial usada para enriquecer
a justificativa do agente com contexto técnico (MITRE ATT&CK / CWE).

Roda UMA VEZ (ou sempre que o conteúdo dos documentos mudar). O resultado fica
persistido em disco, em ./chroma_cybersec, e é reaberto pelos scripts do
agente (agente.py / agente_API.py) sem precisar recalcular embeddings a cada
execução da bateria de testes.

Pré-requisitos:
    pip install chromadb --break-system-packages   # (ou dentro da venv)
    ollama pull nomic-embed-text                    # modelo de embedding local

Uso:
    python3 construir_base_conhecimento.py
"""

import json
import urllib.request
from pathlib import Path

import chromadb

OLLAMA_BASE_URL = "http://localhost:11434/v1"
MODELO_EMBEDDING = "nomic-embed-text"
PERSIST_DIR = "./chroma_cybersec"
COLECAO = "mitre_attack_cybersec"


def obter_embedding(texto: str) -> list[float]:
    """Pede um embedding ao Ollama local (endpoint compatível com OpenAI)."""
    payload = json.dumps({"model": MODELO_EMBEDDING, "input": texto}).encode("utf-8")
    request = urllib.request.Request(
        f"{OLLAMA_BASE_URL}/embeddings",
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        dados = json.load(response)
    return dados["data"][0]["embedding"]


# Base de conhecimento curada, cobrindo os indicadores usados nos 10 casos de
# teste do agente (arquivos críticos, portas de backdoor, brute-force, port
# scan, flood, instaladores maliciosos), mapeados a técnicas MITRE ATT&CK ou
# categorias CWE. Cada entrada é um trecho curto e autocontido — bom o
# suficiente para uma busca por similaridade, sem precisar de chunking.
DOCUMENTOS = [
    {
        "id": "t1053.003",
        "texto": (
            "T1053.003 — Scheduled Task/Job: Cron. Adversários adicionam ou "
            "modificam entradas em /etc/crontab ou /etc/cron.d para garantir "
            "persistência, executando comandos periodicamente (ex.: baixar e "
            "rodar um payload via curl). Uma linha de cron chamando um script "
            "remoto é um indicador forte de comprometimento e persistência ativa."
        ),
    },
    {
        "id": "t1543-trojanizacao",
        "texto": (
            "T1543 — Create or Modify System Process / trojanização de binário. "
            "Substituir um binário do sistema (como /bin/bash ou /bin/ls) por "
            "uma versão adulterada é uma técnica clássica de rootkit para obter "
            "execução de código persistente e evadir detecção; o hash diverge "
            "do de uma instalação limpa."
        ),
    },
    {
        "id": "t1003-credenciais",
        "texto": (
            "T1003 — OS Credential Dumping. Alteração no arquivo /etc/shadow "
            "(hashes de senha) indica tentativa de acesso ou manipulação de "
            "credenciais privilegiadas, geralmente para criar acesso persistente "
            "ou exfiltrar credenciais de outros usuários do sistema."
        ),
    },
    {
        "id": "t1071.001-c2",
        "texto": (
            "T1071 — Application Layer Protocol / C2 sobre HTTP. Um instalador "
            "ou script que baixa um binário adicional de um servidor externo "
            "(ex.: curl http://IP/malware.bin) e o executa é um padrão típico "
            "de dropper: o primeiro estágio de um comprometimento que busca o "
            "payload real remotamente antes de executá-lo."
        ),
    },
    {
        "id": "t1571-metasploit",
        "texto": (
            "T1571 — Non-Standard Port / Metasploit default shell. A porta 4444 "
            "é o listener padrão de payloads reverse shell do Metasploit "
            "Framework; encontrá-la aberta é evidência direta e praticamente "
            "inequívoca de um backdoor ativo, independentemente de outros "
            "indicadores presentes no sistema."
        ),
    },
    {
        "id": "t1219-backorifice",
        "texto": (
            "T1219 — Remote Access Software / Back Orifice. A porta 31337 é "
            "historicamente associada a ferramentas de backdoor como Back "
            "Orifice e variantes; assim como a 4444, sua presença sozinha já "
            "caracteriza comprometimento, não apenas risco potencial."
        ),
    },
    {
        "id": "t1110-bruteforce",
        "texto": (
            "T1110 — Brute Force. Um volume alto de requisições contra uma "
            "porta de autenticação (SSH/22, RDP/3389, VNC/5900) em uma janela "
            "curta de tempo (dezenas a centenas de tentativas em 60s) é a "
            "assinatura de um ataque de força bruta contra credenciais."
        ),
    },
    {
        "id": "t1595.001-portscan",
        "texto": (
            "T1595.001 — Active Scanning: Scanning IP Blocks / Port Scan. Um "
            "único IP de origem tentando conexão em muitas portas distintas em "
            "sequência é reconhecimento ativo de rede (varredura de portas), "
            "geralmente a fase que precede a exploração de um serviço vulnerável."
        ),
    },
    {
        "id": "t1498-dos",
        "texto": (
            "T1498/T1499 — Network Denial of Service. Um volume total muito "
            "alto de requisições de um único IP em curto intervalo (centenas "
            "por minuto) caracteriza tentativa de flood/DDoS, sobrecarregando "
            "o serviço alvo ou mascarando outra atividade maliciosa simultânea."
        ),
    },
    {
        "id": "cwe-284-db-exposta",
        "texto": (
            "CWE-284 — Improper Access Control. Bancos de dados NoSQL/SQL "
            "expostos diretamente à rede sem indicação de autenticação "
            "obrigatória (MySQL/3306, Redis/6379, MongoDB/27017, "
            "PostgreSQL/5432) são um vetor comum de vazamento de dados e "
            "ransomware, mesmo sem evidência de exploração ativa — por isso "
            "entram como risco (ALERTA), não confirmação de comprometimento."
        ),
    },
    {
        "id": "t1021-rdp",
        "texto": (
            "T1021.001 — Remote Services: Remote Desktop Protocol. A porta "
            "3389 (RDP) exposta é um alvo frequente de força bruta e "
            "exploração remota em ambientes Windows; sua presença sozinha é "
            "risco (ALERTA), mas se combinada com muitas tentativas de acesso "
            "na mesma porta, evolui para indicador de ataque ativo."
        ),
    },
]


def main() -> None:
    print(f"Conectando ao Chroma em {PERSIST_DIR} ...")
    cliente = chromadb.PersistentClient(path=PERSIST_DIR)

    # Recria a coleção do zero a cada execução deste script, para o conteúdo
    # nunca ficar dessincronizado da lista DOCUMENTOS acima.
    try:
        cliente.delete_collection(COLECAO)
    except Exception:
        pass
    colecao = cliente.create_collection(COLECAO)

    print(f"Gerando embeddings via Ollama ({MODELO_EMBEDDING}) para {len(DOCUMENTOS)} documentos...")
    embeddings = [obter_embedding(doc["texto"]) for doc in DOCUMENTOS]

    colecao.add(
        ids=[doc["id"] for doc in DOCUMENTOS],
        documents=[doc["texto"] for doc in DOCUMENTOS],
        embeddings=embeddings,
    )

    print(f"✅ Base de conhecimento construída: {colecao.count()} documentos em '{COLECAO}'.")
    print(f"   Persistida em: {Path(PERSIST_DIR).resolve()}")


if __name__ == "__main__":
    main()
