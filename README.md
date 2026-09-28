# Agente de Cibersegurança para Tarefas Verificáveis

Trabalho da disciplina **Tópicos Especiais em Inteligência Computacional A —
IA Agêntica 2026.2**, Avaliação da Unidade I. Implementa, com o `agentkit`
(sem LangChain/LangGraph/outros frameworks de agentes, conforme exigido pelo
enunciado), um agente que investiga se um sistema Linux simulado está
comprometido, cruzando integridade de arquivos, logs de rede e portas abertas.

Participantes: [Nome 1] e [Nome 2].

---

## Sumário

1. [O que o agente faz](#o-que-o-agente-faz)
2. [Por que a tarefa é verificável](#por-que-a-tarefa-é-verificável)
3. [Estrutura do repositório](#estrutura-do-repositório)
4. [Requisitos da avaliação → onde são atendidos](#requisitos-da-avaliação--onde-são-atendidos)
5. [Como rodar — versão local (Ollama)](#como-rodar--versão-local-ollama)
6. [Como rodar — versão API (Groq)](#como-rodar--versão-api-groq)
7. [Extensão RAG (base de conhecimento)](#extensão-rag-base-de-conhecimento)
8. [Casos de teste](#casos-de-teste)
9. [Histórico de correções aplicadas](#histórico-de-correções-aplicadas)
10. [Limitações conhecidas e próximos passos](#limitações-conhecidas-e-próximos-passos)

---

## O que o agente faz

Recebe uma tarefa em linguagem natural descrevendo um cenário de investigação
(arquivos a verificar, logs de rede coletados, portas abertas no host) e
decide sozinho — sem ordem fixa programada — quais das ferramentas
disponíveis usar, em que sequência, e quando já tem evidência suficiente para
emitir um veredicto final:

```json
{"status": "SISTEMA SEGURO" | "ALERTA" | "COMPROMETIDO",
 "confianca": 0-100,
 "justificativa": "texto explicativo"}
```

## Por que a tarefa é verificável

Cada um dos 10 casos de teste tem um **gabarito objetivo**: os dados de
entrada (hashes, logs, portas) são construídos deliberadamente para produzir
uma resposta única e sem ambiguidade, derivada diretamente dos critérios de
veredicto escritos no prompt de sistema. O script compara
`status_obtido == caso["esperado"]` e produz um booleano de aprovado/reprovado
— não há espaço para julgamento subjetivo na correção.

## Estrutura do repositório

```
agente.py                      # Versão local — Ollama (qwen2.5:3b)
agente_API.py                  # Versão API — Groq (openai/gpt-oss-20b)
construir_base_conhecimento.py # Constrói a base vetorial usada pelo RAG
requirements.txt                # Dependências (venv)
.env                             # OPENAI_API_KEY da Groq (não versionar)
chroma_cybersec/                # Gerado por construir_base_conhecimento.py
```

As duas versões do agente compartilham exatamente as mesmas três ferramentas
de investigação, o mesmo dicionário de estado, o mesmo prompt de sistema e o
mesmo schema `Veredicto` — só a configuração do modelo (`LLMAPI`) e a
robustez em torno das chamadas mudam (retry de rate-limit só existe na versão
API, por exemplo).

## Requisitos da avaliação → onde são atendidos

| Requisito | Onde | Como |
|---|---|---|
| ≥ 3 ferramentas com `@tool` | `verificar_integridade_arquivo`, `analisar_logs_rede`, `verificar_portas_abertas` | Três funções decoradas com `@tool`, com docstring e tipos anotados que o agentkit introspecta para gerar o schema exposto ao modelo. |
| Tarefa em múltiplas etapas | `CASOS_DE_TESTE` (casos 5–10) | Casos intermediários exigem 2 ferramentas encadeadas; complexos/desafiadores exigem as 3 na mesma investigação. |
| Decisão dinâmica de ferramentas/ordem/parada | `Agent(llm, FERRAMENTAS, max_steps=12)` | O laço do `Agent` não tem ordem fixa: a cada passo o modelo decide qual ferramenta chamar (ou nenhuma); `max_steps` é só um teto de segurança. |
| Prompt e contexto próprios | `SYSTEM_BASE` + `montar_system()` | Papel, regras de investigação, formato exato de chamada das ferramentas e critérios de veredicto específicos da tarefa. |
| Mecanismo 1 — Memória/Estado | `novo_estado()`, `atualizar_estado()`, `estado_para_texto()` | Dicionário que acumula evidências a cada observação de ferramenta e é reinjetado no prompt de sistema na chamada seguinte. |
| Mecanismo 2 — Planejamento/Reflexão | Regras 1–5 de `SYSTEM_BASE` + estado injetado | O modelo vê o que já apurou e decide se falta evidência antes de fechar o veredicto. |
| (extra) Saída estruturada | Classe Pydantic `Veredicto` | `Literal` fecha o conjunto de status possíveis; validação além do texto do prompt. |
| Chave de API fora do notebook/script | `os.getenv("OPENAI_API_KEY")` + `.env` (`agente_API.py`) | Nunca aparece hardcoded no código-fonte. |
| 10 casos de teste, ≥ 3 desafiadores | `CASOS_DE_TESTE` | Casos 9 e 10 marcados `[DESAFIADOR]`. |
| Relatório: entrada/esperado/obtido/status | Loop de execução dos testes | Cada iteração imprime tudo e acumula em `resultados` para a tabela final. |
| Taxa de acerto + análise de erros | Seção final de cada script | `acertos/total`, taxa por dificuldade, listagem dos reprovados. |
| Execução do início ao fim sem intervenção | Scripts inteiros | Sem `input()`; erros de ferramenta e rate limit são absorvidos, não travam o processo. |

## Como rodar — versão local (Ollama)

```bash
# 1. Suba o Ollama e baixe os modelos usados
ollama pull qwen2.5:3b
ollama pull nomic-embed-text     # só necessário para o RAG (opcional)

# 2. Ambiente Python
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt --break-system-packages

# 3. (Opcional) construa a base de conhecimento do RAG uma vez
python3 construir_base_conhecimento.py

# 4. Rode a bateria de testes
python3 agente.py
```

A primeira chamada ao modelo pode levar 30–60s (carregamento na RAM). O
timeout HTTP interno já está ajustado para 300s (ver [histórico de
correções](#histórico-de-correções-aplicadas)).

## Como rodar — versão API (Groq)

```bash
# 1. Crie o .env na raiz do projeto (NUNCA versionar este arquivo)
echo "OPENAI_API_KEY=sua_chave_da_groq_aqui" > .env

# 2. Mesmo ambiente Python da versão local
source venv/bin/activate
pip install -r requirements.txt --break-system-packages

# 3. Rode a bateria de testes
python3 agente_API.py
```

Se aparecer `429 Too Many Requests`, o script já reage sozinho lendo o tempo
de espera sugerido pela própria Groq (`com_retry`); em tiers muito
restritivos, aumente `PAUSA_ENTRE_CASOS_SEGUNDOS` no topo da Seção 9.

## Extensão RAG (base de conhecimento)

Além dos requisitos obrigatórios, a justificativa do veredicto é enriquecida
com uma referência técnica (MITRE ATT&CK / CWE), buscada por similaridade
numa base vetorial local:

- **Banco vetorial:** [Chroma](https://www.trychroma.com/), persistido em
  `./chroma_cybersec/` — escolhido por ser o mesmo usado no notebook de RAG
  da disciplina (`11 - RAG.ipynb`), reduzindo risco de incompatibilidade com
  ARM em relação a alternativas como LanceDB.
- **Embeddings:** sempre via **Ollama local** (`nomic-embed-text`), mesmo na
  versão que usa a Groq para o raciocínio — é rápido, grátis e evita
  depender de mais uma API externa só para isso.
- **Conteúdo:** ~11 documentos curados cobrindo os indicadores usados nos 10
  casos de teste (persistência via cron, trojanização de binário,
  manipulação de credenciais, backdoors conhecidos em portas 4444/31337,
  brute-force, port scan, flood/DDoS, bancos de dados expostos). Ver
  `construir_base_conhecimento.py`.

**Decisão de projeto importante:** a consulta à base **não** é exposta como
uma 4ª `@tool` para o `Agent` decidir sozinho quando chamar. Ela é feita em
Python, de forma determinística, **depois** que o veredicto já foi decidido
pelas três ferramentas de investigação (função `enriquecer_justificativa_com_rag`,
chamada dentro de `investigar()`). O motivo: o modelo local de 3B já se
mostrou instável na escolha/formatação de chamadas de ferramenta (ver
histórico abaixo); acrescentar uma 4ª ferramenta ao laço do `Agent`
arriscaria regredir os 10 casos de teste que já funcionam. Enriquecer a
justificativa em Python depois do veredicto continua sendo RAG de verdade —
embedding da consulta + busca vetorial por similaridade — só que sem colocar
mais uma decisão na mão de um modelo pouco confiável.

Se quiser transformar isso numa ferramenta agêntica de verdade (o modelo
decide quando consultar a base), o caminho é decorar uma função equivalente
com `@tool`, adicioná-la a `FERRAMENTAS_INVESTIGACAO`/`FERRAMENTAS` e mencioná-la
como **opcional** no `SYSTEM_BASE` — mas reteste os 10 casos depois, porque
isso muda a distribuição de decisões do modelo.

A base é opcional: se `construir_base_conhecimento.py` não tiver sido rodado
(ou o Ollama estiver fora do ar), o agente detecta isso na inicialização,
avisa no console e segue funcionando normalmente — só sem o `[Ref. técnica:
...]` no fim da justificativa.

## Casos de teste

| # | Dificuldade | Cenário | Esperado |
|---|---|---|---|
| 1 | simples | `/bin/bash` com hash trojanizado | COMPROMETIDO |
| 2 | simples | `/etc/hosts` íntegro | SISTEMA SEGURO |
| 3 | simples | porta 4444 (backdoor Metasploit) aberta | COMPROMETIDO |
| 4 | simples | 847 req/60s na porta 22 (brute-force) | ALERTA |
| 5 | intermediário | crontab adulterado + port scan (6 portas) | COMPROMETIDO |
| 6 | intermediário | portas de risco abertas + arquivo íntegro | ALERTA |
| 7 | complexo | 3 arquivos verificados, 2 comprometidos | COMPROMETIDO |
| 8 | complexo | sistema limpo, mas com porta 8080 exposta | ALERTA |
| 9 | **desafiador** | installer.sh malicioso + logs ambíguos (porta 31337 + brute-force simultâneos) | COMPROMETIDO |
| 10 | **desafiador** | mix de arquivos íntegros/comprometidos + flood + backdoor 4444 | COMPROMETIDO |

## Histórico de correções aplicadas

Resumo cronológico dos problemas reais encontrados ao rodar no Orange Pi 4
Pro e na API da Groq, e a correção aplicada em cada um:

1. **`TypeError: unexpected keyword argument 'timeout'`** — o construtor do
   `LLMAPI` desta versão do `agentkit` não aceita `timeout`. Corrigido com um
   monkeypatch de `agentkit.model.post` (a função que faz a chamada HTTP),
   substituindo-a por uma cópia idêntica com `timeout=300`, sem tocar em
   nenhum arquivo da biblioteca instalada.
2. **`AttributeError: 'str' object has no attribute 'get'`** em
   `analisar_logs_rede` — o modelo às vezes embrulha a lista em
   `{"logs": [...]}` em vez de mandar a lista pura. A ferramenta agora
   desembrulha automaticamente, e o prompt ganhou um bloco com o formato
   exato de cada chamada + instrução para corrigir sem explicar o erro em
   texto (evitava respostas cortadas por estourar `max_tokens`).
3. **`429 Too Many Requests` em cascata (versão API)** — sem retry, o script
   original derrubava todos os casos seguintes ao primeiro rate limit.
   Corrigido com `com_retry`/`extrair_espera` (lê o tempo sugerido pela
   própria mensagem de erro da Groq) e reduzindo o número de chamadas por
   caso (parse direto do JSON antes de recorrer a `generate_structured`).
4. **Veredicto errado para porta 4444** (ALERTA em vez de COMPROMETIDO) — o
   modelo local de 3B não aplicava bem o critério escrito em prosa.
   `verificar_portas_abertas` agora sinaliza explicitamente na própria saída:
   *"CRÍTICO: porta 4444 presente — isto por si só já classifica o veredicto
   como COMPROMETIDO"*.
5. **Resposta final vazia (sem texto, sem `tool_calls`)**, causando
   `ERRO_PARSE` mesmo com evidências já coletadas — comportamento observado
   em modelos locais pequenos "engasgando" no fechamento do turno. Corrigido
   com `finalizar_se_vazio`: detecta o caso e faz um pedido explícito de
   fechamento reusando o contexto já acumulado.
6. **Fase 2 (relatório executivo) reenviando o mesmo JSON duas vezes** — a
   versão original colava o JSON bruto dos 10 casos no prompt E pedia ao
   modelo que o reproduzisse como argumento de uma ferramenta, dobrando o
   tamanho do prompt e arriscando truncamento. Corrigido processando o
   resumo em Python puro (`analisar_bateria_testes` chamada diretamente,
   fora do laço do `Agent`) e usando o modelo só para redigir o texto final.

## Limitações conhecidas e próximos passos

- O modelo local de 3B ainda pode, ocasionalmente, produzir uma resposta
  final vazia mesmo após `finalizar_se_vazio` (é geração degenerada, não um
  bug de código); se isso persistir, a próxima linha de ataque seria detectar
  e repetir a chamada com uma leve variação de prompt.
- O RAG está limitado a ~11 documentos curados manualmente; para cobrir
  cenários fora dos 10 casos de teste, a base precisaria crescer (ex.:
  importar o catálogo completo do MITRE ATT&CK).
- LangChain/LangGraph **não** foram usados aqui, conforme vedado pelo
  enunciado da Unidade I — ficam reservados para a reimplementação da
  Unidade II do curso.
- Uma ferramenta externa real (ex.: Shodan) foi cogitada, mas não integrada
  à bateria de teste oficial: resultados de uma API externa mudam com o
  tempo, o que quebraria a verificabilidade exigida pela tarefa. Se
  adicionada, deve ficar como demonstração isolada, fora dos 10 casos
  avaliados.
