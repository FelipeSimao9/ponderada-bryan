# Proposta de Melhoria do Requisito Não Funcional de Segurança em um Sistema Conversacional

**Alternativa escolhida:** (Alternativa 2) Considerando aspectos de segurança, propor como melhorar este requisito não funcional no sistema conversacional.

**Autor:** Felipe Simão

---

## Sumário

1. [Introdução](#1-introdução)
2. [Solução Proposta](#2-solução-proposta)
3. [Conclusão](#3-conclusão)
4. [Referências Bibliográficas](#4-referências-bibliográficas)

---

## 1. Introdução

### 1.1 Contexto

Os chatbots e assistentes virtuais mudaram bastante nos últimos anos. Antes eram árvores de decisão com respostas prontas; hoje, a maioria é construída sobre Modelos de Linguagem de Grande Escala (*Large Language Models*, ou LLMs). Muitas vezes esses modelos ainda estão ligados a bases de conhecimento (RAG, de *Retrieval-Augmented Generation*), a APIs internas e a ferramentas que executam ações em nome do usuário. Isso torna o sistema muito mais útil, mas também abre muito mais portas para ataques. Em outras palavras, a **superfície de ataque** cresce junto com as capacidades.

Na engenharia de software, segurança é um **requisito não funcional**. Ela não diz *o que* o sistema faz, e sim *com que qualidade* ele faz. A ISO/IEC 25010 define segurança como o grau em que um produto protege informações e dados, garantindo que pessoas ou outros sistemas acessem apenas o que o seu nível de autorização permite. A norma divide esse conceito em confidencialidade, integridade, não repúdio, responsabilização (*accountability*) e autenticidade (ISO/IEC, 2023). Sommerville (2018) lembra ainda que requisitos não funcionais costumam ser mais críticos que os funcionais, porque uma falha neles pode deixar o sistema inteiro inutilizável.

### 1.2 Descrição do problema

Num sistema conversacional, quase tudo o que entra é **texto livre**, escrito por um usuário em quem não necessariamente podemos confiar. Num formulário comum, cada campo tem um formato e pode ser validado. Aqui não existe isso: não há um esquema rígido que separe o que é "dado" do que é "instrução". É daí que surgem ameaças bem específicas, que o OWASP Top 10 para Aplicações com LLM (OWASP, 2025) organiza assim:

| Ameaça | Descrição | Impacto no sistema conversacional |
|---|---|---|
| **Injeção de prompt (direta)** | O próprio usuário escreve instruções tentando passar por cima das regras do sistema ("ignore as instruções anteriores…"). | O bot quebra suas políticas, vaza o *system prompt* ou dá respostas que não deveria (PEREZ; RIBEIRO, 2022). |
| **Injeção de prompt (indireta)** | As instruções maliciosas vêm escondidas em documentos, páginas web ou e-mails que o bot lê pelo RAG ou por ferramentas. | O bot executa ações que o usuário nunca pediu (GRESHAKE *et al.*, 2023). |
| **Divulgação de informação sensível** | O modelo revela dados pessoais, segredos ou informações de outros usuários que estavam no contexto ou no treinamento. | Violação da LGPD e da confidencialidade (CARLINI *et al.*, 2021). |
| **Agência excessiva** | O bot tem mais permissões do que precisa em ferramentas e APIs. | Basta uma injeção bem-sucedida para causar um estrago grande. |
| **Tratamento inseguro da saída** | A resposta do modelo é exibida ou executada sem validação (HTML, SQL, comandos). | XSS, injeção de SQL e execução remota de código. |
| **Consumo ilimitado** | Excesso de requisições ou prompts enormes. | Negação de serviço e custos fora de controle. |

### 1.3 Justificativa

Vejo quatro motivos principais para investir nesse requisito:

1. **É uma obrigação legal.** O art. 46 da Lei Geral de Proteção de Dados (BRASIL, 2018) exige que quem trata dados pessoais adote medidas técnicas e administrativas para protegê-los. E as conversas com chatbots costumam estar cheias desses dados: nome, CPF, endereço, informações de saúde e financeiras.
2. **O LLM é probabilístico.** Não dá para garantir que um modelo nunca vai obedecer a uma instrução maliciosa. Por isso, a segurança não pode depender só dele. Ela precisa vir de **camadas determinísticas ao redor do modelo**, que é a ideia por trás da *defesa em profundidade*.
3. **A confiança do usuário está em jogo.** Vazamentos de dados e respostas nocivas afetam diretamente a confiança das pessoas e, consequentemente, a adoção do sistema (WEIDINGER *et al.*, 2021).
4. **Existem frameworks reconhecidos que pedem isso.** O NIST AI Risk Management Framework (NIST, 2023) recomenda que os riscos de IA sejam governados, mapeados, medidos e gerenciados de forma contínua. Para isso, a arquitetura precisa gerar evidências, como logs, métricas e testes.

Com isso, a pergunta que este trabalho busca responder é: **como organizar a arquitetura de um sistema conversacional para que a segurança venha de mecanismos verificáveis, e não do comportamento do modelo de linguagem?**

---

## 2. Solução Proposta

### 2.1 Visão geral

A proposta é uma **arquitetura de defesa em profundidade baseada em Confiança Zero (*Zero Trust*)** (ROSE *et al.*, 2020). A ideia central é simples: nada é confiável por padrão. Isso vale para a mensagem do usuário, para um documento recuperado e até para a resposta do próprio LLM. O modelo é tratado como um componente **não confiável**, que fica isolado entre dois pontos de verificação (um na entrada e outro na saída). Além disso, qualquer ação que tenha efeito real passa por um mediador de ferramentas que trabalha com o mínimo de privilégios possível.

Os princípios que orientam a solução são:

- **Defesa em profundidade:** várias camadas independentes, de modo que, se uma falhar, as outras continuam protegendo o sistema.
- **Privilégio mínimo:** o bot só acessa os dados e as ferramentas de que realmente precisa para atender o usuário autenticado.
- **Separação entre dados e instruções:** todo conteúdo externo é marcado e tratado como dado, nunca como comando.
- **Humano no circuito (*human-in-the-loop*):** ações que não podem ser desfeitas precisam de confirmação explícita.
- **Observabilidade e melhoria contínua:** tudo é registrado, medido e testado com ataques simulados de forma recorrente.

### 2.2 Diagrama de arquitetura

```mermaid
flowchart TB
    U([Usuário]) -->|HTTPS / TLS 1.3| GW

    subgraph P1["Perímetro de Borda"]
        GW["1. API Gateway<br/>Autenticação · Rate limiting · WAF"]
    end

    subgraph P2["Camada de Proteção de Entrada"]
        SAN["2. Sanitizador e Mascarador de PII<br/>(normalização, anonimização LGPD)"]
        IG["3. Guardrail de Entrada<br/>(classificador de injeção / jailbreak)"]
    end

    subgraph P3["Núcleo Conversacional"]
        ORQ["4. Orquestrador de Diálogo<br/>(montagem de prompt com delimitação de contexto)"]
        LLM[["5. LLM<br/>(componente não confiável)"]]
        RAG["6. Recuperador Seguro (RAG)<br/>(filtro por permissão do usuário)"]
        KB[("Base de Conhecimento<br/>com ACL por documento")]
    end

    subgraph P4["Camada de Ações"]
        TM["7. Mediador de Ferramentas<br/>(allowlist · privilégio mínimo · confirmação humana)"]
        API[("APIs e Sistemas Internos")]
    end

    subgraph P5["Camada de Proteção de Saída"]
        OG["8. Guardrail de Saída<br/>(vazamento de PII/segredos, conteúdo nocivo, escape de HTML)"]
    end

    subgraph P6["Governança Transversal"]
        IAM["9. Gestão de Identidade e Segredos<br/>(IAM, cofre de chaves)"]
        AUD["10. Auditoria e Monitoramento<br/>(logs imutáveis, SIEM, alertas)"]
        RT["11. Red Teaming Contínuo<br/>(testes adversariais automatizados)"]
    end

    GW --> SAN --> IG
    IG -->|bloqueado| AUD
    IG -->|aprovado| ORQ
    ORQ <--> RAG
    RAG <--> KB
    ORQ <--> LLM
    LLM -->|chamada de ferramenta| TM
    TM -->|requer confirmação| U
    TM <--> API
    LLM --> OG
    OG -->|resposta segura| GW
    GW --> U

    IAM -.credenciais e escopos.-> GW
    IAM -.escopos.-> RAG
    IAM -.escopos.-> TM
    GW -.eventos.-> AUD
    IG -.eventos.-> AUD
    TM -.eventos.-> AUD
    OG -.eventos.-> AUD
    RT -.ataques simulados.-> GW
    AUD -.novos padrões de ataque.-> IG
    RT -.casos de falha.-> IG
```

### 2.3 Fluxo de uma mensagem

1. O usuário manda a mensagem pelo canal que preferir (web, app, WhatsApp), sempre com TLS.
2. O **API Gateway** confere quem é o usuário, aplica os limites de requisições e descarta o que chegar malformado.
3. O **Sanitizador** limpa o texto, removendo caracteres invisíveis e Unicode usado para disfarçar ataques, e mascara os dados pessoais que não são necessários para a tarefa.
4. O **Guardrail de Entrada** analisa a mensagem. Se perceber uma tentativa de injeção ou um conteúdo proibido, bloqueia e registra o ocorrido.
5. O **Orquestrador** monta o prompt deixando bem separadas, com delimitadores explícitos, as instruções do sistema, o histórico, os documentos recuperados (marcados como "dados não confiáveis") e a pergunta do usuário.
6. O **Recuperador Seguro** busca somente os documentos que aquele usuário tem permissão para ler.
7. O **LLM** gera a resposta ou pede para usar alguma ferramenta.
8. Quando há uma chamada de ferramenta, o **Mediador** confere os parâmetros com um esquema, verifica se o usuário tem permissão para aquilo e, se a ação for sensível (uma transferência, uma exclusão, um envio), pede confirmação explícita.
9. O **Guardrail de Saída** procura vazamento de dados, segredos e conteúdo nocivo, e trata a resposta antes de exibi-la.
10. Todos esses eventos vão para a **Auditoria**, que alimenta o ciclo de melhoria contínua.

### 2.4 Responsabilidades de cada módulo

| # | Módulo | Responsabilidades | Ameaças mitigadas | Tecnologias de referência |
|---|---|---|---|---|
| 1 | **API Gateway** | É a única porta de entrada. Faz a terminação TLS, a autenticação (OAuth 2.0 / OIDC) e o *rate limiting* por usuário e por IP, limita o tamanho das mensagens e usa um WAF contra ataques web clássicos. | Consumo ilimitado, DoS, acesso sem autenticação. | Kong, AWS API Gateway, Cloudflare. |
| 2 | **Sanitizador e Mascarador de PII** | Normaliza o Unicode e remove caracteres de controle ou invisíveis usados para esconder ataques. Também detecta e mascara dados pessoais (CPF, cartão, telefone) antes que cheguem ao LLM, seguindo o princípio da necessidade da LGPD. | Divulgação de informação sensível, injeções disfarçadas. | Microsoft Presidio, expressões regulares, NER. |
| 3 | **Guardrail de Entrada** | Usa um modelo especializado para classificar a intenção da mensagem (legítima, injeção, *jailbreak*, conteúdo proibido). Conforme o caso, bloqueia ou devolve uma resposta segura, e registra cada tentativa. | Injeção de prompt direta, *jailbreak*. | Llama Guard (INAN *et al.*, 2023), NeMo Guardrails, classificadores próprios. |
| 4 | **Orquestrador de Diálogo** | Cuida do estado da conversa e monta o prompt separando bem instruções e dados (*spotlighting* e delimitadores). Nunca coloca segredos no prompt, limita o tamanho do histórico e usa um *system prompt* versionado. | Injeção indireta, vazamento do *system prompt*. | LangChain, LangGraph, código próprio. |
| 5 | **LLM** | Gera a linguagem natural e decide quando chamar ferramentas. É tratado como **não confiável**: não tem credenciais, não acessa a rede diretamente e não guarda memória entre usuários diferentes. | Nenhuma diretamente; é o componente que as outras camadas protegem. | Modelo hospedado ou *self-hosted*. |
| 6 | **Recuperador Seguro (RAG)** | Busca os documentos relevantes respeitando o **controle de acesso de cada documento** conforme a identidade do usuário. Marca o conteúdo recuperado como dado externo e confere a origem dos documentos na ingestão, para evitar que a base seja envenenada. | Vazamento entre usuários, envenenamento de dados, injeção indireta. | Bancos vetoriais com filtro de metadados (pgvector, Weaviate). |
| 7 | **Mediador de Ferramentas** | Mostra ao LLM apenas uma *allowlist* de ferramentas e valida os argumentos com esquema (JSON Schema). Executa tudo com o token **do próprio usuário**, e não com um superusuário, pede confirmação humana para ações irreversíveis e roda código em *sandbox*. | Agência excessiva, escalonamento de privilégios. | Function calling com validação, OPA (*Open Policy Agent*). |
| 8 | **Guardrail de Saída** | Procura PII, segredos (chaves de API, tokens) e conteúdo nocivo na resposta. Faz o escape de HTML e Markdown antes de exibir, confere se o *system prompt* não vazou e aplica a política de recusa. | Tratamento inseguro da saída (XSS), divulgação de informação sensível. | Llama Guard, Presidio, detectores de segredos. |
| 9 | **Gestão de Identidade e Segredos** | Emite e valida identidades e define os escopos (RBAC/ABAC) que o RAG e o Mediador usam. Guarda as chaves de API num cofre com rotação automática e garante criptografia em repouso (AES-256). | Roubo de credenciais, acesso indevido. | Keycloak, HashiCorp Vault, AWS KMS. |
| 10 | **Auditoria e Monitoramento** | Registra de forma imutável as requisições, os bloqueios, as chamadas de ferramenta e as respostas (com PII mascarada). Dispara alertas para padrões estranhos, apoia a resposta a incidentes e a comunicação obrigatória à ANPD (art. 48 da LGPD), e aplica a política de retenção e eliminação de dados. | Não repúdio, responsabilização, detecção tardia. | ELK Stack, Grafana, SIEM. |
| 11 | **Red Teaming Contínuo** | Roda periodicamente, e sempre que o prompt ou o modelo mudam, uma bateria automatizada de ataques conhecidos. Mede quantos ataques passam e transforma cada falha em um novo caso de teste e em dado de treino para o Guardrail de Entrada. | Regressões de segurança, novas técnicas de ataque. | Garak, PyRIT, MITRE ATLAS como catálogo de técnicas. |

### 2.5 Métricas para verificar o requisito

Um requisito não funcional só é útil se puder ser **medido**; caso contrário, vira apenas uma boa intenção. Por isso, sugiro acompanhar os seguintes indicadores:

| Métrica | Meta sugerida |
|---|---|
| Taxa de sucesso de ataques na suíte de *red teaming* | < 2% |
| Taxa de falsos positivos do Guardrail de Entrada (mensagens legítimas bloqueadas) | < 1% |
| Ocorrências de PII não mascarada nos logs | 0 |
| Ações sensíveis executadas sem confirmação humana | 0 |
| Latência adicional causada pelas camadas de segurança (p95) | < 300 ms |
| Tempo médio para detecção de incidente (MTTD) | < 15 min |

---

## 3. Conclusão

O principal aprendizado deste trabalho é que, em sistemas conversacionais baseados em LLM, **não dá para deixar a segurança nas mãos do modelo**. Por melhor que seja o *system prompt*, o LLM continua sendo probabilístico e pode ser convencido a fazer o que não deveria. Por isso, a proposta transfere a responsabilidade pela segurança para camadas determinísticas e auditáveis ao redor dele: autenticação na borda, filtros na entrada e na saída, controle de acesso no RAG e, principalmente, um mediador de ferramentas que impede que uma injeção bem-sucedida vire um dano real. Na minha visão, o **Mediador de Ferramentas** e o **controle de acesso no RAG** são as peças que mais compensam, porque diminuem o impacto de qualquer falha nas outras camadas. Se um ataque consegue enganar o modelo, mas não consegue acessar nada além do que o próprio usuário já poderia, o estrago fica bem limitado.

Acredito que a proposta é viável, mas ela tem alguns custos que precisam ser levados em conta:

- **Latência e custo:** cada guardrail baseado em modelo acrescenta uma inferência. Uma saída é começar com filtros baratos (regras e expressões regulares) e só acionar os classificadores mais caros quando algo parecer suspeito.
- **Usabilidade:** filtros muito rígidos bloqueiam mensagens legítimas e frustram o usuário. É por isso que a taxa de falsos positivos importa tanto quanto a de ataques bloqueados.
- **Manutenção contínua:** as técnicas de ataque mudam rápido. Sem o ciclo de *red teaming* e sem o retorno da auditoria para os guardrails, a arquitetura fica desatualizada em poucos meses.

### 3.1 Estimativa de esforço

Pensando numa equipe de 3 a 4 pessoas (desenvolvimento *backend*, engenharia de ML e segurança), dá para implementar tudo aos poucos, começando pelas camadas de maior impacto:

| Fase | Entregas | Esforço estimado |
|---|---|---|
| **1. Fundação** | API Gateway com autenticação e *rate limiting*, cofre de segredos, TLS e logs estruturados. | 2 a 3 semanas |
| **2. Controle de acesso** | Mediador de Ferramentas com *allowlist*, validação de esquema e confirmação humana; RAG com filtro por permissão. | 3 a 4 semanas |
| **3. Guardrails** | Mascaramento de PII, Guardrails de Entrada e Saída e escape da saída. | 3 a 4 semanas |
| **4. Governança** | Painéis de monitoramento, alertas, suíte de *red teaming* automatizada no CI/CD e política de retenção LGPD. | 2 a 3 semanas |
| **Total** | | **≈ 10 a 14 semanas**, mais a manutenção contínua |

Boa parte dos componentes pode aproveitar ferramentas de código aberto que já são maduras (Presidio, Llama Guard, Keycloak, Vault, Garak). Isso reduz bastante o desenvolvimento e concentra o trabalho na **integração** e na **definição de políticas**. Na minha avaliação, é aí que está a parte mais difícil: decidir o que o bot pode ou não fazer depende de alinhar as áreas de negócio, jurídica e de segurança da organização, e isso vai muito além de escrever código.

---

## 4. Referências Bibliográficas

BRASIL. **Lei nº 13.709, de 14 de agosto de 2018**. Lei Geral de Proteção de Dados Pessoais (LGPD). Diário Oficial da União, Brasília, DF, 15 ago. 2018. Disponível em: https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm. Acesso em: 3 out. 2026.

CARLINI, N. *et al.* Extracting training data from large language models. *In*: USENIX SECURITY SYMPOSIUM, 30., 2021, [*S. l.*]. **Proceedings** [...]. [*S. l.*]: USENIX Association, 2021. p. 2633-2650.

GRESHAKE, K. *et al.* Not what you've signed up for: compromising real-world LLM-integrated applications with indirect prompt injection. *In*: ACM WORKSHOP ON ARTIFICIAL INTELLIGENCE AND SECURITY (AISec), 16., 2023, Copenhagen. **Proceedings** [...]. New York: ACM, 2023. p. 79-90. DOI: https://doi.org/10.1145/3605764.3623985.

INAN, H. *et al.* **Llama Guard**: LLM-based input-output safeguard for human-AI conversations. arXiv preprint arXiv:2312.06674, 2023. Disponível em: https://arxiv.org/abs/2312.06674. Acesso em: 3 out. 2026.

INTERNATIONAL ORGANIZATION FOR STANDARDIZATION; INTERNATIONAL ELECTROTECHNICAL COMMISSION. **ISO/IEC 25010:2023**: systems and software engineering: systems and software quality requirements and evaluation (SQuaRE): product quality model. Geneva: ISO, 2023.

INTERNATIONAL ORGANIZATION FOR STANDARDIZATION; INTERNATIONAL ELECTROTECHNICAL COMMISSION. **ISO/IEC 27001:2022**: information security, cybersecurity and privacy protection: information security management systems: requirements. Geneva: ISO, 2022.

MITRE CORPORATION. **MITRE ATLAS**: Adversarial Threat Landscape for Artificial-Intelligence Systems. [*S. l.*]: MITRE, 2024. Disponível em: https://atlas.mitre.org/. Acesso em: 3 out. 2026.

NATIONAL INSTITUTE OF STANDARDS AND TECHNOLOGY. **Artificial Intelligence Risk Management Framework (AI RMF 1.0)**. NIST AI 100-1. Gaithersburg: NIST, 2023. DOI: https://doi.org/10.6028/NIST.AI.100-1.

OWASP FOUNDATION. **OWASP Top 10 for LLM Applications 2025**. [*S. l.*]: OWASP, 2025. Disponível em: https://genai.owasp.org/llm-top-10/. Acesso em: 3 out. 2026.

PEREZ, F.; RIBEIRO, I. **Ignore previous prompt**: attack techniques for language models. arXiv preprint arXiv:2211.09527, 2022. Disponível em: https://arxiv.org/abs/2211.09527. Acesso em: 3 out. 2026.

ROSE, S. *et al.* **Zero Trust Architecture**. NIST Special Publication 800-207. Gaithersburg: NIST, 2020. DOI: https://doi.org/10.6028/NIST.SP.800-207.

SOMMERVILLE, I. **Engenharia de software**. 10. ed. São Paulo: Pearson Education do Brasil, 2018.

WEIDINGER, L. *et al.* **Ethical and social risks of harm from language models**. arXiv preprint arXiv:2112.04359, 2021. Disponível em: https://arxiv.org/abs/2112.04359. Acesso em: 3 out. 2026.
