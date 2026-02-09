# 📝 Memorial do Projeto

## Informações Gerais

**Título:** Uma Abordagem DevSecOps para Inserção e Automação de Práticas de Segurança em Pipelines CI/CD

**Aluno:** Guilherme Henrique de Lima Machado

**Curso:** Sistemas de Informação - PUC Minas

**Período Inicial:** 2025/2 (Pesquisa - Disciplina TIPI)

**Período de Continuação:** 2026/1 (Trabalho de Conclusão de Curso)

**Orientador TIPI:** Prof. Lesandro Ponciano

---

## 1. Origem do Projeto (2025/2)

O projeto nasceu como uma pesquisa na disciplina **TIPI (Trabalho Interdisciplinar de Pesquisa e Inovação)** no segundo semestre de 2025. A motivação surgiu de uma inquietação profissional: como integrar segurança de forma automatizada em pipelines CI/CD sem criar gargalos no fluxo de desenvolvimento?

### 1.1 Fundamentação Teórica

A pesquisa se baseou em **5 artigos científicos** que foram fichados e analisados:

1. **"An Empirical Study of DevSecOps Focused on Continuous Security Testing"** (2024) - Framework completo de DevSecOps com 8 fases
2. **"Implementation of DevSecOps by Integrating Static and Dynamic Security Testing in CI/CD Pipelines"** (2022) - Combinação SAST + DAST
3. **"Implementing and Automating Security Scanning to a DevSecOps CI/CD Pipeline"** (2023) - Integração com GitHub Actions
4. **"Continuous Security Testing: A Case Study on Integrating Dynamic Security Testing Tools in CI/CD Pipelines"** (2020) - Análise de overhead de DAST
5. **"Integrating Security with DevSecOps: Techniques and Challenges"** (2019) - Desafios culturais e de processo

### 1.2 Proposta Inicial

O objetivo era implementar um pipeline CI/CD completo com ferramentas de segurança automatizadas, usando:
- **Infraestrutura:** Google Cloud Platform (GCP) provisionada via Terraform
- **Aplicação-alvo:** DVWA (Damn Vulnerable Web Application)
- **Ferramentas planejadas:** Semgrep (SAST), OWASP Dependency-Check (SCA), Checkov (IaC), Trivy (Container), OWASP ZAP (DAST)

---

## 2. Implementação e Desafios Técnicos

### 2.1 Infraestrutura (Terraform)

A infraestrutura foi provisionada no GCP incluindo:
- **Google Kubernetes Engine (GKE)** - Cluster para deploy do DVWA
- **Artifact Registry** - Repositório de imagens Docker
- **Cloud Build** - Execução do pipeline CI/CD
- **Cloud Storage** - Armazenamento dos relatórios de segurança
- **VPC e configurações de rede**

**Desafio:** Configuração de IAM e permissões para o Cloud Build acessar todos os serviços.

### 2.2 Pipeline CI/CD (cloudbuild.yaml)

O pipeline foi estruturado com **15 steps**:

| Fase | Ferramenta | Tipo |
|------|------------|------|
| Build | Docker | - |
| SAST | Semgrep | Análise estática |
| SCA | Trivy | Dependências |
| IaC Scan | Checkov | Terraform/K8s |
| Container Scan | Trivy | Imagem Docker |
| Deploy | kubectl | GKE |
| DAST Baseline | OWASP ZAP | Passivo |
| DAST Active | OWASP ZAP | Ativo autenticado |
| Brute Force | Script Python | Autenticação |

### 2.3 Principais Desafios Enfrentados

#### 2.3.1 OWASP ZAP Active Scan - Autenticação

**Problema:** O ZAP Active Scan não estava detectando SQL Injection porque não conseguia autenticar no DVWA.

**Investigação:**
- O DVWA usa proteção CSRF no login
- O ZAP precisa de autenticação para acessar páginas vulneráveis
- A configuração padrão do ZAP não lidava com tokens CSRF dinâmicos

**Solução Implementada:**
1. Configuração de Form-Based Authentication no ZAP
2. Extração automática do token CSRF via regex
3. Uso de ZAP Automation Framework com YAML
4. Configuração de sessão persistente

```yaml
authentication:
  method: "form"
  parameters:
    loginUrl: "http://${DVWA_IP}/login.php"
    loginRequestData: "username={%username%}&password={%password%}&Login=Login&user_token={%user_token%}"
```

#### 2.3.2 Configuração do Nível de Segurança do DVWA

**Problema:** O DVWA estava configurado no nível "IMPOSSIBLE" (seguro), impedindo a detecção de vulnerabilidades.

**Investigação:**
- O DVWA precisa estar no nível "LOW" para expor vulnerabilidades
- A configuração é feita via interface web, não via arquivo
- O step de setup não estava verificando se a alteração foi aplicada

**Solução Implementada:**
1. Criação de step `setup-dvwa` que faz login e altera o nível
2. Implementação de retry logic (3 tentativas)
3. Verificação de múltiplos padrões HTML para confirmar alteração
4. Validação de cookies de sessão

#### 2.3.3 Script de Brute Force Customizado

**Problema:** O Hydra não funciona com DVWA porque não lida com tokens CSRF dinâmicos.

**Solução:**
- Desenvolvimento do script `dvwa-bruteforce.py` inspirado no Hydra
- Extração automática de tokens CSRF a cada requisição
- Manutenção de sessão via cookies
- Detecção de sucesso/falha por parsing de resposta

#### 2.3.4 Detecção de JavaScript Attacks (CWE-749)

**Problema:** A cobertura caiu de 76% para 70% após ajustes.

**Investigação:**
- O Semgrep detectava vulnerabilidades JavaScript mas mapeava para CWE-95 (Eval Injection)
- O DVWA tem vulnerabilidade específica de JavaScript Attacks (CWE-749)
- Os reports JSON não estavam sendo versionados

**Solução:**
- Adicionada lógica no `analise.py` para detectar CWE-749 quando Semgrep encontrar issues no diretório `/javascript/`
- Criação de constante `OUT_OF_SCOPE_VULNERABILITIES` para documentar limitações

---

## 3. Resultados Obtidos

### 3.1 Cobertura de Vulnerabilidades

| Métrica | Valor |
|---------|-------|
| **Cobertura Geral** | 76.5% (13/17) |
| **Cobertura Ajustada** | 100% (13/13) |
| **Vulnerabilidades fora do escopo** | 4 |

### 3.2 Vulnerabilidades Detectadas

| Vulnerabilidade | CWE | Ferramenta |
|-----------------|-----|------------|
| SQL Injection | CWE-89 | ZAP Active Scan |
| Cross-Site Scripting (XSS) | CWE-79 | Semgrep |
| Command Injection | CWE-78 | Semgrep |
| CSRF | CWE-352 | Trivy |
| Brute Force | CWE-307 | Script Python |
| JavaScript Attacks | CWE-749 | Semgrep |
| CSP Bypass | CWE-693 | ZAP |
| Default Credentials | CWE-798 | Script Python |
| Outdated OS | CWE-1104 | Trivy |
| Outdated Packages | CWE-1104 | Trivy |
| Weak Session IDs | CWE-330 | Trivy |
| Open HTTP Redirect | CWE-601 | ZAP |
| Hardcoded Credentials | CWE-798 | Semgrep |

### 3.3 Vulnerabilidades Fora do Escopo

Algumas vulnerabilidades não são detectáveis por pipelines automatizados:

| Vulnerabilidade | CWE | Motivo |
|-----------------|-----|--------|
| File Inclusion | CWE-98 | Requer navegação manual e payloads específicos |
| File Upload | CWE-434 | Requer upload real de arquivos maliciosos |
| Insecure CAPTCHA | CWE-804 | CAPTCHA é projetado para impedir automação |
| Auth Bypass | CWE-639 | Requer entendimento de lógica de negócio |

### 3.4 Métricas das Ferramentas

| Ferramenta | Findings | Críticos | Altos |
|------------|----------|----------|-------|
| Trivy (Container) | 1575 | 254 | 551 |
| Semgrep | 77 | 51 | 26 |
| Checkov | 63 | - | - |
| OWASP ZAP | 32 | 1 | 6 |
| Brute Force | 1 | 1 | - |

---

## 4. Evolução: De Pesquisa para TCC (2026/1)

### 4.1 Motivação para Continuação

A pesquisa em TIPI demonstrou que:
1. É viável integrar múltiplas ferramentas de segurança em um pipeline CI/CD
2. Existem limitações inerentes a testes automatizados que precisam ser documentadas
3. O tema é relevante para a indústria de software

### 4.2 Diferenças para o TCC

| Aspecto | TIPI (2025/2) | TCC (2026/1) |
|---------|---------------|--------------|
| **Foco** | Implementação inicial | Refinamento e documentação |
| **Escopo** | Pipeline básico | Pipeline completo com Active Scan |
| **Análise** | Qualitativa básica | Script de análise automatizado |
| **Documentação** | Pré-projeto | Artigo completo |

---

## 5. Lições Aprendidas

### 5.1 Técnicas

1. **Autenticação em DAST é complexa** - Tokens CSRF, sessões e cookies exigem configuração específica
2. **Ferramentas têm sobreposição** - Semgrep e ZAP podem detectar o mesmo tipo de vulnerabilidade
3. **Mapeamento CWE não é trivial** - Ferramentas usam CWEs diferentes para problemas similares
4. **Pipelines têm limitações** - Nem toda vulnerabilidade pode ser detectada automaticamente

### 5.2 Metodológicas

1. **Versionamento de relatórios é essencial** - Permite comparação entre execuções
2. **Scripts de análise agregam valor** - Consolidam dados de múltiplas ferramentas
3. **Documentação incremental** - Manter README atualizado facilita retomada

### 5.3 Profissionais

1. **DevSecOps é cultura, não só ferramentas** - A integração depende de processos
2. **Automação tem ROI** - Investimento inicial alto, mas ganho a longo prazo
3. **Falsos positivos são comuns** - Triagem manual ainda é necessária

---

## 6. Ferramentas e Tecnologias Utilizadas

### Infraestrutura
- Google Cloud Platform (GCP)
- Terraform (IaC)
- Google Kubernetes Engine (GKE)
- Cloud Build
- Artifact Registry

### Segurança
- **Semgrep** - SAST (PHP, JavaScript)
- **Trivy** - Container Scan e SCA
- **Checkov** - IaC Scanning
- **OWASP ZAP** - DAST (Baseline + Active)
- **Script Python** - Brute Force customizado

### Desenvolvimento
- Python 3 (scripts de análise e brute force)
- Docker
- Kubernetes
- YAML (configurações)

### Aplicação-Alvo
- DVWA (Damn Vulnerable Web Application)
- 17 vulnerabilidades conhecidas
- Níveis de segurança configuráveis

---

## 7. Cronograma Resumido

| Período | Atividade |
|---------|-----------|
| **Out/2025** | Início da pesquisa, fichamentos |
| **Nov/2025** | Pré-projeto, setup inicial GCP |
| **Dez/2025** | Implementação pipeline básico |
| **Jan/2026** | Pausa (férias) |
| **Fev/2026** | Refinamento ZAP, Active Scan, script de análise |
| **Fev/2026** | Documentação final, commit dos relatórios |

---

## 8. Arquivos Principais do Projeto

```
├── Artigo/
│   ├── pre-projeto.md          # Proposta inicial (TIPI)
│   └── esboco.md               # Esboço do artigo
├── Fichamentos/
│   └── *.md                    # 5 fichamentos de artigos
├── Instrumentos/
│   ├── Codigos/DevSecOps/
│   │   ├── dvwa/cloudbuild.yaml    # Pipeline principal (464 linhas)
│   │   ├── infra/*.tf              # Terraform (28 recursos)
│   │   └── dvwa-bruteforce.py      # Script brute force
│   └── Reports/
│       ├── analise.py              # Script de análise (1800+ linhas)
│       ├── reports-*.json          # Relatórios das ferramentas
│       └── relatorio-vulnerabilidades.md
└── README.md                   # Documentação principal
```

---

## 9. Considerações Finais

Este projeto demonstrou que é possível implementar um pipeline DevSecOps funcional com ferramentas open-source, alcançando **100% de cobertura** para vulnerabilidades detectáveis por automação.

As principais contribuições são:
1. **Pipeline replicável** - Toda infraestrutura é código (IaC)
2. **Script de análise** - Automatiza comparação com vulnerabilidades conhecidas
3. **Documentação de limitações** - Identifica o que pipelines automatizados NÃO conseguem detectar

O projeto continuará como TCC em 2026/1, com foco em:
- Refinamento da análise quantitativa
- Escrita do artigo final
- Apresentação para banca

---

*Última atualização: Fevereiro de 2026*