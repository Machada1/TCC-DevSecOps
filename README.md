# 🔐 Uma Abordagem DevSecOps para Inserção e Automação de Práticas de Segurança em Pipelines CI/CD

> **Trabalho de Conclusão de Curso (TCC)** | Pontifícia Universidade Católica de Minas Gerais  
> Curso: Sistemas de Informação | 2025

## 📋 Sumário

- [Resumo do Projeto](#-resumo-do-projeto)
- [Objetivos](#-objetivos)
- [Fundamentação Teórica](#-fundamentação-teórica)
- [Glossário de Termos Técnicos](#-glossário-de-termos-técnicos)
- [Arquitetura da Solução](#-arquitetura-da-solução)
- [Ferramentas Utilizadas](#-ferramentas-utilizadas)
- [Pipeline DevSecOps - Explicação Detalhada](#-pipeline-devsecops---explicação-detalhada)
- [Instruções de Replicação](#-instruções-de-replicação)
- [Análise de Cobertura](#-análise-de-cobertura)
- [Resultados Obtidos](#-resultados-obtidos)
- [Estrutura do Projeto](#-estrutura-do-projeto)
- [Autor e Orientador](#-autor-e-orientador)

---

## 📖 Resumo do Projeto

Este projeto investiga e implementa práticas de segurança em pipelines de **Integração Contínua e Entrega Contínua (CI/CD)**, utilizando os princípios de **DevSecOps**. A pesquisa demonstra como a automação de verificações de segurança pode ser integrada de forma prática em pipelines CI/CD, garantindo que vulnerabilidades sejam detectadas desde as primeiras etapas do ciclo de desenvolvimento.

O projeto utiliza o **DVWA (Damn Vulnerable Web Application)** como aplicação-alvo, uma aplicação web intencionalmente vulnerável amplamente utilizada para treinamento em segurança. A infraestrutura é provisionada via **Terraform** no **Google Cloud Platform (GCP)**, incluindo Cloud Build, Artifact Registry e Google Kubernetes Engine (GKE).

### Principais Contribuições

- Implementação de um pipeline CI/CD com **6 ferramentas de segurança** integradas
- Demonstração prática de **SAST, DAST, SCA e IaC Scanning** automatizados
- Análise quantitativa e qualitativa da cobertura de detecção de vulnerabilidades
- Script de análise que compara resultados com vulnerabilidades conhecidas do DVWA
- Documentação completa para reprodução do experimento

---

## 🎯 Objetivos

### Objetivo Geral
Demonstrar a viabilidade e efetividade da integração de ferramentas de segurança automatizadas em pipelines CI/CD, seguindo os princípios DevSecOps.

### Objetivos Específicos
1. Implementar um pipeline CI/CD completo com ferramentas de segurança
2. Avaliar a cobertura de detecção de vulnerabilidades conhecidas
3. Identificar limitações e gaps de cada tipo de teste de segurança
4. Documentar boas práticas para implementação de DevSecOps
5. Propor melhorias para aumentar a cobertura de segurança

---

## 📚 Fundamentação Teórica

### DevSecOps

**DevSecOps** é uma abordagem que integra práticas de segurança em todas as fases do ciclo de vida do desenvolvimento de software. O termo combina:

- **Dev** (Development): Desenvolvimento de software
- **Sec** (Security): Segurança da informação
- **Ops** (Operations): Operações de TI

#### Princípios Fundamentais

| Princípio | Descrição |
|-----------|-----------|
| **Shift Left** | Mover testes de segurança para o início do ciclo de desenvolvimento |
| **Automação** | Automatizar verificações de segurança para execução contínua |
| **Colaboração** | Integrar equipes de desenvolvimento, segurança e operações |
| **Feedback Rápido** | Fornecer resultados de segurança em tempo real |
| **Cultura de Segurança** | Tornar segurança responsabilidade de todos |

### Tipos de Testes de Segurança

| Tipo | Nome Completo | Descrição |
|------|---------------|-----------|
| **SAST** | Static Application Security Testing | Análise do código-fonte sem executar a aplicação |
| **DAST** | Dynamic Application Security Testing | Teste da aplicação em execução, simulando ataques |
| **SCA** | Software Composition Analysis | Análise de dependências e bibliotecas de terceiros |
| **IaC Scan** | Infrastructure as Code Scanning | Análise de configurações de infraestrutura |

---

## 📖 Glossário de Termos Técnicos

### Siglas de Segurança

| Sigla | Termo Completo | Descrição |
|-------|----------------|-----------|
| **CWE** | Common Weakness Enumeration | Catálogo padronizado de tipos de vulnerabilidades. Ex: CWE-89 (SQL Injection) |
| **CVE** | Common Vulnerabilities and Exposures | Identificador único para vulnerabilidades conhecidas. Ex: CVE-2021-44228 |
| **CVSS** | Common Vulnerability Scoring System | Sistema de pontuação de severidade (0-10) |
| **OWASP** | Open Web Application Security Project | Organização que publica padrões de segurança web |
| **NVD** | National Vulnerability Database | Base de dados pública de CVEs |

### Termos DevSecOps

| Termo | Descrição |
|-------|-----------|
| **Shift Left** | Mover atividades de segurança para o início do desenvolvimento |
| **Pipeline** | Sequência automatizada de etapas para build, teste e deploy |
| **Artifact** | Artefato gerado pelo build (imagem Docker, pacote, etc.) |
| **Container** | Unidade padronizada de software que empacota código e dependências |
| **Baseline Scan** | Scan passivo que não executa ataques ativos |
| **Active Scan** | Scan que executa payloads de ataque |
| **Spider/Crawler** | Componente que navega automaticamente pela aplicação |

### Tipos de Vulnerabilidades

| Vulnerabilidade | CWE | Descrição |
|-----------------|-----|-----------|
| **SQL Injection** | CWE-89 | Injeção de comandos SQL maliciosos |
| **XSS** | CWE-79 | Injeção de scripts no navegador |
| **Command Injection** | CWE-78 | Injeção de comandos do SO |
| **CSRF** | CWE-352 | Falsificação de requisições |
| **File Inclusion** | CWE-98 | Inclusão de arquivos não autorizados |
| **Brute Force** | CWE-307 | Tentativas repetidas de login |
| **Hardcoded Credentials** | CWE-798 | Credenciais fixas no código |

### Severidades

| Nível | CVSS | Descrição |
|-------|------|-----------|
| **CRITICAL** | 9.0-10.0 | Exploração trivial, impacto severo |
| **HIGH** | 7.0-8.9 | Exploração possível, impacto significativo |
| **MEDIUM** | 4.0-6.9 | Requer condições específicas |
| **LOW** | 0.1-3.9 | Impacto limitado |

---

## 🔧 Ferramentas Utilizadas

### 1. Semgrep (SAST)

| Atributo | Valor |
|----------|-------|
| **Categoria** | SAST - Static Application Security Testing |
| **Função** | Análise estática de código-fonte |
| **Linguagens** | PHP, JavaScript, Python, Go, Java |
| **Website** | [semgrep.dev](https://semgrep.dev) |

**O que detecta:** SQL Injection, XSS, Command Injection, Hardcoded Secrets, Eval Injection

**Step no Pipeline:** `semgrep` - Analisa código PHP do DVWA com regras OWASP Top 10

---

### 2. Trivy (SCA + Container Scan)

| Atributo | Valor |
|----------|-------|
| **Categoria** | SCA + Container Security |
| **Função** | Análise de dependências e imagens Docker |
| **Fabricante** | Aqua Security |
| **Website** | [trivy.dev](https://trivy.dev) |

**O que detecta:** CVEs em pacotes, OS desatualizado, Secrets expostos, Pacotes vulneráveis

**Steps no Pipeline:**
- `sca-scan` - Analisa dependências no código-fonte
- `trivy` - Analisa imagem Docker construída

---

### 3. Checkov (IaC Scan)

| Atributo | Valor |
|----------|-------|
| **Categoria** | IaC Security |
| **Função** | Análise de infraestrutura como código |
| **Fabricante** | Bridgecrew (Palo Alto) |
| **Website** | [checkov.io](https://www.checkov.io) |

**O que detecta:** Configurações inseguras em Terraform, Kubernetes, Dockerfiles

**Step no Pipeline:** `checkov` - Analisa Terraform e manifests K8s

---

### 4. OWASP ZAP (DAST)

| Atributo | Valor |
|----------|-------|
| **Categoria** | DAST - Dynamic Application Security Testing |
| **Função** | Testes dinâmicos em aplicação em execução |
| **Fabricante** | OWASP Foundation |
| **Website** | [zaproxy.org](https://www.zaproxy.org) |

**O que detecta:** SQL Injection, XSS, CSRF, Headers ausentes, Information Disclosure

**Steps no Pipeline:**
- `zap-scan` - Baseline scan (passivo)
- `zap-auth-active-scan` - Active scan autenticado com payloads de ataque

---

### 5. Script de Brute Force (Python)

| Atributo | Valor |
|----------|-------|
| **Categoria** | Authentication Testing |
| **Função** | Teste de força bruta com suporte a CSRF |
| **Arquivo** | `dvwa-bruteforce.py` |
| **Baseado em** | [Hydra](https://github.com/vanhauser-thc/thc-hydra) |

**Por que customizado?** O DVWA usa proteção CSRF no login. O **Hydra** é uma das ferramentas mais populares para ataques de força bruta, porém não lida nativamente com tokens CSRF dinâmicos. O script `dvwa-bruteforce.py` foi desenvolvido inspirado na lógica do Hydra, mas com suporte a:
- Extração automática de tokens CSRF
- Manutenção de sessão via cookies
- Parsing de respostas para detectar sucesso/falha

**O que detecta:** CWE-307 (Brute Force), CWE-798 (Default Credentials)

**Step no Pipeline:** `bruteforce-attack`

---

## 🔄 Pipeline DevSecOps - Explicação Detalhada

### Steps do Pipeline

| # | ID | Ferramenta | Descrição |
|---|-----|------------|-----------|
| 0 | `setup` | Ubuntu | Cria diretório de relatórios |
| 1 | `pull-dvwa` | Docker | Pull da imagem DVWA |
| 2-3 | `push-dvwa`, `push` | Docker | Tag e push para Artifact Registry |
| 4 | `semgrep` | Semgrep | **SAST** - Análise estática PHP |
| 5 | `sca-scan` | Trivy | **SCA** - Análise de dependências |
| 6 | `checkov` | Checkov | **IaC Scan** - Terraform e K8s |
| 7 | `trivy` | Trivy | **Container Scan** - Imagem Docker |
| 8-9 | `deploy-mysql`, `deploy` | kubectl | Deploy no GKE |
| 10 | `get-external-ip` | kubectl | Obtém IP do LoadBalancer |
| 10.1 | `setup-dvwa` | curl | Configura DVWA (LOW security) |
| 11 | `zap-scan` | ZAP | **DAST** - Baseline scan |
| 12 | `zap-auth-active-scan` | ZAP | **DAST** - Active scan autenticado |
| 13 | `bruteforce-attack` | Python | **Brute Force** - Teste de credenciais |
| 14 | `upload-reports` | gsutil | Upload relatórios para GCS |

---

## 📖 Instruções de Replicação

### Requisitos

- Conta no **Google Cloud Platform (GCP)**
- **Terraform** >= 1.5
- **Google Cloud SDK** instalado e autenticado

### Passo 1: Provisionar Infraestrutura

```bash
cd Instrumentos/Codigos/DevSecOps/infra
terraform init && terraform apply
```

### Passo 2: Executar Pipeline

```bash
gcloud builds submit --config Instrumentos/Codigos/DevSecOps/dvwa/cloudbuild.yaml .
```

### Passo 3: Analisar Cobertura

```bash
cd Instrumentos/Reports/
python analise.py
cat relatorio-vulnerabilidades.md
```

---

## 📊 Análise de Cobertura

### Cobertura Geral: **76.5% (13/17)**

| Status | Vulnerabilidade | CWE | Ferramenta |
|--------|-----------------|-----|------------|
| ✅ | SQL Injection | CWE-89 | ZAP Active Scan |
| ✅ | XSS | CWE-79 | Semgrep |
| ✅ | Command Injection | CWE-78 | Semgrep |
| ✅ | CSRF | CWE-352 | Trivy |
| ✅ | Brute Force | CWE-307 | Script Brute Force |
| ✅ | JavaScript Attacks | CWE-749 | Semgrep |
| ✅ | CSP Bypass | CWE-693 | ZAP |
| ✅ | Default Credentials | CWE-798 | Script Brute Force |
| ✅ | Outdated OS | CWE-1104 | Trivy |
| ⚠️ | File Inclusion | CWE-98 | Fora do escopo |
| ⚠️ | File Upload | CWE-434 | Fora do escopo |
| ⚠️ | Insecure CAPTCHA | CWE-804 | Fora do escopo |
| ⚠️ | Auth Bypass | CWE-639 | Fora do escopo |

### Cobertura Ajustada (Escopo Automatizável): **100% (13/13)**

Considerando apenas vulnerabilidades passíveis de detecção automatizada em pipelines CI/CD, a cobertura é de **100%**.

---

### ⚠️ Vulnerabilidades Fora do Escopo

As seguintes vulnerabilidades do DVWA **não são detectáveis** por ferramentas automatizadas em pipelines CI/CD devido à sua natureza:

| Vulnerabilidade | CWE | Motivo da Exclusão |
|-----------------|-----|--------------------|
| **File Inclusion (LFI/RFI)** | CWE-98 | Requer interação manual para navegar por diretórios e testar payloads específicos de inclusão de arquivos |
| **File Upload** | CWE-434 | Requer upload real de arquivos maliciosos e verificação de execução no servidor |
| **Insecure CAPTCHA** | CWE-804 | CAPTCHA é projetado para impedir automação; testar sua fraqueza requer análise humana |
| **Authorisation Bypass** | CWE-639 | Requer entendimento da lógica de negócio e testes com múltiplos usuários/sessões |

**Importante:** Essas vulnerabilidades existem no DVWA e são exploráveis, porém sua detecção requer:
- Testes manuais de penetração (pentest)
- Ferramentas interativas (Burp Suite manual, etc.)
- Conhecimento da lógica de negócio da aplicação

Isso demonstra uma **limitação inerente** de pipelines DevSecOps automatizados: nem todas as vulnerabilidades podem ser detectadas sem intervenção humana.

---

## 📈 Resultados Obtidos

| Ferramenta | Findings | Críticos | Altos |
|------------|----------|----------|-------|
| Trivy (Container) | 1575 | 254 | 551 |
| Semgrep | 77 | 51 | 26 |
| Checkov | 63 | - | - |
| OWASP ZAP | 32 | 1 | 6 |
| Brute Force | 1 | 1 | - |

---

## 📁 Estrutura do Projeto

```
├── Artigo/                    # Artigo e pré-projeto
├── Fichamentos/               # Fichamentos de artigos
├── Instrumentos/
│   ├── Codigos/DevSecOps/
│   │   ├── dvwa/
│   │   │   ├── cloudbuild.yaml  # Pipeline principal
│   │   │   ├── src/             # Código-fonte DVWA
│   │   │   └── k8s/             # Manifests Kubernetes
│   │   ├── infra/               # Terraform (GCP)
│   │   └── dvwa-bruteforce.py   # Script brute force
│   └── Reports/
│       ├── analise.py           # Script de análise
│       └── *.json               # Relatórios das ferramentas
└── README.md
```

---

## 👤 Autor e Orientador

**Autor:** Guilherme Henrique de Lima Machado  
**Orientador:** Prof. Lesandro Ponciano ([ORCID](https://orcid.org/0000-0002-5724-0094))

---

## 📚 Referências

- [OWASP DevSecOps Guideline](https://owasp.org/www-project-devsecops-guideline/)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [DVWA - Damn Vulnerable Web Application](https://github.com/digininja/DVWA)
- [Semgrep Docs](https://semgrep.dev/docs/)
- [Trivy Docs](https://aquasecurity.github.io/trivy/)
- [OWASP ZAP Docs](https://www.zaproxy.org/docs/)

---

<div align="center">
<b>PUC Minas | 2025</b><br>
<i>Trabalho de Conclusão de Curso - Sistemas de Informação</i>
</div>
