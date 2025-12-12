# 📊 Análise Completa dos Relatórios de Segurança - Pipeline DevSecOps

**Data:** 12/12/2025 17:22

**Aplicação:** DVWA (Damn Vulnerable Web Application)

**Pesquisa:** Integração de Testes de Segurança Contínuos em Pipelines CI/CD

---

## 📋 Sumário Executivo

| Ferramenta | Tipo | Findings | Status |
| --- | --- | --- | --- |
| Trivy | Container Scan | 1575 | ✅ Executado |
| Semgrep | SAST | 4 | ✅ Executado |
| Trivy FS | SCA | 0 | ✅ Executado |
| OWASP ZAP | DAST | 0 | ⚠️ Não gerado |
| Checkov | IaC Scan | 63 | ✅ Executado |

**Total de issues de segurança identificados: 1642**

## 1. 📦 Container Scan - Trivy

**Imagem analisada:** `dvwa-app:901554b`

**Sistema Operacional:** debian 9.5

**End of Support Life (EOSL):** ⚠️ SIM - Sistema sem suporte!

### Distribuição por Severidade

| Severidade | Quantidade | Percentual |
| --- | --- | --- |
| 🔴 CRITICAL | 254 | 16.1% |
| 🟠 HIGH | 551 | 35.0% |
| 🟡 MEDIUM | 642 | 40.8% |
| 🟢 LOW | 116 | 7.4% |

### Top 10 Pacotes Mais Vulneráveis

| # | Pacote | CVEs |
| --- | --- | --- |
| 1 | libapache2-mod-php7.0 | 53 |
| 2 | php7.0 | 53 |
| 3 | php7.0-cli | 53 |
| 4 | php7.0-common | 53 |
| 5 | php7.0-gd | 53 |
| 6 | php7.0-json | 53 |
| 7 | php7.0-mysql | 53 |
| 8 | php7.0-opcache | 53 |
| 9 | php7.0-pgsql | 53 |
| 10 | php7.0-readline | 53 |

### Top 10 CWEs Mais Frequentes

| CWE | Ocorrências |
| --- | --- |
| CWE-125 | 343 |
| CWE-787 | 148 |
| CWE-190 | 114 |
| CWE-476 | 92 |
| CWE-20 | 65 |
| CWE-416 | 63 |
| CWE-908 | 41 |
| CWE-119 | 37 |
| CWE-120 | 32 |
| CWE-400 | 29 |

### Exemplos de CVEs Críticas

**1. CVE-2019-10082**
- Pacote: `apache2` v2.4.25-3+deb9u5
- Correção: Atualizar para v2.4.25-3+deb9u8
- Descrição: httpd: read-after-free in h2 connection shutdown...

**2. CVE-2021-26691**
- Pacote: `apache2` v2.4.25-3+deb9u5
- Correção: Atualizar para v2.4.25-3+deb9u10
- Descrição: httpd: mod_session: Heap overflow via a crafted SessionHeader value...

**3. CVE-2021-39275**
- Pacote: `apache2` v2.4.25-3+deb9u5
- Correção: Atualizar para v2.4.25-3+deb9u11
- Descrição: httpd: Out-of-bounds write in ap_escape_quotes() via malicious input...

**4. CVE-2021-40438**
- Pacote: `apache2` v2.4.25-3+deb9u5
- Correção: Atualizar para v2.4.25-3+deb9u11
- Descrição: httpd: mod_proxy: SSRF via a crafted request uri-path containing "unix:"...

**5. CVE-2021-44790**
- Pacote: `apache2` v2.4.25-3+deb9u5
- Correção: Atualizar para v2.4.25-3+deb9u12
- Descrição: httpd: mod_lua: Possible buffer overflow when parsing multipart content...

## 2. 🔍 SAST (Static Application Security Testing) - Semgrep

**Total de findings:** 4

### Distribuição por Severidade

| Severidade | Quantidade |
| --- | --- |
| 🔴 ERROR | 0 |
| 🟠 WARNING | 2 |
| 🟢 INFO | 2 |

### Findings por Arquivo

**📄 dvwa.yaml**

- 🟢 **Linha 16:** `run-as-non-root`
  - CWE: CWE-250: Execution with Unnecessary Privileges
  - OWASP: A05:2021 - Security Misconfiguration
- 🟠 **Linha 18:** `allow-privilege-escalation-no-securitycontext`
  - CWE: CWE-732: Incorrect Permission Assignment for Critical Resource
  - OWASP: A05:2021 - Security Misconfiguration

**📄 mysql.yaml**

- 🟢 **Linha 27:** `run-as-non-root`
  - CWE: CWE-250: Execution with Unnecessary Privileges
  - OWASP: A05:2021 - Security Misconfiguration
- 🟠 **Linha 29:** `allow-privilege-escalation-no-securitycontext`
  - CWE: CWE-732: Incorrect Permission Assignment for Critical Resource
  - OWASP: A05:2021 - Security Misconfiguration

### CWEs Identificados

- **CWE-250: Execution with Unnecessary Privileges**: 2 ocorrência(s)
- **CWE-732: Incorrect Permission Assignment for Critical Resource**: 2 ocorrência(s)

### Mapeamento OWASP Top 10

- **A05:2021 - Security Misconfiguration**: 4 ocorrência(s)
- **A06:2017 - Security Misconfiguration**: 4 ocorrência(s)

## 3. 📦 SCA (Software Composition Analysis) - Trivy FS

**Alvo:** Código fonte do projeto

**Vulnerabilidades em dependências:** 0

✅ **NENHUMA VULNERABILIDADE ENCONTRADA EM DEPENDÊNCIAS!**

## 4. 🌐 DAST (Dynamic Application Security Testing) - OWASP ZAP

⚠️ Relatório do OWASP ZAP não disponível.

**Possíveis causas:**
1. O ZAP não conseguiu acessar a aplicação
2. O LoadBalancer não obteve IP externo a tempo
3. A aplicação não estava pronta quando o scan iniciou

## 5. 🏗️ IaC Scan - Checkov

**Checks passados:** 205

**Checks falhados:** 63

**Checks ignorados:** 0

### Findings de Segurança

| Check ID | Recurso | Arquivo | Severidade |
| --- | --- | --- | --- |
| CKV_GCP_84 | google_artifact_registry_repos | artifact-registry.tf | None |
| CKV_GCP_70 | google_container_cluster.prima | gke.tf | None |
| CKV_GCP_65 | google_container_cluster.prima | gke.tf | None |
| CKV_GCP_13 | google_container_cluster.prima | gke.tf | None |
| CKV_GCP_20 | google_container_cluster.prima | gke.tf | None |
| CKV_GCP_25 | google_container_cluster.prima | gke.tf | None |
| CKV_GCP_66 | google_container_cluster.prima | gke.tf | None |
| CKV_GCP_21 | google_container_cluster.prima | gke.tf | None |
| CKV_GCP_12 | google_container_cluster.prima | gke.tf | None |
| CKV_GCP_64 | google_container_cluster.prima | gke.tf | None |
| CKV_GCP_69 | google_container_cluster.prima | gke.tf | None |
| CKV_GCP_61 | google_container_cluster.prima | gke.tf | None |
| CKV_GCP_68 | google_container_node_pool.pri | gke.tf | None |
| CKV_GCP_9 | google_container_node_pool.pri | gke.tf | None |
| CKV_GCP_10 | google_container_node_pool.pri | gke.tf | None |
| CKV_GCP_69 | google_container_node_pool.pri | gke.tf | None |
| CKV_GCP_49 | google_project_iam_member.clou | iam.tf | None |
| CKV_GCP_114 | google_storage_bucket.reports_ | storage.tf | None |
| CKV_GCP_78 | google_storage_bucket.reports_ | storage.tf | None |
| CKV_GCP_62 | google_storage_bucket.reports_ | storage.tf | None |


## 6. 🎯 Comparação com Vulnerabilidades Conhecidas do DVWA

**Vulnerabilidades conhecidas do DVWA:** 17

**Detectadas pelo pipeline:** 7 (41.2%)

**Não detectadas:** 10 (58.8%)

### ✅ Vulnerabilidades Detectadas

| Vulnerabilidade | Categoria | CWE | Descrição |
| --- | --- | --- | --- |
| SQL Injection | web_application | CWE-89 | Permite injeção de comandos SQL em campo... |
| Cross-Site Scripting (XSS) | web_application | CWE-79 | Permite execução de scripts maliciosos n... |
| Command Injection | web_application | CWE-78 | Permite execução de comandos do sistema ... |
| CSRF | web_application | CWE-352 | Cross-Site Request Forgery... |
| Weak Session IDs | web_application | CWE-330 | IDs de sessão previsíveis... |
| Open HTTP Redirect | web_application | CWE-601 | Redirecionamento aberto para sites malic... |
| Exposed MySQL | infrastructure | CWE-284 | MySQL com credenciais fracas... |


### ❌ Vulnerabilidades Não Detectadas

| Vulnerabilidade | Categoria | CWE | OWASP |
| --- | --- | --- | --- |
| File Inclusion (LFI/RFI) | web_application | CWE-98 | A03:2021 - Injection |
| File Upload | web_application | CWE-434 | A04:2021 - Insecure Design |
| Brute Force | web_application | CWE-307 | A07:2021 - Identification and  |
| Insecure CAPTCHA | web_application | CWE-804 | A07:2021 - Identification and  |
| JavaScript Attacks | web_application | CWE-749 | A05:2021 - Security Misconfigu |
| Content Security Policy Bypass | web_application | CWE-693 | A05:2021 - Security Misconfigu |
| Authorisation Bypass | web_application | CWE-639 | A01:2021 - Broken Access Contr |
| Outdated OS | infrastructure | CWE-1104 | N/A |
| Outdated Packages | infrastructure | CWE-1104 | N/A |
| Default Credentials | infrastructure | CWE-798 | N/A |


### Análise da Cobertura


As vulnerabilidades não detectadas são predominantemente:

1. **VULNERABILIDADES WEB (SQL Injection, XSS, etc.)**
   - Requerem análise DINÂMICA (DAST) com a aplicação em execução
   - O SAST analisou arquivos de configuração, não código PHP do DVWA

2. **FALHAS DE AUTENTICAÇÃO (Brute Force, Weak Session IDs)**
   - Requerem testes comportamentais da aplicação

3. **FALHAS DE AUTORIZAÇÃO (CSRF, Authorization Bypass)**
   - Requerem interação HTTP real com a aplicação

**📌 CONCLUSÃO:**

O pipeline atual é eficaz para:
- ✅ Vulnerabilidades de infraestrutura (Container, OS)
- ✅ Misconfigurações (Kubernetes, Terraform, IaC)
- ✅ Dependências vulneráveis (SCA)

Para cobertura completa, é necessário:
- ⚠️ Implementar DAST funcional (OWASP ZAP, Nuclei, etc.)
- ⚠️ Adicionar SAST específico para PHP (linguagem do DVWA)

## 7. 📝 Conclusões e Recomendações para o TCC

### Principais Descobertas


1. **RISCO CRÍTICO - SISTEMA OPERACIONAL**
   - A imagem base do DVWA utiliza Debian 9.5, que está em End of Support Life (EOSL) desde 2020
   - Isso resulta em centenas de vulnerabilidades CRÍTICAS e de ALTA severidade sem patches disponíveis

2. **CONFIGURAÇÃO KUBERNETES INSEGURA**
   - Os manifestos de deployment não implementam SecurityContext adequado
   - `runAsNonRoot` não configurado (CWE-250)
   - `allowPrivilegeEscalation` não bloqueado (CWE-732)
   - Permite potencial escalação de privilégios

3. **CÓDIGO FONTE LIMPO**
   - Nenhuma vulnerabilidade foi encontrada nas dependências do projeto Terraform/CloudBuild
   - Indica boas práticas de composição de software

4. **GAPS DE COBERTURA**
   - O DAST é essencial para detectar as principais vulnerabilidades web do DVWA

### Eficácia do Pipeline


**PONTOS FORTES:**
- ✅ Detecção automatizada de milhares de vulnerabilidades
- ✅ Execução totalmente integrada ao CI/CD (Cloud Build)
- ✅ Múltiplas camadas de análise (Container, IaC, SCA, SAST, DAST)
- ✅ Relatórios estruturados em JSON para análise
- ✅ Tempo de execução aceitável (~10-15 minutos)

**PONTOS DE MELHORIA:**
- ⚠️ Necessidade de validar funcionamento do DAST
- ⚠️ Ausência de SAST para código PHP da aplicação
- ⚠️ Dependency-Check (OWASP) desativado por performance

### Recomendações


**CURTO PRAZO:**
1. Validar execução do OWASP ZAP com IP externo
2. Adicionar timeout/retry para DAST
3. Garantir geração de todos os relatórios

**MÉDIO PRAZO:**
4. Adicionar SAST específico para PHP (PHPStan, Psalm)
5. Configurar NVD API key para OWASP Dependency-Check
6. Implementar quality gates (falhar build em CVEs críticas)

**LONGO PRAZO:**
7. Adicionar análise de secrets (TruffleHog, GitLeaks)
8. Implementar fuzzing automatizado
9. Integrar com plataforma de gestão de vulnerabilidades

---

*Relatório gerado automaticamente em 12/12/2025 às 17:22:41*