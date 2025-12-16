# 📊 Análise Completa dos Relatórios de Segurança - Pipeline DevSecOps

**Data:** 16/12/2025 00:24

**Aplicação:** DVWA (Damn Vulnerable Web Application)

**Pesquisa:** Integração de Testes de Segurança Contínuos em Pipelines CI/CD

---

## 📋 Sumário Executivo

| Ferramenta | Tipo | Findings | Status |
| --- | --- | --- | --- |
| Trivy | Container Scan | 1575 | ✅ Executado |
| Semgrep | SAST | 4 | ✅ Executado |
| Trivy FS | SCA | 0 | ✅ Executado |
| OWASP ZAP | DAST | 18 | ✅ Executado |
| Checkov | IaC Scan | 63 | ✅ Executado |

**Total de issues de segurança identificados: 1660**

## 1. 📦 Container Scan - Trivy

**Imagem analisada:** `dvwa-app:4a6c28b`

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

**Alvo:** `http://34.28.0.21`

**Total de alertas:** 18

### Distribuição por Risco

| Nível de Risco | Quantidade |
| --- | --- |
| Medium | 3 |
| Low | 9 |
| Informational | 6 |

### Alertas Encontrados

**🟠 Content Security Policy (CSP) Header Not Set**
- Risco: Medium (High)
- CWE: CWE-693
- Descrição: Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certai...

**🟠 Missing Anti-clickjacking Header**
- Risco: Medium (Medium)
- CWE: CWE-1021
- Descrição: The response does not protect against 'ClickJacking' attacks. It should include either Content-Secur...

**🟠 Source Code Disclosure - SQL**
- Risco: Medium (Medium)
- CWE: CWE-540
- Descrição: Application Source Code was disclosed by the web server. - SQL ...

**🟡 Cookie No HttpOnly Flag**
- Risco: Low (Medium)
- CWE: CWE-1004
- Descrição: A cookie has been set without the HttpOnly flag, which means that the cookie can be accessed by Java...

**🟡 Cookie without SameSite Attribute**
- Risco: Low (Medium)
- CWE: CWE-1275
- Descrição: A cookie has been set without the SameSite attribute, which means that the cookie can be sent as a r...

**🟡 Dangerous JS Functions**
- Risco: Low (Low)
- CWE: CWE-749
- Descrição: A dangerous JS function seems to be in use that would leave the site vulnerable. ...

**🟡 In Page Banner Information Leak**
- Risco: Low (High)
- CWE: CWE-497
- Descrição: The server returned a version banner string in the response content. Such information leaks may allo...

**🟡 Information Disclosure - Debug Error Messages**
- Risco: Low (Medium)
- CWE: CWE-1295
- Descrição: The response appeared to contain common error messages returned by platforms such as ASP.NET, and We...

**🟡 Insufficient Site Isolation Against Spectre Vulnerability**
- Risco: Low (Medium)
- CWE: CWE-693
- Descrição: Cross-Origin-Resource-Policy header is an opt-in header designed to counter side-channels attacks li...

**🟡 Permissions Policy Header Not Set**
- Risco: Low (Medium)
- CWE: CWE-693
- Descrição: Permissions Policy Header is an added layer of security that helps to restrict from unauthorized acc...

**🟡 Server Leaks Version Information via "Server" HTTP Response Header Field**
- Risco: Low (High)
- CWE: CWE-497
- Descrição: The web/application server is leaking version information via the "Server" HTTP response header. Acc...

**🟡 X-Content-Type-Options Header Missing**
- Risco: Low (Medium)
- CWE: CWE-693
- Descrição: The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older ver...

**🔵 Authentication Request Identified**
- Risco: Informational (High)
- CWE: CWE--1
- Descrição: The given request has been identified as an authentication request. The 'Other Info' field contains ...

**🔵 Information Disclosure - Suspicious Comments**
- Risco: Informational (Medium)
- CWE: CWE-615
- Descrição: The response appears to contain suspicious comments which may help an attacker. ...

**🔵 Non-Storable Content**
- Risco: Informational (Medium)
- CWE: CWE-524
- Descrição: The response contents are not storable by caching components such as proxy servers. If the response ...

**🔵 Session Management Response Identified**
- Risco: Informational (Medium)
- CWE: CWE--1
- Descrição: The given response has been identified as containing a session management token. The 'Other Info' fi...

**🔵 Storable and Cacheable Content**
- Risco: Informational (Medium)
- CWE: CWE-524
- Descrição: The response contents are storable by caching components such as proxy servers, and may be retrieved...

**🔵 Storable but Non-Cacheable Content**
- Risco: Informational (Medium)
- CWE: CWE-524
- Descrição: The response contents are storable by caching components such as proxy servers, but will not be retr...

### CWEs Detectados pelo DAST

- **CWE-693**: 4 ocorrência(s)
- **CWE-1021**: 1 ocorrência(s)
- **CWE-540**: 1 ocorrência(s)
- **CWE-1004**: 1 ocorrência(s)
- **CWE-1275**: 1 ocorrência(s)
- **CWE-749**: 1 ocorrência(s)
- **CWE-497**: 2 ocorrência(s)
- **CWE-1295**: 1 ocorrência(s)
- **CWE--1**: 2 ocorrência(s)
- **CWE-615**: 1 ocorrência(s)
- **CWE-524**: 3 ocorrência(s)

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

**Detectadas pelo pipeline:** 9 (52.9%)

**Não detectadas:** 8 (47.1%)

### ✅ Vulnerabilidades Detectadas

| Vulnerabilidade | Categoria | CWE | Ferramenta | Descrição |
| --- | --- | --- | --- | --- |
| SQL Injection | web_application | CWE-89 | Trivy (Container) | Permite injeção de comandos SQL em campo... |
| Cross-Site Scripting (XSS) | web_application | CWE-79 | Trivy (Container) | Permite execução de scripts maliciosos n... |
| Command Injection | web_application | CWE-78 | Trivy (Container) | Permite execução de comandos do sistema ... |
| CSRF | web_application | CWE-352 | Trivy (Container) | Cross-Site Request Forgery... |
| Weak Session IDs | web_application | CWE-330 | Trivy (Container) | IDs de sessão previsíveis... |
| Open HTTP Redirect | web_application | CWE-601 | Trivy (Container) | Redirecionamento aberto para sites malic... |
| JavaScript Attacks | web_application | CWE-749 | OWASP ZAP | Exposição de lógica sensível no cliente... |
| Content Security Policy Bypass | web_application | CWE-693 | OWASP ZAP | Ausência ou bypass de CSP... |
| Exposed MySQL | infrastructure | CWE-284 | Trivy (Container) | MySQL com credenciais fracas... |


### ❌ Vulnerabilidades Não Detectadas

| Vulnerabilidade | Categoria | CWE | OWASP | Motivo | Sugestão |
| --- | --- | --- | --- | --- | --- |
| File Inclusion (LFI/RFI) | web_application | CWE-98 | A03:2021 - Injection | Requer autenticação e/ou ataque ativo | Adicionar ZAP autenticado/active scan na pipeline |
| File Upload | web_application | CWE-434 | A04:2021 - Insecure Design | Requer autenticação e/ou ataque ativo | Adicionar ZAP autenticado/active scan na pipeline |
| Brute Force | web_application | CWE-307 | A07:2021 - Identification and  | Requer autenticação e/ou ataque ativo | Adicionar ZAP autenticado/active scan na pipeline |
| Insecure CAPTCHA | web_application | CWE-804 | A07:2021 - Identification and  | Requer interação humana ou automação avançada | Fora do escopo do pipeline automatizado |
| Authorisation Bypass | web_application | CWE-639 | A01:2021 - Broken Access Contr | Requer autenticação e/ou ataque ativo | Adicionar ZAP autenticado/active scan na pipeline |
| Outdated OS | infrastructure | CWE-1104 | N/A | Detectada por Trivy | - |
| Outdated Packages | infrastructure | CWE-1104 | N/A | Detectada por Trivy | - |
| Default Credentials | infrastructure | CWE-798 | N/A | Requer brute force/login automatizado | Adicionar brute force (ex: hydra) na pipeline |


### Resumo da Cobertura

Cobertura do pipeline: **9/17** vulnerabilidades conhecidas detectadas (**52.9%**)

Principais motivos para não detecção:
- Detectada por Trivy
- Requer autenticação e/ou ataque ativo
- Requer brute force/login automatizado
- Requer interação humana ou automação avançada

Sugestões para aumentar a cobertura:
- Fora do escopo do pipeline automatizado
- Adicionar ZAP autenticado/active scan na pipeline
- Adicionar brute force (ex: hydra) na pipeline

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

4. **DAST OPERACIONAL**
   - OWASP ZAP executando com sucesso, detectando vulnerabilidades web
   - Headers de segurança ausentes identificados (CSP, X-Content-Type-Options)
   - Cookies sem flags de segurança detectados

### Eficácia do Pipeline


**PONTOS FORTES:**
- ✅ Detecção automatizada de milhares de vulnerabilidades
- ✅ Execução totalmente integrada ao CI/CD (Cloud Build)
- ✅ Múltiplas camadas de análise (Container, IaC, SCA, SAST, DAST)
- ✅ DAST funcional com OWASP ZAP detectando 18 tipos de vulnerabilidades
- ✅ Relatórios estruturados em JSON para análise
- ✅ Tempo de execução aceitável (~10-15 minutos)

**PONTOS DE MELHORIA:**
- ⚠️ Ausência de SAST para código PHP da aplicação
- ⚠️ Scan ZAP não autenticado (não testa áreas logadas)
- ⚠️ Dependency-Check (OWASP) desativado por performance

### Recomendações


**CURTO PRAZO:**
1. Implementar scan ZAP autenticado para testar vulnerabilidades em áreas logadas
2. Adicionar quality gates (falhar build em CVEs críticas)
3. Configurar alertas de segurança automáticos

**MÉDIO PRAZO:**
4. Adicionar SAST específico para PHP (PHPStan, Psalm)
5. Configurar NVD API key para OWASP Dependency-Check
6. Implementar scan de secrets (TruffleHog, GitLeaks)

**LONGO PRAZO:**
7. Integrar com plataforma de gestão de vulnerabilidades (DefectDojo, etc.)
8. Implementar fuzzing automatizado
9. Integrar com plataforma de gestão de vulnerabilidades

---

*Relatório gerado automaticamente em 16/12/2025 às 00:24:00*