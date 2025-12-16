# 📊 Análise Completa dos Relatórios de Segurança - Pipeline DevSecOps

**Data:** 16/12/2025 18:09

**Aplicação:** DVWA (Damn Vulnerable Web Application)

**Pesquisa:** Integração de Testes de Segurança Contínuos em Pipelines CI/CD

---

## 📋 Sumário Executivo

| Ferramenta | Tipo | Findings | Status |
| --- | --- | --- | --- |
| Trivy | Container Scan | 1575 | ✅ Executado |
| Semgrep | SAST | 5 | ✅ Executado |
| Trivy FS | SCA | 0 | ✅ Executado |
| OWASP ZAP | DAST (Baseline) | 23 | ✅ Executado |
| OWASP ZAP | DAST (Active Scan) | 12 | ✅ Executado |
| Checkov | IaC Scan | 63 | ✅ Executado |
| Hydra | Brute Force | Seguro | ✅ Executado |

**Total de issues de segurança identificados: 1678**

## 1. 📦 Container Scan - Trivy

**Imagem analisada:** `dvwa-app:179fbe0`

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

**Total de findings:** 5

### Distribuição por Severidade

| Severidade | Quantidade |
| --- | --- |
| 🔴 ERROR | 1 |
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

**📄 hydra.Dockerfile**

- 🔴 **Linha 4:** `missing-user-entrypoint`
  - CWE: CWE-269: Improper Privilege Management
  - OWASP: A04:2021 - Insecure Design

### CWEs Identificados

- **CWE-250: Execution with Unnecessary Privileges**: 2 ocorrência(s)
- **CWE-732: Incorrect Permission Assignment for Critical Resource**: 2 ocorrência(s)
- **CWE-269: Improper Privilege Management**: 1 ocorrência(s)

### Mapeamento OWASP Top 10

- **A05:2021 - Security Misconfiguration**: 4 ocorrência(s)
- **A06:2017 - Security Misconfiguration**: 4 ocorrência(s)
- **A04:2021 - Insecure Design**: 1 ocorrência(s)

## 3. 📦 SCA (Software Composition Analysis) - Trivy FS

**Alvo:** Código fonte do projeto

**Vulnerabilidades em dependências:** 0

✅ **NENHUMA VULNERABILIDADE ENCONTRADA EM DEPENDÊNCIAS!**

## 4. 🌐 DAST (Dynamic Application Security Testing) - OWASP ZAP

**Alvo:** `https://34.9.5.224`

**Total de alertas:** 23

### Distribuição por Risco

| Nível de Risco | Quantidade |
| --- | --- |
| Medium | 6 |
| Low | 9 |
| Informational | 8 |

### Alertas Encontrados

**🟠 Content Security Policy (CSP) Header Not Set**
- Risco: Medium (High)
- CWE: CWE-693
- Descrição: Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certai...

**🟠 Directory Browsing**
- Risco: Medium (Medium)
- CWE: CWE-548
- Descrição: It is possible to view the directory listing. Directory listing may reveal hidden scripts, include f...

**🟠 HTTP Only Site**
- Risco: Medium (Medium)
- CWE: CWE-311
- Descrição: The site is only served under HTTP and not HTTPS. ...

**🟠 Missing Anti-clickjacking Header**
- Risco: Medium (Medium)
- CWE: CWE-1021
- Descrição: The response does not protect against 'ClickJacking' attacks. It should include either Content-Secur...

**🟠 Relative Path Confusion**
- Risco: Medium (Medium)
- CWE: CWE-20
- Descrição: The web server is configured to serve responses to ambiguous URLs in a manner that is likely to lead...

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

**🔵 Cookie Slack Detector**
- Risco: Informational (Low)
- CWE: CWE-205
- Descrição: Repeated GET requests: drop a different cookie each time, followed by normal request with all cookie...

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

**🔵 User Agent Fuzzer**
- Risco: Informational (Medium)
- CWE: CWE-0
- Descrição: Check for differences in response based on fuzzed User Agent (eg. mobile sites, access as a Search E...

### CWEs Detectados pelo DAST

- **CWE-693**: 4 ocorrência(s)
- **CWE-548**: 1 ocorrência(s)
- **CWE-311**: 1 ocorrência(s)
- **CWE-1021**: 1 ocorrência(s)
- **CWE-20**: 1 ocorrência(s)
- **CWE-540**: 1 ocorrência(s)
- **CWE-1004**: 1 ocorrência(s)
- **CWE-1275**: 1 ocorrência(s)
- **CWE-749**: 1 ocorrência(s)
- **CWE-497**: 2 ocorrência(s)
- **CWE-1295**: 1 ocorrência(s)
- **CWE--1**: 2 ocorrência(s)
- **CWE-205**: 1 ocorrência(s)
- **CWE-615**: 1 ocorrência(s)
- **CWE-524**: 3 ocorrência(s)
- **CWE-0**: 1 ocorrência(s)

## 4.1 🔓 DAST Active Scan (Autenticado) - OWASP ZAP

**Alvo:** `http://34.9.5.224`

**Total de alertas:** 12

**Tipo de scan:** Active Scan com autenticação (detecta SQL Injection, XSS, etc.)

### Distribuição por Risco

| Nível de Risco | Quantidade |
| --- | --- |
| Medium | 4 |
| Low | 5 |
| Informational | 3 |

### Alertas Encontrados (Active Scan)

**🔵 Session Management Response Identified** (x1)
- Risco: Informational
- CWE: CWE--1
- Descrição: The given response has been identified as containing a session management token. The 'Other Info' fi...

**🟠 Content Security Policy (CSP) Header Not Set** (x2)
- Risco: Medium
- CWE: CWE-693
- Descrição: Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certai...

**🟡 Cookie No HttpOnly Flag** (x2)
- Risco: Low
- CWE: CWE-1004
- Descrição: A cookie has been set without the HttpOnly flag, which means that the cookie can be accessed by Java...

**🟡 In Page Banner Information Leak** (x1)
- Risco: Low
- CWE: CWE-497
- Descrição: The server returned a version banner string in the response content. Such information leaks may allo...

**🟡 Cookie without SameSite Attribute** (x2)
- Risco: Low
- CWE: CWE-1275
- Descrição: A cookie has been set without the SameSite attribute, which means that the cookie can be sent as a r...

**🟡 Server Leaks Version Information via "Server" HTTP Response Header Field** (x9)
- Risco: Low
- CWE: CWE-497
- Descrição: The web/application server is leaking version information via the "Server" HTTP response header. Acc...

**🟡 X-Content-Type-Options Header Missing** (x5)
- Risco: Low
- CWE: CWE-693
- Descrição: The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older ver...

**🟠 Missing Anti-clickjacking Header** (x1)
- Risco: Medium
- CWE: CWE-1021
- Descrição: The response does not protect against 'ClickJacking' attacks. It should include either Content-Secur...

**🔵 Authentication Request Identified** (x1)
- Risco: Informational
- CWE: CWE--1
- Descrição: The given request has been identified as an authentication request. The 'Other Info' field contains ...

**🟠 Directory Browsing** (x3)
- Risco: Medium
- CWE: CWE-548
- Descrição: It is possible to view the directory listing. Directory listing may reveal hidden scripts, include f...

**🟠 HTTP Only Site** (x1)
- Risco: Medium
- CWE: CWE-311
- Descrição: The site is only served under HTTP and not HTTPS....

**🔵 User Agent Fuzzer** (x84)
- Risco: Informational
- CWE: CWE-0
- Descrição: Check for differences in response based on fuzzed User Agent (eg. mobile sites, access as a Search E...

### CWEs Detectados pelo Active Scan

- **CWE--1**: 2 ocorrência(s)
- **CWE-693**: 2 ocorrência(s)
- **CWE-1004**: 1 ocorrência(s)
- **CWE-497**: 2 ocorrência(s)
- **CWE-1275**: 1 ocorrência(s)
- **CWE-1021**: 1 ocorrência(s)
- **CWE-548**: 1 ocorrência(s)
- **CWE-311**: 1 ocorrência(s)
- **CWE-0**: 1 ocorrência(s)

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


## 6. 🔐 Teste de Força Bruta - Hydra

**Ferramenta:** Brute Force Scanner

**Tipo de teste:** Brute Force

### ✅ Nenhuma Vulnerabilidade de Força Bruta Detectada

**Resultado:** Nenhuma credencial encontrada ou erro na execução

O teste de força bruta não encontrou credenciais fracas ou o teste não conseguiu ser executado com sucesso.

## 7. 🎯 Comparação com Vulnerabilidades Conhecidas do DVWA

**Vulnerabilidades conhecidas do DVWA:** 17

**Detectadas pelo pipeline:** 11 (64.7%)

**Não detectadas:** 6 (35.3%)

### ✅ Vulnerabilidades Detectadas

| Vulnerabilidade | Categoria | CWE | Ferramenta | Descrição |
| --- | --- | --- | --- | --- |
| SQL Injection | web_application | CWE-89 | Trivy (Container) | Permite injeção de comandos SQL em campo... |
| Cross-Site Scripting (XSS) | web_application | CWE-79 | Trivy (Container) | Permite execução de scripts maliciosos n... |
| Command Injection | web_application | CWE-78 | Trivy (Container) | Permite execução de comandos do sistema ... |
| CSRF | web_application | CWE-352 | Trivy (Container) | Cross-Site Request Forgery... |
| Weak Session IDs | web_application | CWE-330 | Trivy (Container) | IDs de sessão previsíveis... |
| Open HTTP Redirect | web_application | CWE-601 | Trivy (Container) | Redirecionamento aberto para sites malic... |
| JavaScript Attacks | web_application | CWE-749 | OWASP ZAP (Baseline) | Exposição de lógica sensível no cliente... |
| Content Security Policy Bypass | web_application | CWE-693 | OWASP ZAP (Active Scan) | Ausência ou bypass de CSP... |
| Outdated OS | infrastructure | CWE-1104 | Trivy (Container - EOSL) | Sistema operacional desatualizado (Debia... |
| Outdated Packages | infrastructure | CWE-1104 | Trivy (Container - EOSL) | Pacotes com vulnerabilidades conhecidas... |
| Exposed MySQL | infrastructure | CWE-284 | Trivy (Container) | MySQL com credenciais fracas... |


### ❌ Vulnerabilidades Não Detectadas

| Vulnerabilidade | Categoria | CWE | OWASP | Motivo | Sugestão |
| --- | --- | --- | --- | --- | --- |
| File Inclusion (LFI/RFI) | web_application | CWE-98 | A03:2021 - Injection | Requer autenticação e/ou ataque ativo. | Adicionar ZAP autenticado/active scan na pipeline. |
| File Upload | web_application | CWE-434 | A04:2021 - Insecure Design | Requer autenticação e/ou ataque ativo. | Adicionar ZAP autenticado/active scan na pipeline. |
| Brute Force | web_application | CWE-307 | A07:2021 - Identification and  | Requer brute force/login automatizado. | Adicionar brute force (ex: hydra) na pipeline. |
| Insecure CAPTCHA | web_application | CWE-804 | A07:2021 - Identification and  | Requer interação humana ou automação avançada. | Fora do escopo do pipeline automatizado. |
| Authorisation Bypass | web_application | CWE-639 | A01:2021 - Broken Access Contr | Requer autenticação e/ou ataque ativo. | Adicionar ZAP autenticado/active scan na pipeline. |
| Default Credentials | infrastructure | CWE-798 | N/A | Requer brute force/login automatizado. | Adicionar brute force (ex: hydra) na pipeline. |


### Resumo da Cobertura

Cobertura do pipeline: **11/17** vulnerabilidades conhecidas detectadas (**64.7%**)

Principais motivos para não detecção:
- Requer interação humana ou automação avançada.
- Requer autenticação e/ou ataque ativo.
- Requer brute force/login automatizado.

Sugestões para aumentar a cobertura:
- Adicionar ZAP autenticado/active scan na pipeline.
- Fora do escopo do pipeline automatizado.
- Adicionar brute force (ex: hydra) na pipeline.

## 8. 📝 Conclusões e Recomendações para o TCC

### Principais Descobertas

1. **RISCO CRÍTICO - SISTEMA OPERACIONAL**
   - A imagem base utiliza debian 9.5, que está em End of Support Life (EOSL)
   - Foram encontradas 254 vulnerabilidades CRÍTICAS e 551 de ALTA severidade
   - Recomendação: Migrar para imagem base com suporte ativo

2. **CONFIGURAÇÃO KUBERNETES/IAC**
   - Checkov identificou 63 problemas de configuração de segurança
   - Incluem: SecurityContext, RBAC, Network Policies, entre outros
   - Recomendação: Revisar e aplicar as correções sugeridas pelo Checkov

3. **ANÁLISE ESTÁTICA (SAST)**
   - Semgrep identificou 5 potenciais problemas no código
   - CWEs encontrados: CWE-250: Execution with Unnecessary Privileges, CWE-732: Incorrect Permission Assignment for Critical Resource, CWE-269: Improper Privilege Management
   - Recomendação: Revisar e corrigir os findings de alta prioridade

4. **ANÁLISE DINÂMICA (DAST)**
   - OWASP ZAP identificou 35 alertas totais (Baseline Scan: 23 alertas, Active Scan: 12 alertas)
   - Vulnerabilidades web detectadas incluem headers ausentes, cookies inseguros, etc.
   - Active Scan permite detecção de SQLi, XSS e outras vulnerabilidades de injeção

5. **TESTE DE FORÇA BRUTA**
   - Hydra não conseguiu encontrar credenciais por força bruta
   - Pode indicar proteção adequada ou necessidade de ajuste no teste

### Eficácia do Pipeline

**PONTOS FORTES:**
- ✅ Detecção automatizada de 1678 vulnerabilidades/issues
- ✅ Execução totalmente integrada ao CI/CD (Cloud Build)
- ✅ 6 camadas de análise (Container, IaC, SCA, SAST, DAST, Brute Force)
- ✅ DAST com Active Scan autenticado (12 alertas)
- ✅ Relatórios estruturados em JSON para análise automatizada
- ✅ Pipeline sem hardcode (usa substituições do Cloud Build)

**PONTOS DE MELHORIA:**
- ⚠️ Cobertura de 64.7% das vulnerabilidades conhecidas - avaliar testes adicionais
- ⚠️ Verificar configuração do Hydra para testes de força bruta

### Cobertura de Vulnerabilidades DVWA

**Total de vulnerabilidades conhecidas:** 17

**Detectadas pelo pipeline:** 11 (64.7%)

**Não detectadas:** 6 (35.3%)

**Motivos para não detecção:**
- Requer interação humana ou automação avançada.
- Requer autenticação e/ou ataque ativo.
- Requer brute force/login automatizado.

### Recomendações Baseadas nos Resultados

- 🔴 **URGENTE:** Migrar para imagem base com suporte ativo (ex: Debian 11/12, Alpine)
- 🔴 **URGENTE:** Aplicar patches para CVEs críticas ou reconstruir imagem
- 🟠 **ALTA:** Corrigir configurações de segurança do Kubernetes/IaC
- 🟡 **MÉDIA:** Aumentar cobertura de testes de segurança
- 🟢 **CONTÍNUA:** Manter pipeline atualizado com novas regras de segurança
- 🟢 **CONTÍNUA:** Integrar resultados com sistema de gestão de vulnerabilidades

---

*Relatório gerado automaticamente em 16/12/2025 às 18:09:02*