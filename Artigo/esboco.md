# Tema
Uma Abordagem DevSecOps para Inserção e Automação de Práticas de Segurança em Pipelines CI/CD

# Problema
Com a crescente adoção de pipelines de Integração Contínua e Entrega Contínua (CI/CD), as práticas de segurança de aplicação(AppSec) podem acabar sendo negligenciadas. Essa lacuna pode expor vulnerabilidades críticas durante as fases de build, teste e deploy.

O problema que esta pesquisa busca resolver se trata de: Como incorporar práticas de segurança de forma contínua e automatizada em pipelines?

# Objetivo geral
Investigar uma abordagem prática para a inserção e automação de práticas de segurança em pipelines CI/CD, alinhadas aos princípios de DevSecOps.

# Objetivos específicos
Os objetivos específicos são:
1. Mapear as vulnerabilidades mais comuns em pipelines CI/CD.
2. Identificar ferramentas e técnicas de segurança aplicáveis a cada etapa do pipeline (build, test, deploy).
3. Avaliar estratégias de automação de segurança integradas a pipelines como SAST, DAST, SCA e IaC scanning.

## Metodologia  

A pesquisa seguirá uma **abordagem experimental**, com foco na **implementação prática** de ferramentas e técnicas DevSecOps em um ambiente controlado.  

As etapas metodológicas incluem:  

### 1. Revisão bibliográfica  
Levantamento e análise de artigos acadêmicos e publicações técnicas disponíveis na base **IEEE**, incluindo:  

- *“Implementing and Automating Security Scanning to a DevSecOps CI/CD Pipeline”* (IEEE, documento 10235015);  
- *“Integrating Security with DevSecOps: Techniques and Challenges”* (IEEE, documento 9105789);  

### 2. Mapeamento de vulnerabilidades e riscos  
Identificação das vulnerabilidades mais comuns nas diferentes etapas do pipeline (**build**, **test**, **deploy**), com base nas referências estudadas e em frameworks reconhecidos como **OWASP** e **NIST**.  

### 3. Seleção e implementação de ferramentas  
A etapa de implementação ocorrerá em um ambiente **Google Cloud Platform (GCP)**, utilizando o **Cloud Build** como orquestrador do pipeline CI/CD.  

O provisionamento do ambiente será realizado com **Terraform**, garantindo que o **cluster GKE**, o **Artifact Registry** e demais recursos necessários estejam configurados de forma automatizada e reproduzível.  

O pipeline será projetado para integrar práticas automatizadas de segurança nas etapas de build, teste e deploy, utilizando ferramentas complementares:  

- **SAST (Static Application Security Testing):** Semgrep;  
- **DAST (Dynamic Application Security Testing):** OWASP ZAP;  
- **SCA (Software Composition Analysis):** Dependency-Check;  
- **IaC Scanning:** Checkov.  

As imagens de contêiner serão armazenadas no **Artifact Registry**, e o deploy será automatizado em um cluster **Google Kubernetes Engine (GKE)** provisionado via Terraform.  
Dessa forma, será possível avaliar como cada ferramenta se integra ao ciclo de desenvolvimento e como o Cloud Build pode automatizar a execução dessas verificações de segurança.  


### 4. Execução e coleta de resultados  
Será implementado um **aplicativo simples** (como uma aplicação web em Python ou Node.js) para servir como base de teste.  
Esse aplicativo passará por todo o ciclo do pipeline, incluindo build, testes, análise de segurança, e deploy automatizado no GKE provisionado via Terraform.  

Durante a execução, serão observados:  

- **Tipos e quantidade de vulnerabilidades** detectadas por etapa (SAST, DAST, SCA, IaC);  
- **Efetividade das integrações** no pipeline do Cloud Build;  
- **Impacto das práticas automatizadas de segurança** sobre o processo de entrega;  
- **Fluxo de deploy contínuo** do Cloud Build para o GKE, validando o funcionamento de ponta a ponta.  

Os resultados obtidos serão analisados qualitativamente, destacando os benefícios práticos e as boas práticas observadas na integração das práticas DevSecOps em pipelines CI/CD baseados em GCP com provisionamento via Terraform.

### 5. Análise e validação  
Os resultados obtidos serão analisados de forma **qualitativa**, focando em:  

- A **efetividade da integração** das ferramentas de segurança no pipeline CI/CD;  
- O **nível de automação** alcançado para a detecção de vulnerabilidades;  
- As **boas práticas observadas** na implementação de DevSecOps em um ambiente GCP provisionado via Terraform;  
- Lições aprendidas sobre a **detecção e mitigação de vulnerabilidades** em cada etapa do pipeline.  

Essa análise permitirá avaliar como a abordagem proposta contribui para aumentar a segurança das aplicações, sem comprometer o fluxo de entrega automatizado.
