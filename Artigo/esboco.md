# Tema
Uma Abordagem DevSecOps para Inserção e Automação de Práticas de Segurança em Pipelines CI/CD

# Problema
Com a crescente adoção de pipelines de Integração Contínua e Entrega Contínua (CI/CD), as práticas de segurança de aplicação(AppSec) podem acabar sendo negligenciadas. Essa lacuna pode expor vulnerabilidades críticas durante as fases de build, teste e deploy.

O problema central dessa pesquisa é: Como incorporar práticas de segurança de forma contínua e automatizada em pipelines?

# Objetivo geral
Investigar uma abordagem prática para a inserção e automação de práticas de segurança em pipelines CI/CD, alinhadas aos princípios de DevSecOps.

# Objetivos específicos
Os objetivos específicos são:
1. Integrar práticas de segurança em um pipeline CI/CD.
2. Aplicar ferramentas automatizadas de segurança em um pipeline experimental. 
3. Avaliar estratégias de automação de segurança integradas a pipelines como SAST, DAST, SCA e IaC scanning.

## Metodologia  

A pesquisa seguirá uma **abordagem experimental**, com foco na **implementação prática** de ferramentas e técnicas DevSecOps em um ambiente controlado.  

O ambiente será provisionado via **Terraform**, incluindo uma rede, um repositório de artefatos e um cluster Kubernetes (GKE).  
Em seguida, será configurado um pipeline **CI/CD com o Cloud Build**, no qual serão integradas ferramentas automatizadas de análise de segurança de código, dependências e infraestrutura.  

Uma aplicação **DVWA(Damn Vulnerable Web Application)** será utilizada como base para os testes. O pipeline executará o build, as análises de segurança e o deploy automatizado no GKE.  

Os resultados serão analisados de forma **qualitativa**, considerando a capacidade das ferramentas em detectar vulnerabilidades e o nível de automação alcançado.  
A proposta busca demonstrar como práticas DevSecOps podem ser implementadas de forma eficiente e reproduzível em pipelines CI/CD.
