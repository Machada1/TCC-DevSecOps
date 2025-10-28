# Uma Abordagem DevSecOps para Inserção e Automação de Práticas de Segurança em Pipelines CI/CD

1. Guilherme Henrique de Lima Machado

* [Lesandro Ponciano](https://orcid.org/0000-0002-5724-0094)

## Introdução

1. A área da Engenharia de Software tratada neste trabalho é: Integração de Segurança no Ciclo de Vida de Desenvolvimento de Software (Secure SDLC / DevSecOps)
2. O problema que este trabalho busca resolver nessa área é: Como incorporar práticas de segurança de forma contínua e automatizada em pipelines CI/CD?

3. Resolver este problema é relevante porque a segurança ainda é tratada tardiamente no ciclo de desenvolvimento, gerando vulnerabilidades e retrabalho. Integrá-la de forma contínua e automatizada aumenta a confiabilidade e reduz riscos nas entregas de software.
4. O objetivo geral deste trabalho é investigar uma abordagem prática para a inserção e automação de práticas de segurança em pipelines CI/CD, alinhadas aos princípios de DevSecOps.
5. Os *três* objetivos específicos deste trabalho são:
  
- Integrar práticas de segurança em um pipeline CI/CD.
-  Aplicar ferramentas automatizadas de segurança em um pipeline experimental.
-  Aliar estratégias de automação de segurança integradas a pipelines como SAST, DAST, SCA e IaC scanning.


## Fundamentação Teórica

1. O conceito/teoria principal associado a este trabalho é DevSecOps. A sua definição neste trabalho é uma abordagem emergente para integrar segurança robusta ao processo de desenvolvimento de software DevOps, focando em quebrar os silos entre desenvolvimento, segurança e operações , conforme definido no trabalho _"An Empirical Study of DevSecOps Focused on Continuous Security Testing"_ pelos autores Santos, Escravana, Pacheco e Feio.
   
2. O conceito/teoria secundário associado a este trabalho é Continuous Security Testing (Teste Contínuo de Segurança). A sua definição neste trabalho é o princípio de aplicar o teste de segurança do software e seus componentes de forma contínua ao longo de todo o pipeline CI/CD, permitindo que as equipes de segurança acompanhem a velocidade do DevOps , conforme definido no trabalho _"Continuous Security Testing: A Case Study on Integrating Dynamic Security Testing Tools in CI/CD Pipelines"_ pelos autores Rangnau, v. Buijtenen, Fransen e Turkmen.

3. O conceito/teoria terciário associado a este trabalho é CI/CD Pipeline (Pipeline de Integração e Entrega Contínua). A sua definição neste trabalho é o componente central do DevSecOps, composto por um conjunto de fases consecutivas que definem várias atividades e ferramentas para auxiliar na automação do desenvolvimento de software , conforme definido no trabalho _"An Empirical Study of DevSecOps Focused on Continuous Security Testing"_ pelos autores Santos, Escravana, Pacheco e Feio .

## Trabalhos Relacionados

1. O trabalho mais relacionado é _"An Empirical Study of DevSecOps Focused on Continuous Security Testing"_ , publicado em 2024, porque propõe um framework completo de DevSecOps, define um pipeline de oito fases e aplica um estudo de caso real (Projeto GRACE) integrando múltiplas ferramentas para SAST, DAST e SCA (Software Composition Analysis). A abordagem de aplicar um framework experimental a um projeto real, analisando ferramentas e resultados, é diretamente alinhada aos objetivos deste trabalho.
2. O segundo trabalho mais relacionado é _"Implementation of DevSecOps by Integrating Static and Dynamic Security Testing in CI/CD Pipelines"_, publicado em 2022, porque apresenta uma implementação prática que combina especificamente testes de segurança estáticos (SAST) e dinâmicos (DAST) em um pipeline CI/CD , demonstrando a automação com GitLab e Docker e medindo o impacto na redução do tempo de deploy.
3. O terceiro trabalho mais relacionado é _"Implementing and Automating Security Scanning to a DevSecOps CI/CD Pipeline"_, publicado em 2023, porque foca na implementação e automação de varreduras de segurança (SAST e DAST) usando ferramentas específicas (Snyk e StackHawk) em um pipeline CI/CD com GitHub Actions. O foco na integração de ferramentas e no monitoramento de resultados por dashboards é central para os objetivos práticos desta pesquisa.
4. O quarto trabalho mais relacionado é _"Continuous Security Testing: A Case Study on Integrating Dynamic Security Testing Tools in CI/CD Pipelines"_, publicado em 2020, porque realiza um estudo de caso focado exclusivamente na integração de múltiplas técnicas de DAST (WAST, SAS e BDST). Ele fornece uma análise detalhada dos desafios técnicos, do overhead (tempo de execução) e dos requisitos para automatizar testes dinâmicos, o que é muito relevante para os objetivos específicos deste trabalho.
5. O quinto trabalho mais relacionado é _"Integrating Security with DevSecOps: Techniques and Challenges"_, publicado em 2019, porque, apesar de menos técnico, discute os desafios culturais e de processo ao introduzir a segurança em um pipeline DevOps existente. Ele fornece o contexto sobre por que o DevSecOps é necessário e relata um caso de integração da ferramenta Snyk para verificação de dependências (SCA).

## Materiais e Métodos

1. O tipo de pesquisa adotado neste trabalho é Experimental, porque envolve a criação de um ambiente controlado (GCP provisionado via Terraform) e a implementação de um pipeline CI/CD (Cloud Build) com uma aplicação-alvo intencionalmente vulnerável (DVWA). Este ambiente será usado para executar experimentos (automação de SAST, DAST, etc.) e, em seguida, analisar os resultados para validação da abordagem.
  
2. Os materiais utilizados neste trabalho são:
   
- Plataforma de Nuvem: Google Cloud Platform (GCP), incluindo Cloud Build, Artifact Registry, Google Kubernetes Engine (GKE) e Cloud Storage (GCS).
- Software de Infraestrutura como Código: Terraform (>= 1.5).
- Software de Base: Google Cloud SDK, Docker.
- Aplicação-Alvo para Testes: DVWA (Damn Vulnerable Web Application).
- Ferramentas de Segurança: Semgrep (SAST), OWASP Dependency-Check (SCA), Checkov (IaC Scan), Trivy (Container Scan) e OWASP ZAP (DAST).

3. Os métodos empregados neste trabalho são a Análise Qualitativa, focando na efetividade da integração das ferramentas, no nível de automação alcançado e nas boas práticas observadas na implementação de DevSecOps.
   
4. As métricas de avaliação são qualitativas, baseadas na análise dos relatórios (.json e .html) gerados pelas ferramentas de segurança. A avaliação foca em:

- Efetividade da integração das ferramentas no pipeline.
- Nível de automação alcançado na detecção de vulnerabilidades.
- Boas práticas observadas na implementação de DevSecOps.
- Detecção e mitigação de vulnerabilidades em cada etapa do pipeline.
   
5. As etapas de execução do trabalho são:

    1 - Provisionamento do Ambiente: Criação automática da infraestrutura na GCP (VPC, GKE, Artifact Registry, GCS Bucket) usando Terraform.

    2 - Configuração do Pipeline: Definição das etapas de segurança (SAST, SCA, IaC Scan, Container Scan, DAST) e deploy no arquivo cloudbuild.yaml.

    3 - Execução do Pipeline: Disparo do build no Cloud Build para executar o pipeline contra a aplicação-alvo (DVWA).

    4 - Avaliação dos Resultados: Coleta e análise qualitativa dos relatórios de segurança gerados automaticamente e armazenados no bucket GCS.
