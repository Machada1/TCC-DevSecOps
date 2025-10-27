# An Empirical Study of DevSecOps Focused on Continuous Security Testing

C. Feio, N. Santos, N. Escravana and B. Pacheco, "An Empirical Study of DevSecOps Focused on Continuous Security Testing," 2024 IEEE European Symposium on Security and Privacy Workshops (EuroS&PW), Vienna, Austria, 2024, pp. 610-617, doi: 10.1109/EuroSPW61312.2024.00074.

## 1. Fichamento de Conteúdo

O artigo propõe um framework DevSecOps focado em testes contínuos de segurança. Baseado em uma revisão de literatura, os autores definem um pipeline CI/CD ideal de oito fases (Plan, Code, Build, Test, Release, Deploy, Operate, Monitor) , identificam atividades de segurança (como SAST, DAST e SCA) para cada etapa e selecionam ferramentas open-source para automação. O framework foi aplicado em um estudo de caso (Projeto GRACE) , que utilizava um pipeline DevOps de quatro fases. Os autores adaptaram o projeto adicionando uma fase de Teste e integrando ferramentas como SonarQube, Dependency-Check e OWASP ZAP. A implementação foi bem-sucedida, detectando 1795 vulnerabilidades (muitas de dependências desatualizadas) e recebendo feedback positivo dos desenvolvedores.

## 2. Fichamento Bibliográfico

* _DevSecOps_ (p.1): Uma abordagem que integra práticas de segurança robustas ao processo DevOps, focando em quebrar os silos entre as equipes de desenvolvimento, segurança e operações.

* _"Shift-left" approach_ (p.1): Estratégia central do DevSecOps que consiste em integrar medidas de segurança e automação desde o início do ciclo de vida do desenvolvimento (SDLC), em vez de deixá-las para o final.

* _Continuous Security Testing_ (p.1, 3): Um princípio focado no teste de segurança do software e seus componentes ao longo de todo o pipeline CI/CD. Destaca-se pela capacidade de automação sem prejudicar a agilidade do processo.

* _SCA(Software Composition Analysis)_ (p.4): Atividade de segurança que avalia se componentes de terceiros ou open-source (OSS) no projeto contêm vulnerabilidades conhecidas.

## 3. Fichamento de Citações 

* _"...the primary concern being the perception of security as a bottleneck that slows down the speed and agility inherent to DevOps processes."_

* _"Specifically, DevSecOps aims to integrate security measures and automate security practices from the project's inception, adopting a 'shift-left' approach."_

* _"In this paper, we present a DevSecOps framework centered on the principle of continuous security testing, applicable across various software development scenarios."-_

* _"Automation plays a central role in attaining the agility and speed essential for DevSecOps."_

* _"A contributing factor to the large number of vulnerabilities (1795 across all projects) is the lack of updates to many dependencies since the beginning of the project over three years ago."_

* _"The developers found the tools useful and are willing to use them in future projects."_
