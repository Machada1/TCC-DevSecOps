# Continuous Security Testing: A Case Study on Integrating Dynamic Security Testing Tools in CI/CD Pipelines

T. Rangnau, R. v. Buijtenen, F. Fransen and F. Turkmen, "Continuous Security Testing: A Case Study on Integrating Dynamic Security Testing Tools in CI/CD Pipelines," 2020 IEEE 24th International Enterprise Distributed Object Computing Conference (EDOC), Eindhoven, Netherlands, 2020, pp. 145-154, doi: 10.1109/EDOC49727.2020.00026.

# 1. Fichamento de Conteúdo

O artigo aborda a integração de testes dinâmicos de segurança (DAST) em pipelines CI/CD, uma área pouco explorada em comparação com testes estáticos (SAST). Os autores realizam um estudo de caso prático integrando três técnicas de DAST (WAST com ZAP, SAS com JMeter e BDST com SeleniumBase) em um pipeline GitLab CI usando Docker , tendo como alvo a aplicação vulnerável OWASP WebGoat. O estudo detalha a implementação, define oito requisitos para DAST em CI/CD (ex: tempo de build rápido) e analisa o desempenho. Embora a integração tenha detectado vulnerabilidades com sucesso , ela introduziu desafios significativos, principalmente relacionados à complexidade da conteinerização (sincronização, terminação) e ao tempo de execução. O trabalho conclui detalhando esses desafios práticos e propondo soluções, servindo como uma arquitetura de referência para equipes DevSecOps.

# 2. Fichamento Bibliográfico

* _WAST(Web Application Security Testing)_ (p.2): Uma técnica de DAST automatizada que ataca uma aplicação web através de sua interface de usuário. Geralmente inclui uma varredura "spider" (para descobrir URLs) e uma varredura "ativa" (para atacar os recursos encontrados) .

* _SAS(Security API Scanning)_ (p.2): Técnica para testar web services diretamente através de suas APIs , permitindo testes detalhados de endpoints para casos como autenticação, validação de entrada e manipulação de erros.

* _BDST(Behaviour Driven Security Testing)_ (p.3): Aplica os conceitos do BDD (Behaviour Driven Development) ao domínio de testes de segurança. Usa linguagem natural para definir testes, melhorando a colaboração entre especialistas de segurança e equipes DevOps.

* _OWASP ZAP(Zed Attack Proxy)_ (p.2, 4): Uma ferramenta open-source versátil recomendada pela OWASP para testes de segurança. Pode ser usada para scans automatizados (WAST) ou como um proxy para analisar tráfego de outras ferramentas (SAS, BDST).

# Fichamento de Citações

* _"However, classical security management techniques cannot keep up with this quick Software Development Life Cycle (SDLC)."_

* _"The new trend of DevSecOps aims to integrate security techniques into existing DevOps practices."_

* _"Additionally, most of the existing works cover only static code analysis and neglect dynamic testing methods."_

* _"The primary goal of this study is to identify the challenges and pitfalls of applying security testing of web applications and services in CI/CD pipelines."_

* _"Generally speaking, we found that many pitfalls in this area come from the isolated nature of containerized applications and therefore a fair amount of knowledge of tools like Docker and GitLab CI are required."_

* _"We believe that the interested DevSecOps teams can benefit from our work as they can use our approach as a reference architecture for dynamic testing in CI/CD pipelines..."_
