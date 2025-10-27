# Implementation of DevSecOps by Integrating Static and Dynamic Security Testing in CI/CD Pipelines

A. M. Putra and H. Kabetta, "Implementation of DevSecOps by Integrating Static and Dynamic Security Testing in CI/CD Pipelines," 2022 IEEE International Conference of Computer Science and Information Technology (ICOSNIKOM), Laguboti, North Sumatra, Indonesia, 2022, pp. 1-6, doi: 10.1109/ICOSNIKOM56551.2022.10034883.

## 1. Fichamento de Conteúdo

O artigo propõe a implementação prática de um pipeline DevSecOps em um ambiente Agile, integrando testes de segurança estáticos(SAST) e dinâmicos(DAST) automatizados em todas as etapas de desenvolvimento. O estudo busca resolver os problemas comuns de lentidão e inconsistência nas fases de build, teste e deploy, que atrasam entregas em ciclos ágeis. Utilizando as ferramentas GitLab CI/CD e Docker, os autores desenvolveram um processo composto por cinco estágios: *Continuous Development, Continuous Testing, Continuous Integration, Continuous Deployment* e *Continuous Monitoring*. Foram aplicadas as ferramentas Njsscan para análise estática e OWASP ZAP para análise dinâmica, integradas de forma automática ao pipeline. O sistema foi testado em uma aplicação web desenvolvida nas linguagens Node.js e Dart e utiliando os frameworks Express.js e Flutter. Os resultados demonstram que o tempo de implantação foi reduzido de várias horas para apenas 3 a 4 minutos, e que a automação dos testes permitiu identificar vulnerabilidades como CWE-327 e OWASP A9. O estudo conclui que a integração de segurança automatizada ao DevOps aumenta a eficiência e garante entregas mais seguras, além de propor o uso de dashboards para monitoramento contínuo do desempenho e da segurança.

## 2. Fichamento Bibliográfico 

* _OWASP (Open Web Application Security Project)_ (p.2): rganização global sem fins lucrativos dedicada à melhoria da segurança de aplicações. Ela fornece diretrizes, ferramentas e padrões amplamente utilizados, como o OWASP Top 10, que lista as principais vulnerabilidades em sistemas web. Entre suas ferramentas, destaca-se o OWASP ZAP, usada para testes dinâmicos de segurança (DAST), e o item OWASP A9, que alerta para o risco de usar componentes com vulnerabilidades conhecidas.  
* _SAST & DAST_ (p.4): SAST(Static Application Security Testing) é a análise do código-fonte para identificar vulnerabilidades antes da execução do sistema. O **Njsscan** é usado para testes estáticos automatizados, analisando o código-fonte em busca de vulnerabilidades conhecidas; DAST (Dynamic Application Security Testing) são testes de segurança realizados com o sistema em execução, simulando ataques externos para detectar falhas exploráveis. O **OWASP ZAP** realiza testes dinâmicos simulando ataques a endpoints públicos.  
* _Continuous Testing_ (p.5): Possibilitou detectar falhas como o uso de algoritmos criptográficos inseguros (CWE-327) e componentes vulneráveis (OWASP A9).  
* _Continuous Integration_ (p.5): O pipeline é executado em uma instância, com containers Docker configurados e integrados ao repositório GitLab para execução automática dos jobs.  

## 3. Fichamento de Citações 

* _"DevSecOps aims to integrate security controls and processes into the DevOps software development life cycle with collaboration among the security, development, and operations teams."_

* _"Static testing is performed by automating the NJSSCAN tools, whereas dynamic testing is performed by automating the OWASP ZAP tools."_

* _"The deployment process that used to take 2–3 hours now only takes 3–4 minutes after automation was applied."_

* _"It can be seen that there is a security gap based on CWE-327, namely the Use of a Broken or Risky Cryptographic Algorithm, which can result in the disclosure of sensitive information."_

* _"The combination of automated static and dynamic security testing performed in a DevSecOps implementation can help ensure system security."_

* _"Real-time test results can quickly notify developers about security holes or vulnerabilities in the program so that repairs can be made as soon as possible to improve system security."_
