# Implementing and Automating Security Scanning to a DevSecOps CI/CD Pipeline

M. Marandi, A. Bertia and S. Silas, "Implementing and Automating Security Scanning to a DevSecOps CI/CD Pipeline," 2023 World Conference on Communication & Computing (WCONF), RAIPUR, India, 2023, pp. 1-6, doi: 10.1109/WCONF58270.2023.10235015.

## 1. Fichamento de Conteúdo

O artigo propõe uma abordagem prática para automatizar o processo de verificação de segurança em pipelines DevSecOps utilizando as ferramentas **Snyk** (para SAST) e **StackHawk** (para DAST). O trabalho contextualiza o avanço das práticas de DevOps e o uso crescente de containerização como parte da integração e entrega contínuas (CI/CD), destacando os desafios de segurança associados a esse novo modelo. Após uma revisão da literatura sobre práticas e ferramentas DevSecOps, os autores apresentam uma metodologia para integrar varreduras automáticas de vulnerabilidades em diferentes etapas do pipeline, incluindo o uso de dashboards que oferecem monitoramento em tempo real das falhas detectadas. A implementação foi conduzida em um ambiente baseado no GitHub Actions, com Docker e uma aplicação vulnerável (DVWA) como alvo dos testes. Os resultados indicam que a automação reduziu o tempo de detecção e correção de falhas, elevando a eficiência do processo e fortalecendo a segurança geral do ciclo de desenvolvimento. A pesquisa reforça a importância da integração contínua de segurança e sugere, como trabalho futuro, a inclusão de outras técnicas como fuzz testing e behavioral analysis para ampliar a cobertura de segurança.

## 2. Fichamento Bibliográfico 

* _DVWA (DAMN VULNERABLE WEB APPLICATION)_ (p.3): É uma aplicação projetada como um website vulnerável e foi criado para fins educacionais e para teste de ferramentas de segurança.
* _DevSecOps_ (p.1): É a integração de práticas de segurança em todas as fases do ciclo de vida do software, com o objetivo de reduzir riscos e detectar vulnerabilidades o mais cedo possível no processo de desenvolvimento.  
* _SAST (Static Application Security Testing)_ (p.2): Técnica que analisa o código-fonte em busca de vulnerabilidades antes da execução da aplicação, permitindo correções antecipadas.  
* _DAST (Dynamic Application Security Testing)_ (p.2): Técnica que testa a aplicação em execução para identificar vulnerabilidades reais e falhas de segurança dinâmicas.  
* _Snyk & StackHawk Tools_ (p.3): Snyk é uma ferramenta de segurança que atua em código e contêineres, com correção automática e integração ao pipeline CI/CD. StackHawk é outra ferramenta de segurança que foca em testes dinâmicos e relatórios de vulnerabilidades com ações corretivas sugeridas.  
* _DevSecOps Pipeline_ (p.3): Segue as fases *Plan – Code – Build – Test – Release – Deploy – Monitor*, adicionando medidas de segurança específicas a cada uma.  

## 3. Fichamento de Citações 

* _"Security scanning is a key aspect of the DevSecOps pipeline, and it is critical for discovering vulnerabilities early in the development cycle."_

* _"Implementing and automating security scanning will help minimise the time required to find and patch vulnerabilities, making the process more efficient."_ 

* _"The proposed method in this research paper involves implementing and automating security scanning to a DevSecOps CI/CD pipeline."_ 

* _"Snyk is a cloud-based security scanning tool thatspecializes in identifying vulnerabilities in open-sourcelibraries and containers."_ 

* _"StackHawk is a cloud-based dynamic application security testing (DAST) platform that enables security testing [...] and interacts smoothly with CI/CD processes."_ 

* _"The integration of Snyk and StackHawk in the CI/CD pipeline enables automated and continuous security scanning of container images, providing early detection of vulnerabilities and security issues."_ 

* _"The automated remediation features of Snyk and StackHawk save time and improve efficiency, while the integration of image scanning ensures that container images are thoroughly scanned for vulnerabilities before they are deployed."_ 

* _"Future research should explore strategies to optimize resource allocation, parallelize or distribute scanning tasks, and leverage cloud-based infrastructure to enhance the efficiency of the CI/CD pipeline without compromising security."_

