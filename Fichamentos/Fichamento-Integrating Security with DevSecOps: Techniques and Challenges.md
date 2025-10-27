# Integrating Security with DevSecOps: Techniques and Challenges

Z. Ahmed and S. C. Francis, "Integrating Security with DevSecOps: Techniques and Challenges," 2019 International Conference on Digitization (ICD), Sharjah, United Arab Emirates, 2019, pp. 178-182, doi: 10.1109/ICD47981.2019.9105789. 

## 1. Fichamento de Conteúdo

O artigo aborda a necessidade de integrar segurança em todas as etapas do ciclo de desenvolvimento de software, enfatizando a transição de práticas DevOps tradicionais para uma abordagem DevSecOps. Os autores destacam que, embora o DevOps tenha aumentado a eficiência e a velocidade na entrega de projetos, a ausência de mecanismos de segurança contínua resultou em vulnerabilidades graves e retrabalho nas fases finais de desenvolvimento. O estudo foi conduzido com base em projetos acadêmicos de uma universidade, comparando o desempenho de equipes que aplicaram DevOps e aquelas que integraram práticas de DevSecOps. A implementação prática envolveu o uso da ferramenta Snyk para análise de dependências e detecção de vulnerabilidades em tempo de build. Os resultados mostraram que a introdução de segurança desde as fases iniciais reduziu a ocorrência de falhas como “insecure encryption” e “denial of service”. Apesar disso, os autores ressaltam desafios significativos na adoção do modelo, como resistência de equipe, curva de aprendizado e integração entre ferramentas. Em síntese, o artigo evidencia que o DevSecOps melhora a robustez e confiabilidade das aplicações, embora sua adoção demande esforços culturais e técnicos adicionais.

## 2. Fichamento Bibliográfico 

* _DevSecOps_ (p.2): Combinação de desenvolvimento, segurança e operações, que busca inserir práticas de segurança desde o início do ciclo de desenvolvimento para reduzir vulnerabilidades.

* _Snyk Tool_ (p.3): É uma ferramenta de segurança usada para realizar dependency checking e identificar vulnerabilidades conhecidas (CVE) durante o build, evitando que código inseguro avance para produção.

* _Security Automation_ (p.3): Refere-se ao uso de pipelines automatizados para executar verificações de segurança contínuas. A automação permite que o controle de vulnerabilidades, análise de código e revisão de dependências ocorram sem intervenção manual, mantendo a agilidade do DevOps.

* _Insecure Encryption_ (p.2): Uso de algoritmos ou configurações criptográficas fracas, permitindo que dados sensíveis sejam expostos. Pode ser evitado com padrões modernos como AES-GCM e TLS atualizados.

## 3. Fichamento de Citações 

* _“Security is a nonfunctional requirement and does not affect the functionality of the product because of this it is often pushed to the end of the process.”_

* _“DevSecOps is about introducing security earlier in the life cycle of application development, thus minimizing vulnerabilities and bringing security closer to IT and business objectives.”_

* _“We implement security right at the start of the project from the initialization stage.”_

* _“Snyk pulls up all the vulnerabilities and we worked towards fixing these vulnerabilities before moving code for staging and functional testing.”_

* _“Implementing security in continuous development was another challenge as this is seen as something that comes towards the end of development.”_

