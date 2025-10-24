# Uma Abordagem DevSecOps para Inserção e Automação de Práticas de Segurança em Pipelines CI/CD

O objetivo deste projeto é investigar e implementar práticas de segurança em pipelines de Integração Contínua e Entrega Contínua (CI/CD), utilizando os princípios de DevSecOps. A pesquisa busca demonstrar como a automação de verificações de segurança, por meio de ferramentas como SAST, DAST, SCA e IaC scanning, pode ser integrada de forma prática em pipelines CI/CD, garantindo que vulnerabilidades sejam detectadas desde as primeiras etapas do ciclo de desenvolvimento.

Além disso, o projeto propõe a utilização de recursos do Google Cloud Platform (GCP), incluindo Cloud Build, Artifact Registry e Google Kubernetes Engine (GKE), provisionados via Terraform, como ambiente controlado para validação da abordagem. A análise dos resultados será qualitativa, focando na efetividade da integração das ferramentas, no nível de automação alcançado e nas boas práticas observadas na implementação de DevSecOps.

## Alunos integrantes da equipe

* Guilherme Henrique de Lima Machado

## Professores responsáveis

* [Lesandro Ponciano](https://orcid.org/0000-0002-5724-0094)

## Instruções de Replicação/Reprodução

Este projeto pode ser replicado seguindo os passos abaixo:

### Requisitos

- Conta no **Google Cloud Platform (GCP)** com permissões para criar:
  - Projetos, VPCs e sub-redes
  - Clusters GKE
  - Artifact Registry
  - Buckets no Cloud Storage
  - Cloud Build
- **Terraform** instalado (>= 1.5)
- **Google Cloud SDK** instalado e autenticado
- **Docker** instalado para testes locais opcionais
- Código-fonte ou imagem do **DVWA (Damn Vulnerable Web Application)**


### Provisionamento do ambiente com Terraform

1. Navegue até a pasta de infra do projeto:

```bash
cd infra
```
2. No arquivo `variables.tf` ajuste o project_id para o projeto que será utilizado no gcp.

3. Inicialize o Terraform:

```bash
terraform init
```

4. Visualize o plano de execução:

```bash
terraform plan
```

5. Aplique o Terraform para criar todos os recursos:

```bash
terraform apply
```

* Confirme com `yes` quando solicitado.
* Recursos criados:

  * VPC e sub-redes
  * Cluster GKE
  * Artifact Registry
  * Bucket GCS para relatórios de segurança
  * IAM binding para permitir que o Cloud Build grave no bucket

6. Verifique os recursos criados:

```bash
gcloud container clusters list
gcloud artifacts repositories list
gsutil ls gs://devsecops-reports
```

### Preparar a aplicação e Docker(DVWA)

O projeto utiliza a aplicação DVWA (Damn Vulnerable Web Application) como base para testes de segurança.
O DVWA é uma aplicação web vulnerável escrita em PHP/MySQL, amplamente usada em laboratórios de pentest e DevSecOps, permitindo avaliar a efetividade de ferramentas de varredura em um ambiente controlado.


1. O pipeline utilizará a imagem oficial do DVWA disponível no Docker Hub:
2. (Opcional) Teste build da imagem local:

```bash
docker pull vulnerables/web-dvwa
docker run -d -p 8080:80 vulnerables/web-dvwa
```

* Acesse `http://localhost:8080` para confirmar funcionamento.


### Configuração do Cloud Build

1. Verifique o arquivo `cloudbuild.yaml` na pasta "/app" do projeto.
2. Ajuste as substituições:

```yaml
substitutions:
  _ARTIFACT_REPO: "devsecops-repo"
  _REGION: "us-central1"
  _PROJECT_ID: "<SEU_PROJECT_ID>"
  _CLUSTER_NAME: "devsecops-cluster"
  _APP_NAME: "devsecops-app"
  _DEPLOYMENT_NAME: "devsecops-app"
  _REPORT_BUCKET: "gs://devsecops-reports"
```

3. Confirme que a **conta de serviço do Cloud Build** possui permissões:

* Acesso ao GKE
* Acesso ao Artifact Registry
* Escrita no bucket GCS


### Executar o pipeline

1. Dispare o build no Cloud Build:

```bash
gcloud builds submit --config cloudbuild.yaml .
```

* Etapas do pipeline:

  1. Pull da imagem Docker(base DVWA)
  2. Tag e Push para o Artifact Registry
  3. SAST com Semgrep
  4. SCA com OWASP Dependency-Check
  5. IaC Scan com Checkov
  6. Container Scan com Trivy e Deploy do MySQL no GKE
  7. Deploy do app no GKE
  8. DAST com OWASP ZAP
  9. Upload dos relatórios para o bucket GCS
  10. Exibir IP externo do DVWA

2. Acompanhe logs:

```bash
gcloud builds list
gcloud builds log <BUILD_ID>
```

### Avaliação dos resultados

1. Acesse o bucket GCS para conferir relatórios:

```bash
gsutil ls gs://devsecops-reports/<BUILD_ID>/
```

2. Analise os relatórios gerados por cada ferramenta:

* `.json` → Semgrep, Checkov, Trivy
* `.html` → Dependency-Check, OWASP ZAP

3. Pontos de análise qualitativa:

* Efetividade da integração das ferramentas no pipeline
* Nível de automação alcançado na detecção de vulnerabilidades
* Boas práticas observadas na implementação de DevSecOps
* Detecção e mitigação de vulnerabilidades em cada etapa do pipeline

4. Repita o build sempre que desejar testar alterações na aplicação ou na configuração do pipeline. Cada build gera um novo diretório no bucket para manter histórico completo.


### Observações

* O ambiente é totalmente **provisionado via Terraform**, garantindo reprodutibilidade.
* Todos os relatórios ficam armazenados em **bucket GCS**, permitindo auditoria e rastreabilidade.
* As ferramentas de segurança estão configuradas para gerar evidências de vulnerabilidades em cada etapa do pipeline, de forma automatizada.
* O uso do DVWA proporciona um ambiente intencionalmente vulnerável, permitindo observar de forma prática o funcionamento e a precisão das ferramentas automatizadas de segurança.

