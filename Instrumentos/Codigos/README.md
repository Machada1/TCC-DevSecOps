# 💻 Código do Projeto

Este diretório contém todo o código-fonte e configurações da implementação DevSecOps.

## 📁 Estrutura

```
Codigos/
├── DevSecOps/
│   ├── dvwa/
│   │   ├── cloudbuild.yaml      # Pipeline CI/CD principal
│   │   ├── src/                 # Código-fonte do DVWA
│   │   └── k8s/                 # Manifests Kubernetes (DVWA e MySQL)
│   ├── infra/
│   │   ├── *.tf                 # Configurações Terraform (GCP)
│   │   └── terraform.tfvars     # Variáveis do projeto
│   ├── dvwa-bruteforce.py       # Script de brute force customizado
│   └── hydra.Dockerfile         # Dockerfile do Hydra (referência)
└── README.md
```

## 🔧 Componentes Principais

### Pipeline CI/CD (`cloudbuild.yaml`)
Pipeline completo com 15 steps incluindo:
- **SAST**: Semgrep para análise estática
- **SCA**: Trivy para dependências
- **Container Scan**: Trivy para imagem Docker
- **IaC Scan**: Checkov para Terraform/K8s
- **DAST**: OWASP ZAP (Baseline + Active Scan)
- **Brute Force**: Script Python customizado

### Infraestrutura (`infra/`)
Terraform para provisionamento no GCP:
- Google Kubernetes Engine (GKE)
- Artifact Registry
- Cloud Build
- Cloud Storage (relatórios)
- VPC e configurações de rede

### Aplicação Alvo (`dvwa/`)
DVWA (Damn Vulnerable Web Application) - aplicação intencionalmente vulnerável para testes de segurança.

## 🚀 Como Usar

```bash
# 1. Provisionar infraestrutura
cd DevSecOps/infra
terraform init && terraform apply

# 2. Executar pipeline
gcloud builds submit --config DevSecOps/dvwa/cloudbuild.yaml .

# 3. Destruir infraestrutura (após testes)
terraform destroy
```