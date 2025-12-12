# Projeto GCP para os recursos
project_id = "infra-sd-host"

# Região e zona do GCP para implantação de recursos
region = "us-central1"
zone = "us-central1-a"

# REDE
# Nome da VPC (Virtual Private Cloud)
network_name = "devsecops-vpc"

# KUBERNETES (GKE)
# Nome do cluster GKE
cluster_name = "devsecops-cluster"

# ARTIFACT REGISTRY
# Nome do repositório de imagens Docker no Artifact Registry
artifact_repo_name = "devsecops-repo"

# GITHUB
# Proprietário (owner) do repositório GitHub
# Exemplo: "seu-usuario-github" ou "sua-organizacao"
github_owner = "Machada1"

# Nome do repositório GitHub que será conectado ao Cloud Build
github_repo = "devsecops-guilherme-machado"

# Nome da conexão GitHub criada no Cloud Build (veja em Cloud Build > Connections)
github_connection_name = "devsecops"