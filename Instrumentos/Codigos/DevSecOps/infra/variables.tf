variable "project_id" {
  description = "ID do projeto no GCP"
  type        = string
}

variable "region" {
  description = "Região do GCP"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "Zona do GCP"
  type        = string
  default     = "us-central1-a"
}

variable "network_name" {
  description = "Nome da VPC"
  type        = string
  default     = "devsecops-vpc"
}

variable "cluster_name" {
  description = "Nome do cluster GKE"
  type        = string
  default     = "devsecops-cluster"
}

variable "artifact_repo_name" {
  description = "Nome do repositório no Artifact Registry"
  type        = string
  default     = "devsecops-repo"
}

variable "github_owner" {
  description = "Dono do repositório GitHub"
  type        = string
}

variable "github_repo" {
  description = "Nome do repositório GitHub conectado ao Cloud Build"
  type        = string
}

