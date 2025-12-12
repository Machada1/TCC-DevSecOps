# Cloud Build v2 - Usando conexão GitHub existente

# ID da conexão construído manualmente (conexão já criada no console)
locals {
  github_connection_id = "projects/${var.project_id}/locations/${var.region}/connections/${var.github_connection_name}"
}

# Vincula o repositório à conexão
resource "google_cloudbuildv2_repository" "repo" {
  name              = "${var.github_owner}-${var.github_repo}"
  location          = var.region
  parent_connection = local.github_connection_id
  remote_uri        = "https://github.com/${var.github_owner}/${var.github_repo}.git"
}

# Trigger automático no push para master
resource "google_cloudbuild_trigger" "devsecops_trigger" {
  name        = "devsecops-cloudbuild-trigger"
  description = "Trigger para build e deploy automatizado via Cloud Build"
  location    = var.region
  project     = var.project_id

  # Service account user-managed (criada em reports-bucket.tf)
  service_account = google_service_account.cloudbuild.id

  repository_event_config {
    repository = google_cloudbuildv2_repository.repo.id
    push {
      branch = "^master$"
    }
  }

  filename = "Instrumentos/Codigos/DevSecOps/dvwa/cloudbuild.yaml"

  substitutions = {
    _ARTIFACT_REPO = google_artifact_registry_repository.devsecops_repo.repository_id
    _REGION        = var.region
    _PROJECT_ID    = var.project_id
  }

  depends_on = [google_cloudbuildv2_repository.repo, google_service_account.cloudbuild]
}
