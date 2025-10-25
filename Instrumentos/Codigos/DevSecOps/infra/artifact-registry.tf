resource "google_artifact_registry_repository" "devsecops_repo" {
  provider      = google
  location      = var.region
  repository_id = var.artifact_repo_name
  description   = "Repositório Docker para armazenar imagens do pipeline DevSecOps"
  format        = "DOCKER"

  cleanup_policies {
    id     = "retain-latest"
    action = "KEEP"
    most_recent_versions {
      keep_count = 1
    }
  }

  docker_config {
    immutable_tags = false
  }

  labels = {
    environment = "dev"
    managed_by  = "terraform"
  }
}
