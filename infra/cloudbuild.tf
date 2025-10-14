resource "google_cloudbuild_trigger" "devsecops_trigger" {
  name        = "devsecops-cloudbuild-trigger"
  description = "Trigger para build e deploy automatizado da aplicação Python no GKE via Cloud Build"
  location    = var.region

  github {
    owner = var.github_owner
    name  = var.github_repo

    push {
      branch = "master"
    }
  }

  filename = "../app/cloudbuild.yaml"

  substitutions = {
    _ARTIFACT_REPO = google_artifact_registry_repository.devsecops_repo.repository_id
    _REGION        = var.region
    _PROJECT_ID    = var.project_id
  }
}
