# Ativar APIs necessárias para o projeto DevSecOps

resource "google_project_service" "artifact_registry" {
  project = var.project_id
  service = "artifactregistry.googleapis.com"

  disable_on_destroy = false
}

resource "google_project_service" "compute_engine" {
  project = var.project_id
  service = "compute.googleapis.com"

  disable_on_destroy = false
}

resource "google_project_service" "container" {
  project = var.project_id
  service = "container.googleapis.com"

  disable_on_destroy = false
}

resource "google_project_service" "cloud_build" {
  project = var.project_id
  service = "cloudbuild.googleapis.com"

  disable_on_destroy = false
}

resource "google_project_service" "cloud_storage" {
  project = var.project_id
  service = "storage-api.googleapis.com"

  disable_on_destroy = false
}

locals {
  api_dependencies = [
    google_project_service.artifact_registry.id,
    google_project_service.compute_engine.id,
    google_project_service.container.id,
    google_project_service.cloud_build.id,
    google_project_service.cloud_storage.id
  ]
}
