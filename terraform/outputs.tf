output "cluster_name" {
  value = google_container_cluster.primary.name
}

output "kubeconfig_command" {
  value = "gcloud container clusters get-credentials ${google_container_cluster.primary.name} --region ${var.region} --project ${var.project_id}"
}

output "artifact_registry_url" {
  value = "us-central1-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.devsecops_repo.repository_id}"
  description = "URL base do repositório Docker no Artifact Registry"
}
