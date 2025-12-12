# ============================================================================
# IAM - Service Accounts e Permissões para Cloud Build
# ============================================================================

# Dados do projeto (para obter o project number)
data "google_project" "project" {}

# ----------------------------------------------------------------------------
# Service Account customizada para Cloud Build
# ----------------------------------------------------------------------------
resource "google_service_account" "cloudbuild" {
  account_id   = "cloudbuild"
  display_name = "Cloud Build Service Account"
  description  = "Service Account para execução de builds no Cloud Build"
}

# ----------------------------------------------------------------------------
# Permissões para a SA customizada (cloudbuild@...)
# ----------------------------------------------------------------------------
resource "google_project_iam_member" "cloudbuild_service_usage" {
  project = var.project_id
  role    = "roles/serviceusage.serviceUsageConsumer"
  member  = "serviceAccount:${google_service_account.cloudbuild.email}"
}

resource "google_project_iam_member" "cloudbuild_logs_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.cloudbuild.email}"
}

resource "google_project_iam_member" "cloudbuild_builder" {
  project = var.project_id
  role    = "roles/cloudbuild.builds.builder"
  member  = "serviceAccount:${google_service_account.cloudbuild.email}"
}

resource "google_project_iam_member" "cloudbuild_artifact_registry" {
  project = var.project_id
  role    = "roles/artifactregistry.writer"
  member  = "serviceAccount:${google_service_account.cloudbuild.email}"
}

resource "google_project_iam_member" "cloudbuild_gke" {
  project = var.project_id
  role    = "roles/container.developer"
  member  = "serviceAccount:${google_service_account.cloudbuild.email}"
}

# Permitir gravar relatórios no bucket
resource "google_storage_bucket_iam_member" "cloudbuild_write_reports" {
  bucket = google_storage_bucket.reports_bucket.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.cloudbuild.email}"
}

# Permitir gravar logs no bucket de logs
resource "google_storage_bucket_iam_member" "cloudbuild_write_logs" {
  bucket = google_storage_bucket.cloudbuild_logs.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.cloudbuild.email}"
}

# ----------------------------------------------------------------------------
# Permissões para a SA padrão do Cloud Build (PROJECT_NUMBER@cloudbuild.gserviceaccount.com)
# ----------------------------------------------------------------------------
resource "google_project_iam_member" "cloudbuild_default_service_usage" {
  project = var.project_id
  role    = "roles/serviceusage.serviceUsageConsumer"
  member  = "serviceAccount:${data.google_project.project.number}@cloudbuild.gserviceaccount.com"
}

resource "google_project_iam_member" "cloudbuild_default_logs_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${data.google_project.project.number}@cloudbuild.gserviceaccount.com"
}

# Permitir que a SA padrão atue como a SA customizada
resource "google_service_account_iam_member" "cloudbuild_sa_user" {
  service_account_id = google_service_account.cloudbuild.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${data.google_project.project.number}@cloudbuild.gserviceaccount.com"
}

# ----------------------------------------------------------------------------
# Permissões para o Cloud Build Service Agent (service-PROJECT_NUMBER@gcp-sa-cloudbuild.iam.gserviceaccount.com)
# Esta é a SA que dispara os triggers
# ----------------------------------------------------------------------------
resource "google_project_iam_member" "cloudbuild_agent_service_usage" {
  project = var.project_id
  role    = "roles/serviceusage.serviceUsageConsumer"
  member  = "serviceAccount:service-${data.google_project.project.number}@gcp-sa-cloudbuild.iam.gserviceaccount.com"
}

resource "google_project_iam_member" "cloudbuild_agent_logs_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:service-${data.google_project.project.number}@gcp-sa-cloudbuild.iam.gserviceaccount.com"
}

# Permitir que o Service Agent atue como a SA customizada
resource "google_service_account_iam_member" "cloudbuild_trigger_sa_user" {
  service_account_id = google_service_account.cloudbuild.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:service-${data.google_project.project.number}@gcp-sa-cloudbuild.iam.gserviceaccount.com"
}

# Permitir que o Service Agent obtenha tokens da SA customizada
resource "google_service_account_iam_member" "cloudbuild_trigger_token_creator" {
  service_account_id = google_service_account.cloudbuild.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:service-${data.google_project.project.number}@gcp-sa-cloudbuild.iam.gserviceaccount.com"
}

# ----------------------------------------------------------------------------
# Outputs
# ----------------------------------------------------------------------------
output "cloudbuild_service_account" {
  description = "Email da Service Account do Cloud Build"
  value       = google_service_account.cloudbuild.email
}
