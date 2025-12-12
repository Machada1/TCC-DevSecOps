resource "google_storage_bucket" "reports_bucket" {
  name                        = "devsecops-reports-dvwa"
  location                    = var.region
  force_destroy               = true
  uniform_bucket_level_access = true

  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      age = 30  # remove relatórios antigos automaticamente após 30 dias
    }
  }

  labels = {
    environment = "devsecops"
    purpose     = "security-reports"
  }
}

# Criar service account Cloud Build
resource "google_service_account" "cloudbuild" {
  account_id   = "cloudbuild"
  display_name = "Cloud Build Service Account"
}

# IAM Binding: permitir que o Cloud Build grave relatórios no bucket
resource "google_storage_bucket_iam_member" "cloudbuild_write_reports" {
  bucket = google_storage_bucket.reports_bucket.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.cloudbuild.email}"

  depends_on = [google_service_account.cloudbuild]
}

data "google_project" "project" {}

output "cloudbuild_service_account" {
  value = google_service_account.cloudbuild.email
}
