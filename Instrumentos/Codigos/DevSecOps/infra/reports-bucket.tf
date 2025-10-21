resource "google_storage_bucket" "reports_bucket" {
  name                        = "devsecops-reports"
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

# IAM Binding: permitir que o Cloud Build grave relatórios no bucket
resource "google_storage_bucket_iam_member" "cloudbuild_write_reports" {
  bucket = google_storage_bucket.reports_bucket.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${data.google_project.project.number}@cloudbuild.gserviceaccount.com"
}

data "google_project" "project" {}
