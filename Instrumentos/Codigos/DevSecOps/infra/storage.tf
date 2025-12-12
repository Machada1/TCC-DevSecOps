# ============================================================================
# Storage Buckets
# ============================================================================

# Bucket para relatórios de segurança (SAST, DAST, SCA, etc)
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

# Bucket de logs para Cloud Build (necessário para service account user-managed)
resource "google_storage_bucket" "cloudbuild_logs" {
  name                        = "${var.project_id}-cloudbuild-logs"
  location                    = var.region
  force_destroy               = true
  uniform_bucket_level_access = true

  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      age = 30
    }
  }

  labels = {
    environment = "devsecops"
    purpose     = "cloudbuild-logs"
  }
}

# ----------------------------------------------------------------------------
# Outputs
# ----------------------------------------------------------------------------
output "cloudbuild_logs_bucket" {
  description = "Nome do bucket de logs do Cloud Build"
  value       = google_storage_bucket.cloudbuild_logs.name
}

output "reports_bucket" {
  description = "Nome do bucket de relatórios de segurança"
  value       = google_storage_bucket.reports_bucket.name
}
