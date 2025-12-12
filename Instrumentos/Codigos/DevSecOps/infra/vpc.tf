resource "google_compute_network" "vpc" {
  name                    = var.network_name
  auto_create_subnetworks = false

  depends_on = [google_project_service.compute_engine]
}

resource "google_compute_subnetwork" "subnet" {
  name                      = "${var.network_name}-subnet"
  ip_cidr_range             = "10.0.0.0/24"
  region                    = var.region
  network                   = google_compute_network.vpc.id
  private_ip_google_access  = true  # Requerido por org policy para acesso a APIs Google
}
