# REFERENCE MODULE. VPC + private services access, Cloud SQL for PostgreSQL 16 (private IP, TLS only, HA,
# PITR), Secret Manager containers, a least-privilege service account, Cloud Run (two containers, Direct VPC
# egress), and a global external HTTPS load balancer with a Google-managed certificate.
# Mirrors deploy/gcp/cloud-run/service.yaml.

locals {
  labels = merge({ application = "tessera", managed-by = "terraform" }, var.labels)
  secret_ids = {
    db_owner_dsn          = "${var.name}-db-owner-dsn"
    db_app_dsn            = "${var.name}-db-app-dsn"
    kek                   = "${var.name}-kek"
    aws_access_key_id     = "${var.name}-aws-access-key-id"
    aws_secret_access_key = "${var.name}-aws-secret-access-key"
  }
}

resource "google_project_service" "apis" {
  for_each = toset([
    "run.googleapis.com", "sqladmin.googleapis.com", "secretmanager.googleapis.com",
    "compute.googleapis.com", "servicenetworking.googleapis.com", "logging.googleapis.com",
  ])
  service            = each.value
  disable_on_destroy = false
}

# ---------------------------------------------------------------- network
resource "google_compute_network" "this" {
  name                    = var.name
  auto_create_subnetworks = false
  depends_on              = [google_project_service.apis]
}

resource "google_compute_subnetwork" "run" {
  name                     = "${var.name}-run"
  region                   = var.region
  network                  = google_compute_network.this.id
  ip_cidr_range            = var.subnet_cidr
  private_ip_google_access = true
  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.25
  }
}

resource "google_compute_global_address" "private_services" {
  name          = "${var.name}-private-services"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 20
  network       = google_compute_network.this.id
}

resource "google_service_networking_connection" "private_services" {
  network                 = google_compute_network.this.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_services.name]
}

# Cloud Run egress (Direct VPC): allow only Cloud SQL (5432) inside the VPC and https out.
resource "google_compute_firewall" "run_egress_db" {
  name      = "${var.name}-run-egress-db"
  network   = google_compute_network.this.name
  direction = "EGRESS"
  priority  = 900
  allow {
    protocol = "tcp"
    ports    = ["5432"]
  }
  destination_ranges = ["${google_compute_global_address.private_services.address}/${google_compute_global_address.private_services.prefix_length}"]
  target_tags        = ["${var.name}-run"]
}

# ---------------------------------------------------------------- database
resource "google_sql_database_instance" "this" {
  name                = var.name
  region              = var.region
  database_version    = "POSTGRES_16"
  deletion_protection = var.deletion_protection

  settings {
    tier              = var.db_tier
    edition           = "ENTERPRISE"
    disk_type         = "PD_SSD"
    disk_size         = var.db_disk_gb
    disk_autoresize   = true
    availability_type = var.db_high_availability ? "REGIONAL" : "ZONAL"
    user_labels       = local.labels

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.this.id
      ssl_mode        = "ENCRYPTED_ONLY" # TLS required; the Tessera DSN uses sslmode=require or stricter
    }

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = 7
      backup_retention_settings {
        retained_backups = var.db_backup_retention_days
      }
    }

    database_flags {
      name  = "log_connections"
      value = "on"
    }
    database_flags {
      name  = "log_disconnections"
      value = "on"
    }

    insights_config {
      query_insights_enabled = true
    }
    maintenance_window {
      day  = 7
      hour = 3
    }
  }

  depends_on = [google_service_networking_connection.private_services]
}

resource "google_sql_database" "tessera" {
  name     = "tessera"
  instance = google_sql_database_instance.this.name
}
# No google_sql_user: the postgres password and the tessera_owner / tessera_app roles are created by you
# (README), so no password is in Terraform state.

# ---------------------------------------------------------------- secrets and identity
resource "google_secret_manager_secret" "this" {
  for_each  = local.secret_ids
  secret_id = each.value
  labels    = local.labels
  replication {
    auto {}
  }
  depends_on = [google_project_service.apis]
}

resource "google_service_account" "run" {
  account_id   = var.name
  display_name = "Tessera Cloud Run"
}

resource "google_secret_manager_secret_iam_member" "run" {
  for_each  = google_secret_manager_secret.this
  secret_id = each.value.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.run.email}"
}

# ---------------------------------------------------------------- Cloud Run
resource "google_cloud_run_v2_service" "this" {
  name                = var.name
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
  deletion_protection = var.deletion_protection
  labels              = local.labels

  template {
    service_account                  = google_service_account.run.email
    max_instance_request_concurrency = 80
    timeout                          = "60s"

    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }

    vpc_access {
      egress = "PRIVATE_RANGES_ONLY"
      network_interfaces {
        network    = google_compute_network.this.id
        subnetwork = google_compute_subnetwork.run.id
        tags       = ["${var.name}-run"]
      }
    }

    volumes {
      name = "tessera-data"
      empty_dir {
        medium     = "MEMORY"
        size_limit = "128Mi"
      }
    }
    volumes {
      name = "api-tmp"
      empty_dir {
        medium     = "MEMORY"
        size_limit = "64Mi"
      }
    }
    volumes {
      name = "ui-tmp"
      empty_dir {
        medium     = "MEMORY"
        size_limit = "64Mi"
      }
    }

    containers {
      name  = "ui"
      image = var.ui_image
      ports {
        container_port = 8080
      }
      env {
        name  = "API_UPSTREAM"
        value = "127.0.0.1:8000"
      }
      resources {
        limits            = { cpu = "1", memory = "256Mi" }
        cpu_idle          = false
        startup_cpu_boost = true
      }
      volume_mounts {
        name       = "ui-tmp"
        mount_path = "/tmp"
      }
      depends_on = ["api"]
      startup_probe {
        http_get {
          path = "/api/health"
        }
        period_seconds    = 5
        failure_threshold = 30
      }
    }

    containers {
      name  = "api"
      image = var.api_image
      args  = ["serve", "-addr", "0.0.0.0:8000"]
      resources {
        limits   = { cpu = "1", memory = "1Gi" }
        cpu_idle = false # background loops run outside requests
      }
      env {
        name  = "TESSERA_ENV"
        value = "prod"
      }
      env {
        name  = "TESSERA_PUBLIC_URL"
        value = "https://${var.domain}"
      }
      env {
        name  = "TESSERA_COOKIE_SECURE"
        value = "true"
      }
      env {
        name  = "TESSERA_TRUSTED_PROXIES"
        value = "127.0.0.1/32"
      }
      env {
        name  = "TESSERA_AUDIT_ANCHOR"
        value = var.anchor_bucket
      }
      env {
        name  = "AWS_REGION"
        value = var.anchor_aws_region
      }
      env {
        name  = "TESSERA_METRICS_ADDR"
        value = "off"
      }
      dynamic "env" {
        for_each = {
          TESSERA_DB            = "db_owner_dsn"
          TESSERA_DB_APP        = "db_app_dsn"
          TESSERA_KEK           = "kek"
          AWS_ACCESS_KEY_ID     = "aws_access_key_id"
          AWS_SECRET_ACCESS_KEY = "aws_secret_access_key"
        }
        content {
          name = env.key
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.this[env.value].secret_id
              version = "latest"
            }
          }
        }
      }
      volume_mounts {
        name       = "tessera-data"
        mount_path = "/var/lib/tessera"
      }
      volume_mounts {
        name       = "api-tmp"
        mount_path = "/tmp"
      }
      startup_probe {
        http_get {
          path = "/api/health"
          port = 8000
        }
        period_seconds    = 5
        failure_threshold = 30
      }
      liveness_probe {
        http_get {
          path = "/api/health"
          port = 8000
        }
        period_seconds = 15
      }
    }
  }

  depends_on = [google_secret_manager_secret_iam_member.run, google_sql_database.tessera]
}

# The service accepts traffic only from the load balancer (ingress above); invocation itself is public because
# Tessera does its own authentication.
resource "google_cloud_run_v2_service_iam_member" "public" {
  name     = google_cloud_run_v2_service.this.name
  location = var.region
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# ---------------------------------------------------------------- global external HTTPS load balancer
resource "google_compute_global_address" "lb" {
  name = "${var.name}-lb"
}

resource "google_compute_region_network_endpoint_group" "run" {
  name                  = var.name
  region                = var.region
  network_endpoint_type = "SERVERLESS"
  cloud_run {
    service = google_cloud_run_v2_service.this.name
  }
}

resource "google_compute_backend_service" "this" {
  name                  = var.name
  protocol              = "HTTPS"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  backend {
    group = google_compute_region_network_endpoint_group.run.id
  }
  log_config {
    enable      = true
    sample_rate = 1
  }
}

resource "google_compute_url_map" "https" {
  name            = var.name
  default_service = google_compute_backend_service.this.id
}

resource "google_compute_managed_ssl_certificate" "this" {
  name = var.name
  managed {
    domains = [var.domain]
  }
}

resource "google_compute_ssl_policy" "modern" {
  name            = var.name
  profile         = "MODERN"
  min_tls_version = "TLS_1_2"
}

resource "google_compute_target_https_proxy" "this" {
  name             = var.name
  url_map          = google_compute_url_map.https.id
  ssl_certificates = [google_compute_managed_ssl_certificate.this.id]
  ssl_policy       = google_compute_ssl_policy.modern.id
}

resource "google_compute_global_forwarding_rule" "https" {
  name                  = "${var.name}-https"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  target                = google_compute_target_https_proxy.this.id
  port_range            = "443"
  ip_address            = google_compute_global_address.lb.id
}

resource "google_compute_url_map" "redirect" {
  name = "${var.name}-redirect"
  default_url_redirect {
    https_redirect         = true
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
    strip_query            = false
  }
}

resource "google_compute_target_http_proxy" "redirect" {
  name    = "${var.name}-redirect"
  url_map = google_compute_url_map.redirect.id
}

resource "google_compute_global_forwarding_rule" "http" {
  name                  = "${var.name}-http"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  target                = google_compute_target_http_proxy.redirect.id
  port_range            = "80"
  ip_address            = google_compute_global_address.lb.id
}
