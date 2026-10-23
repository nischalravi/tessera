output "load_balancer_ip" {
  description = "Create the DNS A record for var.domain pointing here; the managed certificate activates afterwards."
  value       = google_compute_global_address.lb.address
}

output "sql_private_ip" {
  description = "Host for both DSNs (sslmode=require or stricter)."
  value       = google_sql_database_instance.this.private_ip_address
}

output "sql_server_ca_cert" {
  description = "Server CA, to mount for sslmode=verify-ca."
  value       = google_sql_database_instance.this.server_ca_cert[0].cert
  sensitive   = false
}

output "secret_ids" {
  description = "Add versions with `gcloud secrets versions add` (README)."
  value       = { for k, s in google_secret_manager_secret.this : k => s.secret_id }
}

output "service_account" {
  value = google_service_account.run.email
}
