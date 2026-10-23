# REFERENCE MODULE. VNet, PostgreSQL Flexible Server (private access, TLS required), Key Vault, user-assigned
# identity, Log Analytics and a Container Apps environment + app (two containers). Mirrors
# deploy/azure/container-apps/containerapp.yaml.

locals {
  tags = merge({ Application = "tessera", ManagedBy = "terraform" }, var.tags)
}

data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "this" {
  name     = "rg-${var.name}"
  location = var.location
  tags     = local.tags
}

# ---------------------------------------------------------------- network
resource "azurerm_virtual_network" "this" {
  name                = "vnet-${var.name}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  address_space       = [var.vnet_cidr]
  tags                = local.tags
}

resource "azurerm_subnet" "apps" {
  name                 = "snet-apps"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [cidrsubnet(var.vnet_cidr, 7, 0)] # /23, the minimum for a workload-profile environment
  delegation {
    name = "aca"
    service_delegation {
      name    = "Microsoft.App/environments"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "azurerm_subnet" "db" {
  name                 = "snet-db"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [cidrsubnet(var.vnet_cidr, 8, 4)]
  delegation {
    name = "pg"
    service_delegation {
      name    = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "azurerm_network_security_group" "db" {
  name                = "nsg-${var.name}-db"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  security_rule {
    name                       = "allow-apps-postgres"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "5432"
    source_address_prefix      = azurerm_subnet.apps.address_prefixes[0]
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "deny-other-inbound"
    priority                   = 4000
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  tags = local.tags
}

resource "azurerm_subnet_network_security_group_association" "db" {
  subnet_id                 = azurerm_subnet.db.id
  network_security_group_id = azurerm_network_security_group.db.id
}

resource "azurerm_private_dns_zone" "pg" {
  name                = "${var.name}.private.postgres.database.azure.com"
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "pg" {
  name                  = "pg"
  resource_group_name   = azurerm_resource_group.this.name
  private_dns_zone_name = azurerm_private_dns_zone.pg.name
  virtual_network_id    = azurerm_virtual_network.this.id
}

# ---------------------------------------------------------------- database
# Tessera logs in with passwords (tessera_owner, tessera_app), so password authentication stays on. The
# administrator password is write-only (administrator_password_wo): it is not stored in Terraform state.
# The deploying principal is also an Entra administrator and creates the two Tessera roles (README).
resource "azurerm_postgresql_flexible_server" "this" {
  name                          = "psql-${var.name}"
  resource_group_name           = azurerm_resource_group.this.name
  location                      = azurerm_resource_group.this.location
  version                       = "16"
  sku_name                      = var.db_sku_name
  storage_mb                    = var.db_storage_mb
  delegated_subnet_id           = azurerm_subnet.db.id
  private_dns_zone_id           = azurerm_private_dns_zone.pg.id
  public_network_access_enabled = false
  zone                          = var.db_zone

  backup_retention_days        = var.db_backup_retention_days
  geo_redundant_backup_enabled = false # set true (and a paired region) for region-loss recovery

  administrator_login               = "tessera_admin"
  administrator_password_wo         = var.db_admin_password
  administrator_password_wo_version = 1 # bump to rotate

  authentication {
    active_directory_auth_enabled = true
    password_auth_enabled         = true
    tenant_id                     = data.azurerm_client_config.current.tenant_id
  }

  dynamic "high_availability" {
    for_each = var.db_high_availability ? [1] : []
    content {
      mode                      = "ZoneRedundant"
      standby_availability_zone = var.db_standby_zone
    }
  }

  tags       = local.tags
  depends_on = [azurerm_private_dns_zone_virtual_network_link.pg]
  lifecycle {
    ignore_changes = [zone, high_availability[0].standby_availability_zone]
  }
}

resource "azurerm_postgresql_flexible_server_active_directory_administrator" "deployer" {
  server_name         = azurerm_postgresql_flexible_server.this.name
  resource_group_name = azurerm_resource_group.this.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  object_id           = data.azurerm_client_config.current.object_id
  principal_name      = "tessera-db-admin"
  principal_type      = "User"
}

resource "azurerm_postgresql_flexible_server_database" "tessera" {
  name      = "tessera"
  server_id = azurerm_postgresql_flexible_server.this.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

resource "azurerm_postgresql_flexible_server_configuration" "tls" {
  name      = "require_secure_transport"
  server_id = azurerm_postgresql_flexible_server.this.id
  value     = "on"
}

resource "azurerm_postgresql_flexible_server_configuration" "tls_min" {
  name      = "ssl_min_protocol_version"
  server_id = azurerm_postgresql_flexible_server.this.id
  value     = "TLSv1.2"
}

# ---------------------------------------------------------------- identity, Key Vault
resource "azurerm_user_assigned_identity" "app" {
  name                = "id-${var.name}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.tags
}

resource "azurerm_key_vault" "this" {
  name                          = "kv-${var.name}-${substr(sha1(azurerm_resource_group.this.id), 0, 6)}"
  location                      = azurerm_resource_group.this.location
  resource_group_name           = azurerm_resource_group.this.name
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  rbac_authorization_enabled    = true
  purge_protection_enabled      = true
  soft_delete_retention_days    = 30
  # Private by default. Set key_vault_public_network_access = true (and list your IPs in key_vault_allowed_ips)
  # to set secret values from a workstation; the ACL stays default-deny either way.
  public_network_access_enabled = var.key_vault_public_network_access
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
    ip_rules       = var.key_vault_allowed_ips
  }
  tags = local.tags
}

# The app identity may read secrets (and nothing else). Secret VALUES are not managed here (kept out of state):
# az keyvault secret set --vault-name <vault> --name kek --value ...
resource "azurerm_role_assignment" "app_secrets" {
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
}

resource "azurerm_role_assignment" "deployer_secrets" {
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_role_assignment" "acr_pull" {
  count                = var.registry_id == "" ? 0 : 1
  scope                = var.registry_id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
}

# ---------------------------------------------------------------- logging
resource "azurerm_log_analytics_workspace" "this" {
  name                = "log-${var.name}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  tags                = local.tags
}

# ---------------------------------------------------------------- Container Apps
resource "azurerm_container_app_environment" "this" {
  name                           = "cae-${var.name}"
  location                       = azurerm_resource_group.this.location
  resource_group_name            = azurerm_resource_group.this.name
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.this.id
  infrastructure_subnet_id       = azurerm_subnet.apps.id
  zone_redundancy_enabled        = true
  internal_load_balancer_enabled = false
  tags                           = local.tags
}

locals {
  default_url = "https://${var.name}.${azurerm_container_app_environment.this.default_domain}"
  public_url  = var.public_url != "" ? var.public_url : local.default_url
  secret_urls = {
    db-owner-dsn          = "${azurerm_key_vault.this.vault_uri}secrets/db-owner-dsn"
    db-app-dsn            = "${azurerm_key_vault.this.vault_uri}secrets/db-app-dsn"
    kek                   = "${azurerm_key_vault.this.vault_uri}secrets/kek"
    aws-access-key-id     = "${azurerm_key_vault.this.vault_uri}secrets/aws-access-key-id"
    aws-secret-access-key = "${azurerm_key_vault.this.vault_uri}secrets/aws-secret-access-key"
  }
}

resource "azurerm_container_app" "this" {
  name                         = var.name
  container_app_environment_id = azurerm_container_app_environment.this.id
  resource_group_name          = azurerm_resource_group.this.name
  revision_mode                = "Single"
  tags                         = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.app.id]
  }

  registry {
    server   = var.registry_server
    identity = azurerm_user_assigned_identity.app.id
  }

  dynamic "secret" {
    for_each = local.secret_urls
    content {
      name                = secret.key
      key_vault_secret_id = secret.value
      identity            = azurerm_user_assigned_identity.app.id
    }
  }

  ingress {
    external_enabled           = true
    target_port                = 8080
    transport                  = "auto"
    allow_insecure_connections = false
    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  template {
    min_replicas = var.desired_min_replicas
    max_replicas = var.max_replicas

    volume {
      name         = "tessera-data"
      storage_type = "EmptyDir"
    }
    volume {
      name         = "api-tmp"
      storage_type = "EmptyDir"
    }
    volume {
      name         = "ui-tmp"
      storage_type = "EmptyDir"
    }

    http_scale_rule {
      name                = "http"
      concurrent_requests = "80"
    }

    container {
      name   = "ui"
      image  = var.ui_image
      cpu    = 0.25
      memory = "0.5Gi"
      env {
        name  = "API_UPSTREAM"
        value = "127.0.0.1:8000"
      }
      volume_mounts {
        name = "ui-tmp"
        path = "/tmp"
      }
      readiness_probe {
        transport = "HTTP"
        port      = 8080
        path      = "/api/health"
      }
    }

    container {
      name    = "api"
      image   = var.api_image
      args    = ["serve", "-addr", "0.0.0.0:8000"]
      cpu     = 0.75
      memory  = "1.5Gi"
      command = null

      env {
        name  = "TESSERA_ENV"
        value = "prod"
      }
      env {
        name  = "TESSERA_PUBLIC_URL"
        value = local.public_url
      }
      env {
        name  = "TESSERA_COOKIE_SECURE"
        value = "true"
      }
      env {
        name  = "TESSERA_TRUSTED_PROXIES"
        value = join(",", concat(["127.0.0.1/32"], var.trusted_proxy_cidrs))
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
      env {
        name        = "TESSERA_DB"
        secret_name = "db-owner-dsn"
      }
      env {
        name        = "TESSERA_DB_APP"
        secret_name = "db-app-dsn"
      }
      env {
        name        = "TESSERA_KEK"
        secret_name = "kek"
      }
      env {
        name        = "AWS_ACCESS_KEY_ID"
        secret_name = "aws-access-key-id"
      }
      env {
        name        = "AWS_SECRET_ACCESS_KEY"
        secret_name = "aws-secret-access-key"
      }
      volume_mounts {
        name = "tessera-data"
        path = "/var/lib/tessera"
      }
      volume_mounts {
        name = "api-tmp"
        path = "/tmp"
      }
      startup_probe {
        transport               = "HTTP"
        port                    = 8000
        path                    = "/api/health"
        interval_seconds        = 5
        failure_count_threshold = 30
      }
      liveness_probe {
        transport = "HTTP"
        port      = 8000
        path      = "/api/health"
      }
      readiness_probe {
        transport = "HTTP"
        port      = 8000
        path      = "/api/health"
      }
    }
  }

  depends_on = [azurerm_role_assignment.app_secrets, azurerm_role_assignment.acr_pull]
}
