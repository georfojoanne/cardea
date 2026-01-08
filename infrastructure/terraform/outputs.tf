# ============================================
# Cardea Infrastructure Outputs
# All important values for deployment & config
# ============================================

# ===================
# AI Services
# ===================
output "openai_endpoint" {
  description = "Azure OpenAI endpoint URL"
  value       = azurerm_cognitive_account.openai.endpoint
}

output "openai_deployment_name" {
  description = "Name of the OpenAI model deployment"
  value       = azurerm_cognitive_deployment.oracle_brain.name
}

output "openai_key" {
  description = "Azure OpenAI API key (sensitive)"
  value       = azurerm_cognitive_account.openai.primary_access_key
  sensitive   = true
}

output "search_endpoint" {
  description = "Azure AI Search endpoint URL"
  value       = "https://${azurerm_search_service.search.name}.search.windows.net"
}

output "search_key" {
  description = "Azure AI Search admin key (sensitive)"
  value       = azurerm_search_service.search.primary_key
  sensitive   = true
}

# ===================
# Oracle Backend
# ===================
output "oracle_url" {
  description = "Public URL of the Oracle API"
  value       = "https://${azurerm_container_app.oracle.ingress[0].fqdn}"
}

output "oracle_internal_url" {
  description = "Internal URL for Oracle (within Azure network)"
  value       = "http://${azurerm_container_app.oracle.name}"
}

output "acr_login_server" {
  description = "Azure Container Registry login server"
  value       = azurerm_container_registry.acr.login_server
}

output "acr_admin_username" {
  description = "ACR admin username"
  value       = azurerm_container_registry.acr.admin_username
}

output "acr_admin_password" {
  description = "ACR admin password (sensitive)"
  value       = azurerm_container_registry.acr.admin_password
  sensitive   = true
}

# ===================
# Database
# ===================
output "db_host" {
  description = "PostgreSQL server hostname"
  value       = azurerm_postgresql_flexible_server.oracle_db.fqdn
}

output "db_connection_string" {
  description = "PostgreSQL connection string (sensitive)"
  value       = "postgresql+asyncpg://${var.db_admin_username}:${var.db_admin_password != null ? var.db_admin_password : random_password.db_password.result}@${azurerm_postgresql_flexible_server.oracle_db.fqdn}:5432/cardea_oracle?ssl=require"
  sensitive   = true
}

output "db_password" {
  description = "Generated database password (if not provided)"
  value       = var.db_admin_password != null ? "(user-provided)" : random_password.db_password.result
  sensitive   = true
}

# ===================
# Redis Cache
# ===================
output "redis_host" {
  description = "Redis cache hostname"
  value       = azurerm_redis_cache.oracle_redis.hostname
}

output "redis_connection_string" {
  description = "Redis connection string (sensitive)"
  value       = "rediss://:${azurerm_redis_cache.oracle_redis.primary_access_key}@${azurerm_redis_cache.oracle_redis.hostname}:${azurerm_redis_cache.oracle_redis.ssl_port}/0"
  sensitive   = true
}

# ===================
# Dashboard
# ===================
output "dashboard_hostname" {
  description = "Dashboard static web app hostname"
  value       = azurerm_static_web_app.dashboard.default_host_name
}

# ===================
# Sentry Integration
# ===================
output "sentry_api_key" {
  description = "API key for Sentry-to-Oracle communication (sensitive)"
  value       = var.sentry_api_key != null ? var.sentry_api_key : random_password.sentry_api_key.result
  sensitive   = true
}

output "sentry_webhook_url" {
  description = "Webhook URL for Sentry to send alerts to Oracle"
  value       = "https://${azurerm_container_app.oracle.ingress[0].fqdn}/api/alerts"
}

# ===================
# Environment Info
# ===================
output "current_mode" {
  description = "Current deployment mode"
  value       = var.is_production ? "PRODUCTION" : "DEVELOPMENT"
}

output "resource_group" {
  description = "Resource group name"
  value       = azurerm_resource_group.cardea_rg.name
}

# ===================
# Sentry Configuration Export
# ===================
output "sentry_env_config" {
  description = "Environment variables to set on Sentry edge device"
  value = <<-EOT
    # Cardea Sentry Configuration
    # Add these to your Sentry .env file or docker-compose.yml
    
    ORACLE_WEBHOOK_URL=https://${azurerm_container_app.oracle.ingress[0].fqdn}/api/alerts
    ORACLE_API_KEY=${var.sentry_api_key != null ? var.sentry_api_key : random_password.sentry_api_key.result}
    SENTRY_ID=sentry_001
  EOT
  sensitive = true
}
