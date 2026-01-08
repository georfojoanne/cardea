# ============================================
# Cardea Dashboard - Azure Static Web App
# Static hosting for the React frontend
# ============================================

# Static Web App for dashboard
resource "azurerm_static_web_app" "dashboard" {
  name                = "${var.project_name}-dashboard"
  resource_group_name = azurerm_resource_group.cardea_rg.name
  location            = var.location
  
  # Free tier for dev, Standard for prod (custom domains, more bandwidth)
  sku_tier = var.is_production ? "Standard" : "Free"
  sku_size = var.is_production ? "Standard" : "Free"

  tags = var.tags
}

# Output the deployment token (used by GitHub Actions)
# Note: This is sensitive and should be stored as a GitHub secret
output "dashboard_deployment_token" {
  description = "Deployment token for Azure Static Web App (use as AZURE_STATIC_WEB_APPS_API_TOKEN secret)"
  value       = azurerm_static_web_app.dashboard.api_key
  sensitive   = true
}

output "dashboard_url" {
  description = "URL of the deployed dashboard"
  value       = "https://${azurerm_static_web_app.dashboard.default_host_name}"
}

# Custom domain configuration (optional, for production)
# resource "azurerm_static_web_app_custom_domain" "dashboard" {
#   count             = var.is_production ? 1 : 0
#   static_web_app_id = azurerm_static_web_app.dashboard.id
#   domain_name       = "dashboard.cardea.example.com"
#   validation_type   = "cname-delegation"
# }
