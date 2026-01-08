# ============================================
# Cardea Infrastructure Variables
# ============================================

variable "is_production" {
  description = "Toggle for production mode (affects SKUs and model selection)"
  type        = bool
  default     = false
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "cardea"
}

variable "location" {
  description = "Primary Azure region for resources"
  type        = string
  default     = "East Asia"
}

variable "ai_location" {
  description = "Azure region for AI services (OpenAI, Search)"
  type        = string
  default     = "swedencentral"
}

# Database Configuration
variable "db_admin_username" {
  description = "PostgreSQL admin username"
  type        = string
  default     = "oracle_admin"
}

variable "db_admin_password" {
  description = "PostgreSQL admin password"
  type        = string
  sensitive   = true
  default     = null  # Must be provided via tfvars or env
}

# Container Image Configuration
variable "oracle_image_tag" {
  description = "Docker image tag for Oracle container"
  type        = string
  default     = "latest"
}

# Sentry Communication
variable "sentry_allowed_ips" {
  description = "List of IP addresses/CIDRs allowed to communicate with Oracle (Sentry locations)"
  type        = list(string)
  default     = []  # Empty means allow all (for dev)
}

variable "sentry_api_key" {
  description = "API key for Sentry-to-Oracle authentication"
  type        = string
  sensitive   = true
  default     = null
}

# Tags
variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    Project     = "Cardea"
    Environment = "Development"
    ManagedBy   = "Terraform"
  }
}
