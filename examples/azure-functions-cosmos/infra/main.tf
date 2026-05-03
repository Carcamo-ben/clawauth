terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "azurerm" {
  features {}
}

variable "resource_group" { type = string }
variable "location"       { type = string }
variable "name_prefix"    { type = string }

resource "random_string" "suffix" {
  length  = 6
  upper   = false
  special = false
  numeric = true
}

locals {
  short = lower(replace(var.name_prefix, "/[^a-z0-9]/", ""))
  base  = substr("${local.short}${random_string.suffix.result}", 0, 18)
}

resource "azurerm_resource_group" "rg" {
  name     = var.resource_group
  location = var.location
}

resource "azurerm_storage_account" "fn" {
  name                          = "st${local.base}"
  resource_group_name           = azurerm_resource_group.rg.name
  location                      = azurerm_resource_group.rg.location
  account_tier                  = "Standard"
  account_replication_type      = "LRS"
  min_tls_version               = "TLS1_2"
  public_network_access_enabled = true
}

resource "azurerm_application_insights" "ai" {
  name                = "ai-${local.base}"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  application_type    = "web"
}

resource "azurerm_cosmosdb_account" "cosmos" {
  name                          = "cosmos-${local.base}"
  location                      = azurerm_resource_group.rg.location
  resource_group_name           = azurerm_resource_group.rg.name
  offer_type                    = "Standard"
  kind                          = "GlobalDocumentDB"
  public_network_access_enabled = true
  free_tier_enabled             = true
  consistency_policy {
    consistency_level = "Session"
  }
  geo_location {
    location          = azurerm_resource_group.rg.location
    failover_priority = 0
  }
  capabilities {
    name = "EnableServerless"
  }
}

resource "azurerm_cosmosdb_sql_database" "db" {
  name                = "clawauthdemo"
  resource_group_name = azurerm_resource_group.rg.name
  account_name        = azurerm_cosmosdb_account.cosmos.name
}

resource "azurerm_service_plan" "plan" {
  name                = "plan-${local.base}"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  os_type             = "Linux"
  sku_name            = "Y1"
}

resource "azurerm_linux_function_app" "fn" {
  name                       = "func-${local.base}"
  resource_group_name        = azurerm_resource_group.rg.name
  location                   = azurerm_resource_group.rg.location
  service_plan_id            = azurerm_service_plan.plan.id
  storage_account_name       = azurerm_storage_account.fn.name
  storage_account_access_key = azurerm_storage_account.fn.primary_access_key
  https_only                 = true

  site_config {
    application_insights_connection_string = azurerm_application_insights.ai.connection_string
    application_stack {
      node_version = "20"
    }
    cors {
      allowed_origins = ["*"]
    }
  }

  app_settings = {
    FUNCTIONS_WORKER_RUNTIME = "node"
    WEBSITE_RUN_FROM_PACKAGE = "1"
    # CLAWAUTH_JWT_SECRET, GOOGLE_CLIENT_ID, COSMOS_CONN are set by the deploy script
    # AFTER terraform apply, so they don't end up in tfstate.
  }

  lifecycle {
    ignore_changes = [
      app_settings["CLAWAUTH_JWT_SECRET"],
      app_settings["GOOGLE_CLIENT_ID"],
      app_settings["COSMOS_CONN"]
    ]
  }
}

output "function_app_name"   { value = azurerm_linux_function_app.fn.name }
output "function_app_host"   { value = azurerm_linux_function_app.fn.default_hostname }
output "cosmos_account_name" { value = azurerm_cosmosdb_account.cosmos.name }
output "resource_group_name" { value = azurerm_resource_group.rg.name }
