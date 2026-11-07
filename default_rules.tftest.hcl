mock_provider "azurerm" {}

variables {
  resource_group_name = "rg-nsg-test"
}

run "deny_all_by_default" {
  command = plan

  assert {
    condition     = toset(keys(azurerm_network_security_rule.default_rules_for)) == toset(["DenyAllInbound"])
    error_message = "Default inputs must create only DenyAllInbound."
  }

  assert {
    condition = (
      azurerm_network_security_rule.default_rules_for["DenyAllInbound"].priority == 4096 &&
      azurerm_network_security_rule.default_rules_for["DenyAllInbound"].access == "Deny" &&
      azurerm_network_security_rule.default_rules_for["DenyAllInbound"].direction == "Inbound" &&
      azurerm_network_security_rule.default_rules_for["DenyAllInbound"].protocol == "*" &&
      azurerm_network_security_rule.default_rules_for["DenyAllInbound"].source_address_prefix == "*" &&
      azurerm_network_security_rule.default_rules_for["DenyAllInbound"].destination_address_prefix == "*" &&
      azurerm_network_security_rule.default_rules_for["DenyAllInbound"].source_port_range == "*" &&
      azurerm_network_security_rule.default_rules_for["DenyAllInbound"].destination_port_range == "*"
    )
    error_message = "Deny-all priority, direction and traffic scope must remain unchanged."
  }
}

run "production_name_defaults_to_probes" {
  command = plan

  variables {
    security_group_name = "p-network-nsg"
  }

  assert {
    condition     = toset(keys(azurerm_network_security_rule.default_rules_for)) == toset(["AllowAzureLoadbalancerInbound", "DenyAllInbound"])
    error_message = "A lowercase p prefix must default to probes and deny-all, never GatewayManager."
  }
}

run "load_balancer_only" {
  command = plan

  variables {
    allow_azure_load_balancer_inbound = true
  }

  assert {
    condition     = toset(keys(azurerm_network_security_rule.default_rules_for)) == toset(["AllowAzureLoadbalancerInbound", "DenyAllInbound"])
    error_message = "Load Balancer opt-in must not enable GatewayManager traffic."
  }

  assert {
    condition = (
      azurerm_network_security_rule.default_rules_for["AllowAzureLoadbalancerInbound"].priority == 4095 &&
      azurerm_network_security_rule.default_rules_for["AllowAzureLoadbalancerInbound"].source_address_prefix == "AzureLoadbalancer" &&
      azurerm_network_security_rule.default_rules_for["AllowAzureLoadbalancerInbound"].destination_address_prefix == "VirtualNetwork" &&
      azurerm_network_security_rule.default_rules_for["AllowAzureLoadbalancerInbound"].destination_port_range == "*" &&
      azurerm_network_security_rule.default_rules_for["AllowAzureLoadbalancerInbound"].access == "Allow" &&
      azurerm_network_security_rule.default_rules_for["AllowAzureLoadbalancerInbound"].direction == "Inbound"
    )
    error_message = "Load Balancer probes must retain their existing scope and priority."
  }
}

run "production_name_explicit_false" {
  command = plan

  variables {
    security_group_name               = "p-network-nsg"
    allow_azure_load_balancer_inbound = false
  }

  assert {
    condition     = toset(keys(azurerm_network_security_rule.default_rules_for)) == toset(["DenyAllInbound"])
    error_message = "Explicit false must override the production name default."
  }
}

run "microsegmentation_disabled" {
  command = plan

  variables {
    disable_microsegmentation = true
  }

  assert {
    condition     = length(azurerm_network_security_rule.default_rules_for) == 0
    error_message = "Disabling microsegmentation must suppress all module-managed default rules."
  }
}

run "microsegmentation_disabled_with_production_default" {
  command = plan

  variables {
    disable_microsegmentation = true
    security_group_name       = "p-network-nsg"
  }

  assert {
    condition     = length(azurerm_network_security_rule.default_rules_for) == 0
    error_message = "The production name default must not override disabled microsegmentation."
  }
}

run "microsegmentation_disabled_with_load_balancer" {
  command = plan

  variables {
    disable_microsegmentation         = true
    allow_azure_load_balancer_inbound = true
  }

  assert {
    condition     = length(azurerm_network_security_rule.default_rules_for) == 0
    error_message = "Load Balancer opt-in must not override disabled microsegmentation."
  }
}

run "microsegmentation_disabled_with_false" {
  command = plan

  variables {
    disable_microsegmentation         = true
    security_group_name               = "p-network-nsg"
    allow_azure_load_balancer_inbound = false
  }

  assert {
    condition     = length(azurerm_network_security_rule.default_rules_for) == 0
    error_message = "Explicit false must retain disabled microsegmentation behavior."
  }
}

run "production_name_explicit_null" {
  command = plan

  variables {
    security_group_name               = "p"
    allow_azure_load_balancer_inbound = null
  }

  assert {
    condition     = toset(keys(azurerm_network_security_rule.default_rules_for)) == toset(["AllowAzureLoadbalancerInbound", "DenyAllInbound"])
    error_message = "Explicit null and a single lowercase p must use the name-based probe default."
  }
}

run "nonproduction_name_explicit_null" {
  command = plan

  variables {
    security_group_name               = "dev-network-nsg"
    allow_azure_load_balancer_inbound = null
  }

  assert {
    condition     = toset(keys(azurerm_network_security_rule.default_rules_for)) == toset(["DenyAllInbound"])
    error_message = "Null must not allow probes on a non-p name."
  }
}

run "uppercase_prefix_is_not_production" {
  command = plan

  variables {
    security_group_name = "Prod-network-nsg"
  }

  assert {
    condition     = toset(keys(azurerm_network_security_rule.default_rules_for)) == toset(["DenyAllInbound"])
    error_message = "The name prefix check must be case-sensitive."
  }
}

run "embedded_p_is_not_production" {
  command = plan

  variables {
    security_group_name = "nsg-prod"
  }

  assert {
    condition     = toset(keys(azurerm_network_security_rule.default_rules_for)) == toset(["DenyAllInbound"])
    error_message = "Only a leading lowercase p may default to probes."
  }
}

run "production_name_explicit_true" {
  command = plan

  variables {
    security_group_name               = "p-network-nsg"
    allow_azure_load_balancer_inbound = true
  }

  assert {
    condition     = toset(keys(azurerm_network_security_rule.default_rules_for)) == toset(["AllowAzureLoadbalancerInbound", "DenyAllInbound"])
    error_message = "Explicit true must enable probes without duplicate rules."
  }
}

run "nonproduction_name_explicit_false" {
  command = plan

  variables {
    security_group_name               = "dev-network-nsg"
    allow_azure_load_balancer_inbound = false
  }

  assert {
    condition     = toset(keys(azurerm_network_security_rule.default_rules_for)) == toset(["DenyAllInbound"])
    error_message = "Explicit false must keep nonproduction probes disabled."
  }
}
