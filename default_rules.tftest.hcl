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

run "application_gateway_includes_probes" {
  command = plan

  variables {
    allow_application_gateway_infrastructure_inbound = true
  }

  assert {
    condition     = toset(keys(azurerm_network_security_rule.default_rules_for)) == toset(["AllowApplicationGatewayInfrastructureInbound", "AllowAzureLoadbalancerInbound", "DenyAllInbound"])
    error_message = "Application Gateway opt-in alone must create both infrastructure allows and deny-all."
  }

  assert {
    condition = (
      azurerm_network_security_rule.default_rules_for["AllowApplicationGatewayInfrastructureInbound"].priority == 4050 &&
      azurerm_network_security_rule.default_rules_for["AllowApplicationGatewayInfrastructureInbound"].source_address_prefix == "GatewayManager" &&
      azurerm_network_security_rule.default_rules_for["AllowApplicationGatewayInfrastructureInbound"].destination_port_range == "65200-65535" &&
      azurerm_network_security_rule.default_rules_for["AllowApplicationGatewayInfrastructureInbound"].access == "Allow" &&
      azurerm_network_security_rule.default_rules_for["AllowApplicationGatewayInfrastructureInbound"].direction == "Inbound"
    )
    error_message = "Application Gateway infrastructure traffic must retain its existing scope and priority."
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

run "both_flags_no_duplicate_rules" {
  command = plan

  variables {
    allow_application_gateway_infrastructure_inbound = true
    allow_azure_load_balancer_inbound                = true
  }

  assert {
    condition     = toset(keys(azurerm_network_security_rule.default_rules_for)) == toset(["AllowApplicationGatewayInfrastructureInbound", "AllowAzureLoadbalancerInbound", "DenyAllInbound"])
    error_message = "Enabling both flags must create each infrastructure rule exactly once alongside deny-all."
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

run "microsegmentation_disabled_with_gateway" {
  command = plan

  variables {
    disable_microsegmentation                        = true
    allow_application_gateway_infrastructure_inbound = true
  }

  assert {
    condition     = length(azurerm_network_security_rule.default_rules_for) == 0
    error_message = "Application Gateway opt-in must not override disabled microsegmentation."
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

run "microsegmentation_disabled_with_both" {
  command = plan

  variables {
    disable_microsegmentation                        = true
    allow_application_gateway_infrastructure_inbound = true
    allow_azure_load_balancer_inbound                = true
  }

  assert {
    condition     = length(azurerm_network_security_rule.default_rules_for) == 0
    error_message = "Both opt-ins must not override disabled microsegmentation."
  }
}
