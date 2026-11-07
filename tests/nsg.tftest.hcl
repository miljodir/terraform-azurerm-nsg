mock_provider "azurerm" {}

variables {
  resource_group_name = "rg-test"
  security_group_name = "nsg-test"
}

run "defaults_create_nsg_with_default_rules" {
  command = plan

  assert {
    condition     = azurerm_network_security_group.nsg.name == "nsg-test"
    error_message = "NSG name should come from security_group_name."
  }

  assert {
    condition     = azurerm_network_security_group.nsg.location == "norwayeast"
    error_message = "Location should default to norwayeast."
  }

  assert {
    condition = toset(keys(azurerm_network_security_rule.default_rules_for)) == toset([
      "AllowApplicationGatewayInfrastructureInbound",
      "AllowAzureLoadbalancerInbound",
      "DenyAllInbound",
    ])
    error_message = "All three default rules should be created when microsegmentation is enabled."
  }

  assert {
    condition     = azurerm_network_security_rule.default_rules_for["DenyAllInbound"].access == "Deny"
    error_message = "DenyAllInbound must deny traffic."
  }

  assert {
    condition     = azurerm_network_security_rule.default_rules_for["DenyAllInbound"].priority == 4096
    error_message = "DenyAllInbound must use the lowest priority (4096)."
  }

  assert {
    condition     = length(azurerm_network_security_rule.custom_rules_for) == 0
    error_message = "No custom rules should be created by default."
  }
}

run "disable_microsegmentation_removes_default_rules" {
  command = plan

  variables {
    disable_microsegmentation = true
  }

  assert {
    condition     = length(azurerm_network_security_rule.default_rules_for) == 0
    error_message = "Default rules must not be created when microsegmentation is disabled."
  }
}

run "custom_rule_defaults" {
  command = plan

  variables {
    custom_rules = [
      {
        name                   = "AllowHttpsInbound"
        priority               = 200
        destination_port_range = "443"
      }
    ]
  }

  assert {
    condition     = azurerm_network_security_rule.custom_rules_for["AllowHttpsInbound"].access == "Allow"
    error_message = "Custom rules should default to Allow."
  }

  assert {
    condition     = azurerm_network_security_rule.custom_rules_for["AllowHttpsInbound"].direction == "Inbound"
    error_message = "Custom rules should default to Inbound."
  }

  assert {
    condition     = azurerm_network_security_rule.custom_rules_for["AllowHttpsInbound"].protocol == "*"
    error_message = "Custom rules should default to protocol '*'."
  }

  assert {
    condition     = azurerm_network_security_rule.custom_rules_for["AllowHttpsInbound"].source_address_prefix == "*"
    error_message = "Source address prefix should default to '*'."
  }

  assert {
    condition     = azurerm_network_security_rule.custom_rules_for["AllowHttpsInbound"].description == "Security rule for AllowHttpsInbound"
    error_message = "Description should be generated from the rule name."
  }
}

run "subnet_names_resolve_to_cidr" {
  command = plan

  variables {
    subnets = {
      frontend = "10.0.1.0/24"
      backend  = "10.0.2.0/24"
    }
    custom_rules = [
      {
        name                       = "AllowFrontendToBackend"
        priority                   = 300
        source_address_prefix      = "frontend"
        destination_address_prefix = "backend"
        destination_port_range     = "8080"
      },
      {
        name                       = "AllowServiceTag"
        priority                   = 310
        source_address_prefix      = "AzureLoadBalancer"
        destination_address_prefix = "VirtualNetwork"
        destination_port_range     = "*"
      }
    ]
  }

  assert {
    condition     = azurerm_network_security_rule.custom_rules_for["AllowFrontendToBackend"].source_address_prefix == "10.0.1.0/24"
    error_message = "Subnet name used as source should resolve to its CIDR."
  }

  assert {
    condition     = azurerm_network_security_rule.custom_rules_for["AllowFrontendToBackend"].destination_address_prefix == "10.0.2.0/24"
    error_message = "Subnet name used as destination should resolve to its CIDR."
  }

  assert {
    condition     = azurerm_network_security_rule.custom_rules_for["AllowServiceTag"].source_address_prefix == "AzureLoadBalancer"
    error_message = "Values that are not subnet names should pass through unchanged."
  }
}

run "address_prefixes_take_precedence" {
  command = plan

  variables {
    custom_rules = [
      {
        name                         = "AllowFromList"
        priority                     = 400
        source_address_prefixes      = ["192.0.2.0/24", "198.51.100.0/24"]
        destination_address_prefixes = ["10.0.0.0/24"]
        destination_port_range       = "22"
      }
    ]
  }

  assert {
    condition     = azurerm_network_security_rule.custom_rules_for["AllowFromList"].source_address_prefix == null
    error_message = "source_address_prefix must be null when source_address_prefixes is set."
  }

  assert {
    condition     = toset(azurerm_network_security_rule.custom_rules_for["AllowFromList"].source_address_prefixes) == toset(["192.0.2.0/24", "198.51.100.0/24"])
    error_message = "source_address_prefixes should be passed through."
  }

  assert {
    condition     = azurerm_network_security_rule.custom_rules_for["AllowFromList"].destination_address_prefix == null
    error_message = "destination_address_prefix must be null when destination_address_prefixes is set."
  }
}

run "source_port_range_list_is_split" {
  command = plan

  variables {
    custom_rules = [
      {
        name                   = "AllowSourcePorts"
        priority               = 500
        source_port_range      = "1000, 2000-2100"
        destination_port_range = "443"
      }
    ]
  }

  assert {
    condition     = azurerm_network_security_rule.custom_rules_for["AllowSourcePorts"].source_port_range == null
    error_message = "source_port_range must be null when a list of ports is given."
  }

  assert {
    condition     = toset(azurerm_network_security_rule.custom_rules_for["AllowSourcePorts"].source_port_ranges) == toset(["1000", "2000-2100"])
    error_message = "Comma separated source ports should be split and trimmed."
  }
}

run "custom_rule_priority_too_low_is_rejected" {
  command = plan

  variables {
    custom_rules = [
      {
        name     = "TooLow"
        priority = 99
      }
    ]
  }

  expect_failures = [azurerm_network_security_rule.custom_rules_for]
}

run "custom_rule_priority_in_reserved_range_is_rejected" {
  command = plan

  variables {
    custom_rules = [
      {
        name     = "Reserved"
        priority = 4050
      }
    ]
  }

  expect_failures = [azurerm_network_security_rule.custom_rules_for]
}
