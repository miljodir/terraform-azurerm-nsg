mock_provider "azurerm" {}

variables {
  resource_group_name = "rg-test"
  security_group_name = "nsg-test"
}

run "omitted_source_port_defaults_to_wildcard" {
  command = plan

  variables {
    custom_rules = [{
      name                   = "OmittedSourcePort"
      priority               = 200
      destination_port_range = "443"
    }]
  }

  assert {
    condition = (
      azurerm_network_security_rule.custom_rules_for["OmittedSourcePort"].source_port_range == "*" &&
      azurerm_network_security_rule.custom_rules_for["OmittedSourcePort"].source_port_ranges == null
    )
    error_message = "An omitted source port must use only the singular wildcard."
  }
}

run "null_source_port_defaults_to_wildcard" {
  command = plan

  variables {
    custom_rules = [{
      name                   = "NullSourcePort"
      priority               = 200
      source_port_range      = null
      destination_port_range = "443"
    }]
  }

  assert {
    condition = (
      azurerm_network_security_rule.custom_rules_for["NullSourcePort"].source_port_range == "*" &&
      azurerm_network_security_rule.custom_rules_for["NullSourcePort"].source_port_ranges == null
    )
    error_message = "An explicit null source port must use only the singular wildcard."
  }
}

run "explicit_wildcard_uses_singular_source_port" {
  command = plan

  variables {
    security_group_name = "p-nsg-test"
    custom_rules = [{
      name                   = "WildcardSourcePort"
      priority               = 200
      source_port_range      = "*"
      destination_port_range = "443"
    }]
  }

  assert {
    condition = (
      azurerm_network_security_rule.custom_rules_for["WildcardSourcePort"].source_port_range == "*" &&
      azurerm_network_security_rule.custom_rules_for["WildcardSourcePort"].source_port_ranges == null
    )
    error_message = "An explicit wildcard must retain the singular source-port attribute."
  }

  assert {
    condition = (
      length(azurerm_network_security_rule.default_rules_for) == 2 &&
      alltrue([for rule in azurerm_network_security_rule.default_rules_for :
        rule.source_port_range == "*" && rule.source_port_ranges == null
      ])
    )
    error_message = "Both generated default rules must retain singular wildcard source ports."
  }
}

run "single_source_port_uses_port_ranges" {
  command = plan

  variables {
    custom_rules = [{
      name                   = "SingleSourcePort"
      priority               = 200
      source_port_range      = "1000"
      destination_port_range = "443"
    }]
  }

  assert {
    condition = (
      azurerm_network_security_rule.custom_rules_for["SingleSourcePort"].source_port_range == null &&
      toset(azurerm_network_security_rule.custom_rules_for["SingleSourcePort"].source_port_ranges) == toset(["1000"])
    )
    error_message = "A single non-wildcard port must retain the plural source-port attribute."
  }
}

run "empty_source_port_is_not_replaced_with_wildcard" {
  command = plan

  variables {
    custom_rules = [{
      name                   = "EmptySourcePort"
      priority               = 200
      source_port_range      = ""
      destination_port_range = "443"
    }]
  }

  assert {
    condition = (
      azurerm_network_security_rule.custom_rules_for["EmptySourcePort"].source_port_range == null &&
      toset(azurerm_network_security_rule.custom_rules_for["EmptySourcePort"].source_port_ranges) == toset([""])
    )
    error_message = "An empty source-port string must retain existing parsing, not broaden to '*'."
  }
}

run "comma_separated_source_ports_are_split_and_trimmed" {
  command = plan

  variables {
    custom_rules = [{
      name                   = "MultipleSourcePorts"
      priority               = 200
      source_port_range      = " 1000, 2000-2100 "
      destination_port_range = "443"
    }]
  }

  assert {
    condition = (
      azurerm_network_security_rule.custom_rules_for["MultipleSourcePorts"].source_port_range == null &&
      toset(azurerm_network_security_rule.custom_rules_for["MultipleSourcePorts"].source_port_ranges) == toset(["1000", "2000-2100"])
    )
    error_message = "Comma-separated ports and ranges must still be split and trimmed."
  }
}
