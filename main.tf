locals {
  # Add default deny everything rule with high priority
  default_rules = [
    {
      name                       = "AllowApplicationGatewayInfrastructureInbound"
      description                = "Allows inbound traffic for Azure Application Gateway v2 infrastructure"
      protocol                   = "*"
      source_port_range          = "*"
      destination_port_range     = "65200-65535"
      source_address_prefix      = "GatewayManager"
      destination_address_prefix = "*"
      access                     = "Allow"
      priority                   = 4050
      direction                  = "Inbound"
    },
    {
      name                       = "AllowAzureLoadbalancerInbound"
      description                = "Allows inbound traffic for Azure Load balancer probes"
      protocol                   = "*"
      source_port_range          = "*"
      destination_port_range     = "*"
      source_address_prefix      = "AzureLoadbalancer"
      destination_address_prefix = "VirtualNetwork"
      access                     = "Allow"
      priority                   = 4095
      direction                  = "Inbound"
    },
    {
      name                       = "DenyAllInbound"
      description                = "Denies all inbound traffic not explicitly allowed above"
      protocol                   = "*"
      source_port_range          = "*"
      destination_port_range     = "*"
      source_address_prefix      = "*"
      destination_address_prefix = "*"
      access                     = "Deny"
      priority                   = 4096
      direction                  = "Inbound"
    }
  ]
}

resource "azurerm_network_security_group" "nsg" {
  name                = var.security_group_name
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

#############################
#  Detailed security rules  #
#############################

resource "azurerm_network_security_rule" "custom_rules" {
  count = var.use_for_each ? 0 : length(var.custom_rules)

  name                                       = lookup(var.custom_rules[count.index], "name", "default_rule_name")
  priority                                   = lookup(var.custom_rules[count.index], "priority")
  direction                                  = lookup(var.custom_rules[count.index], "direction", "Any")
  access                                     = lookup(var.custom_rules[count.index], "access", "Deny")
  protocol                                   = lookup(var.custom_rules[count.index], "protocol", "*")
  source_port_range                          = lookup(var.custom_rules[count.index], "source_port_range", "*") == "*" ? "*" : null
  source_port_ranges                         = lookup(var.custom_rules[count.index], "source_port_range", "*") == "*" ? null : split(",", var.custom_rules[count.index].source_port_range)
  destination_port_range                     = lookup(var.custom_rules[count.index], "destination_port_range", null)
  destination_port_ranges                    = lookup(var.custom_rules[count.index], "destination_port_ranges", null)
  source_address_prefix                      = lookup(var.custom_rules[count.index], "source_address_prefix", null)
  source_address_prefixes                    = lookup(var.custom_rules[count.index], "source_address_prefixes", null)
  destination_address_prefix                 = lookup(var.custom_rules[count.index], "destination_application_security_group_ids", null) == null && lookup(var.custom_rules[count.index], "destination_address_prefixes", null) == null ? lookup(var.custom_rules[count.index], "destination_address_prefix", "*") : null
  destination_address_prefixes               = lookup(var.custom_rules[count.index], "destination_application_security_group_ids", null) == null ? lookup(var.custom_rules[count.index], "destination_address_prefixes", null) : null
  description                                = lookup(var.custom_rules[count.index], "description", "Security rule for ${lookup(var.custom_rules[count.index], "name", "default_rule_name")}")
  resource_group_name                        = var.resource_group_name
  network_security_group_name                = azurerm_network_security_group.nsg.name
  source_application_security_group_ids      = lookup(var.custom_rules[count.index], "source_application_security_group_ids", null)
  destination_application_security_group_ids = lookup(var.custom_rules[count.index], "destination_application_security_group_ids", null)
}

resource "azurerm_network_security_rule" "custom_rules_for" {
  for_each = { for value in var.custom_rules : value.name => value if var.use_for_each }

  access                                     = lookup(each.value, "access", "Allow")
  direction                                  = lookup(each.value, "direction", "Inbound")
  name                                       = lookup(each.value, "name", "default_rule_name")
  network_security_group_name                = azurerm_network_security_group.nsg.name
  priority                                   = each.value.priority
  protocol                                   = lookup(each.value, "protocol", "*")
  resource_group_name                        = var.resource_group_name
  description                                = lookup(each.value, "description", "Security rule for ${lookup(each.value, "name", "default_rule_name")}")
  destination_address_prefix                 = lookup(each.value, "destination_application_security_group_ids", null) == null && lookup(each.value, "destination_address_prefixes", null) == null ? lookup(each.value, "destination_address_prefix", "*") : null
  destination_address_prefixes               = lookup(each.value, "destination_application_security_group_ids", null) == null ? lookup(each.value, "destination_address_prefixes", null) : null
  destination_application_security_group_ids = lookup(each.value, "destination_application_security_group_ids", null)
  destination_port_range                     = lookup(each.value, "destination_port_range", null)
  destination_port_ranges                    = lookup(each.value, "destination_port_ranges", null)
  source_address_prefix                      = lookup(each.value, "source_application_security_group_ids", null) == null && lookup(each.value, "source_address_prefixes", null) == null ? lookup(each.value, "source_address_prefix", "*") : null
  source_address_prefixes                    = lookup(each.value, "source_application_security_group_ids", null) == null ? lookup(each.value, "source_address_prefixes", null) : null
  source_application_security_group_ids      = lookup(each.value, "source_application_security_group_ids", null)
  source_port_range                          = lookup(each.value, "source_port_range", "*") == "*" ? "*" : null
  source_port_ranges                         = lookup(each.value, "source_port_range", "*") == "*" ? null : [for r in split(",", each.value.source_port_range) : trimspace(r)]

  lifecycle {
    precondition {
      condition     = try(each.value.priority >= 100 && each.value.priority < 4050, false)
      error_message = "Precondition failed: custom rules must be configured with priority between 100 and 4049"
    }
  }
}

resource "azurerm_network_security_rule" "default_rules_for" {
  for_each = { for value in local.default_rules : value.name => value if var.disable_microsegmentation == false }

  access                                     = lookup(each.value, "access", "Deny")
  direction                                  = lookup(each.value, "direction", "Any")
  name                                       = lookup(each.value, "name")
  network_security_group_name                = azurerm_network_security_group.nsg.name
  priority                                   = each.value.priority
  protocol                                   = lookup(each.value, "protocol", "*")
  resource_group_name                        = var.resource_group_name
  description                                = lookup(each.value, "description", "Security rule for ${lookup(each.value, "name", "default_rule_name")}")
  destination_address_prefix                 = lookup(each.value, "destination_address_prefix", null)
  destination_address_prefixes               = lookup(each.value, "destination_address_prefixes", null)
  destination_application_security_group_ids = lookup(each.value, "destination_application_security_group_ids", null)
  destination_port_range                     = lookup(each.value, "destination_port_range", null)
  source_address_prefix                      = lookup(each.value, "source_address_prefix", null)
  source_address_prefixes                    = lookup(each.value, "source_address_prefixes", null)
  source_application_security_group_ids      = lookup(each.value, "source_application_security_group_ids", null)
  source_port_range                          = lookup(each.value, "source_port_range", "*") == "*" ? "*" : null
  source_port_ranges                         = lookup(each.value, "source_port_range", "*") == "*" ? null : [for r in split(",", each.value.source_port_range) : trimspace(r)]

  lifecycle {
    precondition {
      condition     = try(each.value.priority >= 100 && each.value.priority <= 4096, false)
      error_message = "Precondition failed: 'predefined_rules.priority' must be provided and configured between 100 and 4096 for predefined rules if 'var.use_for_each' is set to true."
    }
  }
}
