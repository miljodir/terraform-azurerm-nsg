# Network Security Group definition
variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
}

variable "security_group_name" {
  description = "Network security group name"
  type        = string
  default     = "nsg"
}

variable "tags" {
  description = "The tags to associate with your network security group."
  type        = map(string)
  default     = {}
}

variable "location" {
  description = "Location (Azure Region) for the network security group."
  type        = string
  default     = "norwayeast"
}

# Security Rules definition 

# Custom security rules
# [priority, direction, access, protocol, source_port_range, destination_port_range, description]"
variable "custom_rules" {
  description = "Security rules for the network security group using this format name = [priority, direction, access, protocol, source_port_range, destination_port_range, source_address_prefix, destination_address_prefix, description]. Omitted or null source_port_range defaults to '*'; comma-separated source ports and ranges are split and trimmed."
  type        = any
  default     = []
}

variable "disable_microsegmentation" {
  type        = bool
  default     = false
  description = "Disable microsegmentation between subnets? Should only be used if necessary. Defaults to false."
}

variable "allow_azure_load_balancer_inbound" {
  description = "Allow AzureLoadBalancer health probes. Null defaults to whether security_group_name starts with lowercase p; explicit true or false overrides the name-based default. Unnecessary if custom rules already permit required probes. Ignored when disable_microsegmentation is true."
  type        = bool
  default     = null
  nullable    = true
}

variable "subnets" {
  description = "A map of subnet names to CIDR ranges in the virtual network, for use in NSG rules"
  type        = map(string)
  default     = {}
}