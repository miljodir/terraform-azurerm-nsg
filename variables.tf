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
# All the fields are required.
variable "custom_rules" {
  description = "Security rules for the network security group using this format name = [priority, direction, access, protocol, source_port_range, destination_port_range, source_address_prefix, destination_address_prefix, description]"
  type        = any
  default     = []
}

variable "disable_microsegmentation" {
  type        = bool
  default     = false
  description = "Disable microsegmentation between subnets? Should only be used if necessary. Defaults to false."
}

# TODO - consider enabling to true if bumping major version. Adding and removing rules is a hassle with count
variable "use_for_each" {
  type        = bool
  default     = false
  description = "Use for_each instead of count. Defaults to false."
}
