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

variable "allow_application_gateway_infrastructure_inbound" {
  description = "Allow GatewayManager on ports 65200-65535 and AzureLoadBalancer probes for subnets hosting standard Application Gateway v2 without Network Isolation. Private network-isolated gateways need only the load-balancer allowance. Does not allow client or backend application traffic. Ignored when disable_microsegmentation is true."
  type        = bool
  default     = false
}

variable "allow_azure_load_balancer_inbound" {
  description = "Allow AzureLoadBalancer health probes for load-balanced workloads and network-isolated private Application Gateway v2. Standard Application Gateway infrastructure opt-in already includes this rule. Unnecessary if custom rules already permit required probes. Ignored when disable_microsegmentation is true."
  type        = bool
  default     = false
}

variable "subnets" {
  description = "A map of subnet names to CIDR ranges in the virtual network, for use in NSG rules"
  type        = map(string)
  default     = {}
}