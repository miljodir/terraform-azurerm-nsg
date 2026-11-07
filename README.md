# Network Security Group

[![Changelog](https://img.shields.io/badge/changelog-release-green.svg)](https://github.com/miljodir/terraform-azurerm-nsg/wiki/main#changelog)
[![TF Registry](https://img.shields.io/badge/terraform-registry-blue.svg)](https://registry.terraform.io/modules/miljodir/nsg/azurerm/)

Heavily influenced by another NSG module found on the internet, but I can't find the link anymore. If you recognize your code, please let us know so we can give you credit.

Adds deny-all inbound by default, with opt-in Azure infrastructure exceptions and custom rules for application traffic.

## Inbound policy

With `disable_microsegmentation = false` (the default), `DenyAllInbound` remains at priority 4096. Custom rules must use priorities 100-4049 and are evaluated before the infrastructure rules and deny-all. The deny-all overrides Azure's built-in inbound allows, including virtual-network traffic and load-balancer probes. Outbound rules are unchanged.

| Rule | Priority | Use case | Opt-in |
| --- | --- | --- | --- |
| `AllowApplicationGatewayInfrastructureInbound` | 4050 | `GatewayManager` to ports 65200-65535 for infrastructure management of Application Gateway v2 instances in this subnet. | `allow_application_gateway_infrastructure_inbound = true` |
| `AllowAzureLoadbalancerInbound` | 4095 | `AzureLoadbalancer` health probes to `VirtualNetwork`, all ports; required for load-balanced workloads and Application Gateway infrastructure when deny-all overrides Azure's built-in probe allow. | Either flag below |
| `DenyAllInbound` | 4096 | Deny inbound traffic not explicitly allowed by higher-priority rules. | Always enabled unless microsegmentation is disabled |

Both infrastructure flags default to `false`:

- `allow_application_gateway_infrastructure_inbound`: enable on the **dedicated subnet hosting standard Application Gateway v2 without Network Isolation**, not on backend subnets merely reachable by it. This flag creates **both** infrastructure allow rules, so the load-balancer flag is not also needed.
- `allow_azure_load_balancer_inbound`: enable on subnets whose workloads need Azure Load Balancer health probes, including network-isolated private Application Gateway v2 hosting subnets. This flag alone creates only the probe rule; it does not allow load-balanced client traffic. Existing narrower custom rules may already permit the required probes, in which case this broad exception is unnecessary.

These exceptions are unnecessary on ordinary subnets. Application Gateway client/listener traffic still requires custom rules on its hosting subnet. Backend application traffic and Application Gateway backend probes originate from the gateway subnet, not `GatewayManager` or `AzureLoadBalancer`: use custom rules permitting the gateway subnet CIDR to the required backend application ports. Neither opt-in flag grants that access.

Setting `disable_microsegmentation = true` retains the existing behavior: none of these module-managed default rules are created, regardless of the flags, and Azure's built-in NSG rules apply alongside custom rules.

See Microsoft's [Application Gateway infrastructure requirements](https://learn.microsoft.com/en-us/azure/application-gateway/configuration-infrastructure#network-security-groups) and [Azure Load Balancer health probes](https://learn.microsoft.com/en-us/azure/load-balancer/load-balancer-custom-probe-overview).

The GatewayManager requirement applies to standard deployments without Network Isolation. [Private deployments with Network Isolation](https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-private-deployment#network-security-group-control) still require inbound `AzureLoadBalancer` health probes but do **not** require `GatewayManager`. For these hosting subnets, keep `allow_application_gateway_infrastructure_inbound = false` and set `allow_azure_load_balancer_inbound = true`, unless existing custom rules already permit the required probes.

## Migration (minor release with a compatibility warning)

Previously, both infrastructure allow rules were created for every NSG with microsegmentation enabled. This update is classified as a **minor release (1.4.0)** at the user's request, but upgrading with unchanged inputs removes both allow rules while preserving deny-all inbound. **This changes existing behavior and can disrupt infrastructure operations or workload health checks.** Before upgrading, opt in on standard Application Gateway v2 hosting subnets using the Application Gateway flag, and on network-isolated private gateway or other load-balancer probe subnets using only the load-balancer flag. Review existing custom rules first: narrower rules may already permit the required traffic. Ordinary backend subnets should keep both flags disabled and use explicit application rules.

For direct NSG module callers, set the relevant module input. Virtual-network module callers should opt in per subnet using the corresponding inputs exposed by that module.

```hcl
module "application_gateway_nsg" {
  source = "miljodir/nsg/azurerm"

  resource_group_name                              = "rg-network"
  security_group_name                              = "nsg-application-gateway"
  allow_application_gateway_infrastructure_inbound = true
}
```

## Tests

GitHub Actions runs `terraform fmt -check -recursive -diff`, `terraform init -backend=false -input=false`, `terraform validate`, and `terraform test`. The tests use a mocked AzureRM provider, require Terraform 1.7 or newer, and cover all combinations of the infrastructure flags and `disable_microsegmentation` without Azure credentials or deployments.
