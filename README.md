# Network Security Group

[![Changelog](https://img.shields.io/badge/changelog-release-green.svg)](https://github.com/miljodir/terraform-azurerm-nsg/wiki/main#changelog)
[![TF Registry](https://img.shields.io/badge/terraform-registry-blue.svg)](https://registry.terraform.io/modules/miljodir/nsg/azurerm/)

Heavily influenced by another NSG module found on the internet, but I can't find the link anymore. If you recognize your code, please let us know so we can give you credit.

Adds deny-all inbound by default, a name-based Azure Load Balancer probe allowance with explicit overrides, and custom rules for application traffic. The module does not create a GatewayManager rule.

## Inbound policy

With `disable_microsegmentation = false` (the default), `DenyAllInbound` remains at priority 4096. Custom rules must use priorities 100-4049 and are evaluated before the probe rule and deny-all. The deny-all overrides Azure's built-in inbound allows, including virtual-network traffic and load-balancer probes. Outbound rules are unchanged.

| Rule | Priority | Use case | Enabled when |
| --- | --- | --- | --- |
| `AllowAzureLoadbalancerInbound` | 4095 | `AzureLoadbalancer` health probes to `VirtualNetwork`, all ports. | Resolved load-balancer allowance is true |
| `DenyAllInbound` | 4096 | Deny inbound traffic not explicitly allowed by higher-priority rules. | Always unless microsegmentation is disabled |

`allow_azure_load_balancer_inbound` is a nullable boolean, defaulting to `null`:

| Input | Behavior |
| --- | --- |
| Omitted or `null` | Enable probes if the effective NSG name (`security_group_name`) starts with lowercase `p`, following the production naming convention. |
| `true` | Enable probes regardless of the NSG name. |
| `false` | Disable the module probe allowance regardless of the NSG name. |

The check is case-sensitive: `p`, `prod-nsg`, and `p-network-nsg` enable probes by default; `Prod-nsg`, `nsg-prod`, and the default name `nsg` do not. Unknown inputs remain unknown rather than silently defaulting to allow or deny; the name or an explicit override must be known when Terraform determines the rule instances.

For direct NSG module callers, the default uses the NSG name, not the resource group or subnet name. The companion virtual-network module resolves the nullable input per subnet from **`vnet_name`** and passes an explicit boolean to this module, so a production VNet gets the default allowance even if its generated NSG name does not start with `p`. A per-subnet explicit `true` or `false` overrides that VNet name default.

Setting `disable_microsegmentation = true` retains the existing behavior: neither module-managed rule is created, regardless of the allowance or name. Azure's built-in NSG rules apply alongside custom rules.

## Infrastructure and application traffic

Azure Load Balancer probes are needed for load-balanced workloads and Application Gateway infrastructure. Non-`p` consumers requiring these probes must set `allow_azure_load_balancer_inbound = true`, unless existing narrower custom rules already permit them. The naming convention is a default policy, not evidence that every production subnet needs probes; use `false` where they are unnecessary.

The former `AllowApplicationGatewayInfrastructureInbound` rule and its proposed opt-in input have been removed entirely. Standard Application Gateway v2 deployments without Network Isolation that require `GatewayManager` on ports 65200-65535 must use explicit **custom rules**. [Private deployments with Network Isolation](https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-private-deployment#network-security-group-control) need inbound `AzureLoadBalancer` health probes but not `GatewayManager`.

Neither the probe allowance nor a GatewayManager custom rule grants application/client access. Application Gateway client/listener traffic needs custom rules on its hosting subnet. Backend application traffic and Application Gateway backend probes originate from the gateway subnet, not `GatewayManager` or `AzureLoadBalancer`: use custom rules from the gateway subnet CIDR to the required backend ports.

See Microsoft's [Application Gateway infrastructure requirements](https://learn.microsoft.com/en-us/azure/application-gateway/configuration-infrastructure#network-security-groups) and [Azure Load Balancer health probes](https://learn.microsoft.com/en-us/azure/load-balancer/load-balancer-custom-probe-overview).

## Migration (minor release with a compatibility warning)

Previously, both infrastructure allow rules were created for every NSG with microsegmentation enabled. This update is classified as a **minor release (1.4.0)** at the user's request, but upgrading removes the module GatewayManager rule for every NSG and removes the probe allowance for non-`p` NSG names unless explicitly overridden. **This changes existing behavior and can disrupt infrastructure operations or workload health checks.** Add required GatewayManager custom rules and configure the probe override, or confirm existing custom rules already permit the necessary traffic, before upgrading. Deny-all inbound is preserved.

**Existing virtual-network module consumers are affected without upgrading their virtual-network module.** Released `miljodir/virtual-network/azurerm` versions 1.4.1 and 2.0.1 depend on NSG `~> 1.0`, which permits NSG 1.4.0 on a fresh module installation or upgrade. Those older VNet versions do not expose the override or resolve it from `vnet_name`; the default therefore uses their generated NSG names, which may not start with `p` even for production VNets. Before allowing that dependency resolution, move to a VNet version exposing the override and configure required per-subnet exceptions, or verify existing custom rules already allow the required traffic. Rule removal does not require a VNet version upgrade.

**Migrating custom rules requires reviewing denies and names too.** With `disable_microsegmentation = true`, the override is ignored. If changing it to `false` to use the module probe allowance, a custom inbound deny at priority 4049 takes precedence over the probe rule at 4095 and blocks that traffic. Migrate the custom catch-all deny to the module's `DenyAllInbound` at 4096 rather than leaving an earlier deny in place. Custom rules named `DenyAllInbound` or `AllowAzureLoadbalancerInbound` conflict with enabled module-managed rules of the same Azure name; migrate their Terraform ownership and remove overlapping definitions before enabling those module rules. A custom `AllowApplicationGatewayInfrastructureInbound` no longer conflicts because the module rule is gone. Review the rule and state transition before applying so deny-all protection is retained throughout. Existing probe and deny-all priorities are unchanged.

```hcl
module "workload_nsg" {
  source = "miljodir/nsg/azurerm"

  resource_group_name              = "rg-network"
  security_group_name              = "dev-workload-nsg"
  allow_azure_load_balancer_inbound = true
}
```

## Tests

GitHub Actions runs `terraform fmt -check -recursive -diff`, `terraform init -backend=false -input=false`, `terraform validate`, and `terraform test`. Tests use a mocked AzureRM provider, require Terraform 1.7 or newer, and cover omitted/null/true/false probe inputs, lowercase prefix cases, retained rule scopes and priorities, and microsegmentation gating without Azure credentials or deployments.
