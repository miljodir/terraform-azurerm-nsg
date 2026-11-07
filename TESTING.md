# Testing

This module uses the native Terraform test framework. Its tests run on both
Terraform and OpenTofu in GitHub Actions on pull requests and pushes to `main`
(see `.github/workflows/terraform-test.yaml`). The caller uses the shared
[Terraform and OpenTofu test workflow](https://github.com/miljodir/workflow-templates/blob/main/doc/workflows/terraform-test.md).
CI uses Terraform `1.x` and the latest stable OpenTofu `1.x` release.

## What runs in CI

The shared workflow formats the module, initializes without a backend, validates
the configuration, and runs its native tests with both engines. It uses
`contents: read` and requires no secrets or cloud credentials.

## How the tests work

- Test files live in `tests/` and end in `.tftest.hcl`. Terraform and OpenTofu
  both support this test format.
- Every test file declares `mock_provider` blocks. Mocked providers do not call
  Azure, so no credentials are needed and **no real resources are created**.
  Resource attributes that Azure would compute (for example `id`) get
  generated fake values.
- Each `run` block plans (`command = plan`) or applies against the mocks
  (`command = apply`) with a set of input variables, then checks the result
  with `assert` blocks.
- Input validation is tested with `expect_failures`, which passes only when
  the listed variable validation or precondition fails.
- Data sources and nested modules that would need real lookups can be replaced
  with `override_data` / `override_module`.

When tests run, the module is the *root* module. Terraform rejects outputs
that contain sensitive attributes unless they are marked `sensitive = true`
(consumers calling the module are not affected). If needed, put test-only
override files in `tests/overrides/` named `*_override.tf`, for example:

```hcl
output "storage_account" {
  sensitive = true
}
```

The shared workflow can be configured to copy these overrides into the module
root before running tests.

These are unit-style tests: they verify how the module turns inputs into
resource configuration. They do not prove that Azure accepts the configuration;
that still happens when a consuming workload runs `terraform plan`/`apply`.

## Writing a test

```hcl
mock_provider "azurerm" {}

variables {
  resource_group_name = "rg-test"
}

run "defaults" {
  command = plan

  assert {
    condition     = azurerm_example.this.name == "expected"
    error_message = "Name should default to 'expected'."
  }
}

run "rejects_invalid_input" {
  command = plan

  variables {
    some_setting = "not-allowed"
  }

  expect_failures = [var.some_setting]
}
```

Guidelines:

- Add or update a test whenever you change behaviour, defaults or validation.
- Use obviously fake values (`rg-test`, `00000000-0000-0000-0000-000000000000`,
  documentation IP ranges such as `192.0.2.0/24`). Never use real subscription
  IDs, tenant IDs, names or addresses — this repository is public.
- Prefer one behaviour per `run` block with a descriptive name.

## Running locally

Terraform mocked-provider tests require Terraform >= 1.7. This suite has been
verified with OpenTofu 1.13.9; CI selects the latest stable `1.x` release.

```sh
terraform fmt -check -recursive
terraform init -backend=false
terraform validate
terraform test
```

```sh
tofu fmt -check -recursive
tofu init -backend=false
tofu validate
tofu test
```

If you configure test-only output overrides, remove any copied `*_override.tf`
files afterwards (they are git-ignored).
