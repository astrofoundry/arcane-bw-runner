# Arcane Bitwarden runner

This repository builds the lifecycle runner that writes container secrets before Arcane deploys a GitOps project.

GitHub Actions tests the Go helper and publishes a multi-platform image to `ghcr.io/astrofoundry/arcane-bw-runner`.

## Vault item

Create one Secure Note per container. Add each environment variable as a hidden custom field.

Use the item UUID in the hook. The runner rejects item names, visible fields, empty values, duplicate fields, and multiline values.

## Arcane hook

Mount the credential directory at `/run/bwcreds:ro`. The directory must use mode `0700`. Both files must use mode `0600` and UID `1000`:

```text
/run/bwcreds/client.env
/run/bwcreds/master-password
```

Use the runner image and a project script like this:

```sh
#!/bin/sh
set -eu

exec /usr/local/bin/arcane-bw-runner \
  --server "$BW_SERVER" \
  --item-id "123e4567-e89b-12d3-a456-426614174000" \
  --field CRAWL4AI_API_TOKEN
```

The runner writes `.env.runtime` with mode `0600`. It replaces the file only after Bitwarden returns every requested field.

Load the file without interpolation:

```yaml
env_file:
  - path: ./.env.runtime
    format: raw
```

The runner captures all Bitwarden CLI output. Arcane receives only a fixed success message or a fixed error.

## Image updates

Each push to `main` publishes `latest` and `sha-<commit>`. A `v*` tag also publishes semantic version tags.

Dependabot proposes updates for the base images and GitHub Actions. Update `BW_VERSION` and both archive digests together when Bitwarden releases a new CLI version.
