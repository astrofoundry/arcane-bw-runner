# Arcane Bitwarden runner

Arcane Bitwarden runner writes container secrets before Arcane deploys a GitOps project. It keeps plaintext secrets out of Git and Arcane's lifecycle settings.

The image includes the Bitwarden CLI and a small Go helper. The helper logs in to Bitwarden or Vaultwarden, reads selected hidden fields, and writes a Compose environment file.

## How it works

1. Arcane starts this image as a pre-deploy lifecycle runner.
2. Arcane mounts a dedicated account's credentials as read-only files.
3. The runner reads one vault item by UUID and selects explicit hidden fields.
4. The runner atomically writes `.env.runtime` with mode `0600`.
5. Docker Compose loads `.env.runtime` through `env_file`.

The runner captures all Bitwarden CLI output. Arcane receives only a fixed success message or a fixed error.

## Requirements

- An Arcane GitOps project sync with the whole project directory enabled.
- Arcane lifecycle hooks enabled by an administrator.
- A Bitwarden or Vaultwarden server that the lifecycle runner can reach through HTTPS.
- A dedicated vault account with a personal API key and access to one organization collection.
- A trusted Git repository. Anyone who can change the hook can read its mounted credentials.

The Arcane host does not need the Bitwarden CLI. The runner image includes it.

## Setup

### 1. Create the vault account

Create a dedicated Bitwarden or Vaultwarden account for Arcane. Add it to the organization as a User.

Create one collection for container secrets. Grant the Arcane account only `View items` access to that collection. Do not grant edit or collection-management access. Do not use `View items, hidden passwords`, because the runner must read hidden fields.

Accept and confirm the organization invitation before you continue.

### 2. Create a vault item

Create one organization-owned Secure Note per container. Put it in the collection from the previous step.

Add each secret as a Hidden custom field. Use `--alias` when a container needs a different environment variable name. Values must be non-empty and single-line.

Copy the item's lowercase UUID. The runner rejects item names so that renames and duplicate names cannot select a different item.

### 3. Create the personal API key

Sign in as the Arcane account. Open **Settings → Security → Keys**, then select **View API key**.

Save the personal `client_id`, personal `client_secret`, and master password. Do not use an organization API key. The personal API key logs in to the CLI, while the master password decrypts the vault.

See [Bitwarden's personal API key guide](https://bitwarden.com/help/personal-api-key/).

### 4. Write the host credential files

Choose a protected directory on the Arcane host. The directory and both files must belong to UID `1000`.

```text
/srv/arcane-bw-runner/
├── client.env
└── master-password
```

`client.env` must contain only these two lines:

```dotenv
BW_CLIENTID=user.example
BW_CLIENTSECRET=replace-with-personal-client-secret
```

`master-password` must contain only the account master password.

Set the directory mode to `0700`. Set both file modes to `0600`. Use a protected editor or secret-provisioning tool so the values do not enter shell history.

### 5. Add the project files

Place an executable `pre-deploy.sh` beside the project's `compose.yaml`:

```sh
#!/bin/sh
set -eu

exec /usr/local/bin/arcane-bw-runner \
  --server "$BW_SERVER" \
  --item-id "123e4567-e89b-12d3-a456-426614174000" \
  --field DATABASE_PASSWORD \
  --field API_TOKEN \
  --alias DATABASE_PASSWORD=MYSQL_PASSWORD
```

Replace the UUID and field names. Keep the item UUID in Git because it identifies the item but does not decrypt it.

Load the generated file from Compose:

```yaml
services:
  app:
    image: example/app:latest
    env_file:
      - ./.env.runtime
```

### 6. Configure Arcane

Open **Environments → your environment → Security → Lifecycle**. Enable lifecycle hooks and set a maximum timeout of at least 60 seconds.

Edit the project's GitOps sync and use these settings:

```text
Sync Files:             enabled
Pre-deploy script:      pre-deploy.sh
Runner image:           ghcr.io/astrofoundry/arcane-bw-runner:latest
Timeout:                60
Network:                bridge
Environment variables: BW_SERVER=https://vault.example.com
Extra mounts:           /srv/arcane-bw-runner:/run/bwcreds:ro
```

Use `bridge` because the runner needs outbound HTTPS access. Use another Docker network only when the vault server needs it.

Arcane requires the script to be executable and inside the synced project directory. See [Arcane's lifecycle hook guide](https://getarcane.app/docs/guides/gitops-lifecycle-hooks).

### 7. Run and check the deployment

Run a manual GitOps sync before you enable auto sync. Check these results:

- The hook status is `success` and its output is `wrote .env.runtime`.
- `.env.runtime` uses mode `0600` and owner UID `1000`.
- The container is healthy and receives the expected variables.
- A missing item, field, or vault connection stops the deployment before Compose replaces the container.

Enable auto sync after these checks pass.

## Secret updates and project removal

After you change a vault field, redeploy the project through Arcane. A GitOps sync with no Git change does not run the hook.

After you delete a project, check its managed directory for `.env.runtime`. Delete that file if Arcane left it behind. GitOps cannot remove a generated file after the project no longer syncs.

## Input rules

The runner accepts one `--server`, one `--item-id`, and one or more `--field` or `--alias` arguments.

- `--server` must be an HTTPS URL.
- `--item-id` must be a lowercase UUID.
- `--field NAME` reads and writes the same name.
- `--alias SOURCE=TARGET` reads `SOURCE` and writes only `TARGET`.
- Use both forms for the same source when both output names are needed.
- Each source must exist once, use the Hidden type, and contain a non-empty single-line value.
- Source and output names must use shell environment variable syntax.
- Each output name must be unique.

The runner never prints Bitwarden CLI output or secret values.

## Image updates

Each push to `main` publishes `latest` and `sha-<commit>`. A `v*` tag also publishes semantic version tags.

Arcane can retain a local copy of `latest`. Open Arcane's **Images** page and pull `ghcr.io/astrofoundry/arcane-bw-runner:latest` before you test a new release.

Dependabot proposes updates for the base images and GitHub Actions. Update `BW_VERSION` and both archive digests together when Bitwarden releases a new CLI version.

## Development

GitHub Actions runs formatting checks, `go test ./...`, and `go vet ./...`. It builds Linux images for AMD64 and ARM64 without a local Go installation.

## License

The runner source uses the MIT license. The image also contains the Bitwarden CLI under the GNU General Public License version 3. See `THIRD_PARTY_NOTICES.md` for its source and license details.
