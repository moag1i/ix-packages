# GitHub Actions Workflows

This directory contains CI/CD workflows for the ix-packages monorepo.

## Workflows

### ci-cd.yml

Main CI/CD pipeline that runs on push and pull requests.

**Jobs:**
- **test**: Runs tests on Python 3.10, 3.11, and 3.12 with coverage reporting
- **security**: Runs Bandit security scans and checks for known vulnerabilities
- **build**: Builds distribution packages (wheel and sdist)
- **publish**: Publishes to configured package registry (only on version tags)

### version-bump.yml

Manual workflow for bumping package versions.

## Local Testing with act

You can test workflows locally using [act](https://github.com/nektos/act), which runs GitHub Actions in Docker containers on your machine.

### Prerequisites

1. **Docker**: Must be installed and running
   - [Install Docker Desktop](https://docs.docker.com/get-docker/)

2. **act**: GitHub Actions local runner
   ```bash
   # macOS
   brew install act

   # Linux/WSL
   curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash
   ```

### Quick Start

1. **Run the test script**:
   ```bash
   .github/scripts/test-workflow-locally.sh
   ```

   This script will:
   - Check if Docker and act are installed
   - Create configuration files from examples
   - Show a menu to run specific jobs

2. **Test specific jobs**:
   ```bash
   # Test the test job
   .github/scripts/test-workflow-locally.sh test

   # Test security scanning
   .github/scripts/test-workflow-locally.sh security

   # Test package building
   .github/scripts/test-workflow-locally.sh build

   # Run all jobs
   .github/scripts/test-workflow-locally.sh all
   ```

### Manual Testing with act

1. **Copy configuration files**:
   ```bash
   cp .github/act-secrets.example .github/act-secrets
   cp .github/act-vars.example .github/act-vars
   ```

2. **Edit configuration files** (optional):
   - `.github/act-secrets`: Add real tokens if needed
   - `.github/act-vars`: Configure package registry settings

3. **Run workflows**:
   ```bash
   # Run all jobs (push event)
   act push --secret-file .github/act-secrets --var-file .github/act-vars

   # Run specific job
   act -j test --secret-file .github/act-secrets --var-file .github/act-vars

   # Run with specific Python version
   act -j test --matrix python-version:3.11

   # Run with verbose output for debugging
   act -j test --verbose
   ```

### Configuration Files

#### Required Secrets (`.github/act-secrets`)

| Secret | Description | Required | Default for Testing |
|--------|-------------|----------|-------------------|
| `GITHUB_TOKEN` | GitHub API token | Yes | `test-github-token` |
| `CODECOV_TOKEN` | Codecov.io token | No | `test-codecov-token` |
| `AWS_ACCESS_KEY_ID` | AWS credentials | If using AWS | - |
| `AWS_SECRET_ACCESS_KEY` | AWS credentials | If using AWS | - |
| `AZURE_DEVOPS_PAT` | Azure DevOps PAT | If using Azure | - |
| `AZURE_ARTIFACTS_URL` | Azure Artifacts URL | If using Azure | - |
| `PYPI_USERNAME` | PyPI username | If using private PyPI | - |
| `PYPI_PASSWORD` | PyPI password | If using private PyPI | - |
| `PRIVATE_PYPI_URL` | Private PyPI URL | If using private PyPI | - |

#### Repository Variables (`.github/act-vars`)

| Variable | Description | Options | Default |
|----------|-------------|---------|---------|
| `PACKAGE_REGISTRY` | Registry to publish to | `github`, `aws`, `azure`, `private`, or empty | empty (skip) |
| `PACKAGE_REGISTRY_URL` | Registry URL (display only) | Any URL | `https://pypi.org` |
| `AWS_REGION` | AWS region | Any AWS region | `us-east-1` |
| `CODEARTIFACT_DOMAIN` | CodeArtifact domain | Your domain | - |
| `CODEARTIFACT_REPO` | CodeArtifact repository | Your repo | - |

### Limitations of Local Testing

1. **Services**: PostgreSQL service in the test job may not work perfectly locally
2. **Actions**: Some GitHub-specific actions may have limited functionality
3. **Secrets**: The `GITHUB_TOKEN` in local testing won't have the same permissions
4. **Artifacts**: Upload/download artifact actions work differently locally
5. **Codecov**: Coverage uploads will fail without a real token

### Troubleshooting

#### Docker not running
```
Error: Cannot connect to the Docker daemon
```
**Solution**: Start Docker Desktop

#### act not found
```
Error: command not found: act
```
**Solution**: Install act using the instructions above

#### Container platform issues
```
Error: The requested image's platform (linux/amd64) does not match
```
**Solution**: Use the catthehacker Ubuntu images (configured in .actrc)

#### Missing dependencies in container
```
Error: command not found in container
```
**Solution**: The default act images are minimal. Use catthehacker images:
```bash
act -P ubuntu-latest=catthehacker/ubuntu:act-latest
```

### GitHub Repository Configuration

For the workflows to run in GitHub Actions, configure these settings:

#### Repository Variables
Go to: Settings → Secrets and variables → Actions → Variables

- `PACKAGE_REGISTRY`: Set to your registry type or leave empty
- `PACKAGE_REGISTRY_URL`: Optional, for display purposes

#### Repository Secrets
Go to: Settings → Secrets and variables → Actions → Secrets

- `CODECOV_TOKEN`: Get from [codecov.io](https://codecov.io)
- Registry-specific secrets based on your `PACKAGE_REGISTRY` choice

#### Environment
Go to: Settings → Environments

Create a `production` environment for the publish job (optional).

## Best Practices

1. **Test locally first**: Always test workflows locally before pushing
2. **Use act for debugging**: Add `--verbose` flag to debug issues
3. **Keep secrets secure**: Never commit real secrets, use `.gitignore`
4. **Use matrix strategy**: Test on multiple Python versions
5. **Cache dependencies**: Use actions/cache for faster builds (in real GitHub Actions)

## Resources

- [act Documentation](https://github.com/nektos/act)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Workflow Syntax](https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions)
- [catthehacker Docker Images](https://github.com/catthehacker/docker_images)