#!/bin/bash

# test-workflow-locally.sh
# Script to test GitHub Actions workflows locally using act
# Usage: .github/scripts/test-workflow-locally.sh [job-name]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is installed and running
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        echo "Visit: https://docs.docker.com/get-docker/"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        print_error "Docker is not running. Please start Docker Desktop."
        exit 1
    fi

    print_info "Docker is installed and running"
}

# Check if act is installed
check_act() {
    if ! command -v act &> /dev/null; then
        print_warning "act is not installed. Installing now..."

        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS
            if command -v brew &> /dev/null; then
                brew install act
            else
                print_info "Installing act via curl..."
                curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash
            fi
        else
            # Linux
            print_info "Installing act via curl..."
            curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash
        fi

        if ! command -v act &> /dev/null; then
            print_error "Failed to install act"
            exit 1
        fi
    fi

    print_info "act is installed ($(act --version))"
}

# Setup configuration files
setup_configs() {
    local github_dir="$(dirname "$0")/.."

    # Create act secrets file if it doesn't exist
    if [ ! -f "$github_dir/act-secrets" ]; then
        if [ -f "$github_dir/act-secrets.example" ]; then
            print_info "Creating act-secrets from example..."
            cp "$github_dir/act-secrets.example" "$github_dir/act-secrets"
            print_warning "Please edit $github_dir/act-secrets with your actual values"
        else
            print_info "Creating default act-secrets file..."
            cat > "$github_dir/act-secrets" <<EOF
# GitHub Actions secrets for local testing with act
# These are test values - replace with real values if needed
GITHUB_TOKEN=test-github-token
CODECOV_TOKEN=test-codecov-token

# Package registry secrets (optional)
AWS_ACCESS_KEY_ID=test-key
AWS_SECRET_ACCESS_KEY=test-secret
AZURE_DEVOPS_PAT=test-pat
AZURE_ARTIFACTS_URL=https://test.artifacts.azure.com
PYPI_USERNAME=test-user
PYPI_PASSWORD=test-pass
PRIVATE_PYPI_URL=https://test.pypi.org
EOF
            print_warning "Created $github_dir/act-secrets with test values"
        fi
    fi

    # Create act variables file if it doesn't exist
    if [ ! -f "$github_dir/act-vars" ]; then
        if [ -f "$github_dir/act-vars.example" ]; then
            print_info "Creating act-vars from example..."
            cp "$github_dir/act-vars.example" "$github_dir/act-vars"
        else
            print_info "Creating default act-vars file..."
            cat > "$github_dir/act-vars" <<EOF
# GitHub Actions variables for local testing with act
# Leave PACKAGE_REGISTRY empty to skip publishing
PACKAGE_REGISTRY=
PACKAGE_REGISTRY_URL=https://pypi.org

# AWS CodeArtifact settings (if using AWS)
AWS_REGION=us-east-1
CODEARTIFACT_DOMAIN=your-domain
CODEARTIFACT_REPO=your-repo
EOF
        fi
    fi
}

# Run workflow with act
run_workflow() {
    local job_name="$1"
    local github_dir="$(dirname "$0")/.."
    local root_dir="$github_dir/../.."

    cd "$root_dir"

    # Build act command
    local act_cmd="act"
    local act_args=""

    # Use better Ubuntu image for compatibility
    act_args="$act_args -P ubuntu-latest=catthehacker/ubuntu:act-latest"

    # Add secrets and variables
    if [ -f "$github_dir/act-secrets" ]; then
        act_args="$act_args --secret-file $github_dir/act-secrets"
    fi

    if [ -f "$github_dir/act-vars" ]; then
        act_args="$act_args --var-file $github_dir/act-vars"
    fi

    # Add reuse flag to speed up subsequent runs
    act_args="$act_args --reuse"

    if [ -n "$job_name" ]; then
        # Run specific job
        print_info "Running job: $job_name"
        $act_cmd -j "$job_name" $act_args
    else
        # Run all jobs (triggered by push event)
        print_info "Running all jobs (push event)"
        $act_cmd push $act_args
    fi
}

# Main menu
show_menu() {
    echo ""
    echo "GitHub Actions Workflow Local Tester"
    echo "====================================="
    echo ""
    echo "Available jobs in ci-cd.yml:"
    echo "  1) test     - Run tests on multiple Python versions"
    echo "  2) security - Run security scans"
    echo "  3) build    - Build distribution packages"
    echo "  4) publish  - Publish to package registry (requires tag)"
    echo "  5) all      - Run all jobs (push event)"
    echo ""
    echo "Usage:"
    echo "  $0          - Show this menu"
    echo "  $0 test     - Run test job"
    echo "  $0 security - Run security job"
    echo "  $0 build    - Run build job"
    echo "  $0 all      - Run all jobs"
    echo ""
}

# Main execution
main() {
    print_info "Checking prerequisites..."
    check_docker
    check_act
    setup_configs

    case "${1:-}" in
        test|security|build|publish)
            run_workflow "$1"
            ;;
        all|"")
            if [ -z "$1" ]; then
                show_menu
                read -p "Enter job name (or press Enter for all): " job_choice
                if [ -n "$job_choice" ]; then
                    run_workflow "$job_choice"
                else
                    run_workflow ""
                fi
            else
                run_workflow ""
            fi
            ;;
        *)
            print_error "Unknown job: $1"
            show_menu
            exit 1
            ;;
    esac
}

main "$@"
