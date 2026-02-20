#!/usr/bin/env bash

# This script executes repository quality gates inside an isolated Node 20 Docker container.
set -euo pipefail

# This block resolves the repository root so the script works from any current directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# This block prepares a clean temporary workspace to avoid host node_modules pollution.
TMP_WORKDIR="${TMPDIR:-/tmp}/linkwarden-mcp-docker-checks"
rm -rf "${TMP_WORKDIR}"
mkdir -p "${TMP_WORKDIR}"
rsync -a --delete --exclude node_modules --exclude dist "${REPO_ROOT}/" "${TMP_WORKDIR}/"

# This block selects the requested npm script target with a safe default.
TARGET="${1:-qa}"
case "${TARGET}" in
  lint)
    NPM_COMMAND="npm ci && npm run lint"
    ;;
  build)
    NPM_COMMAND="npm ci && npm run build"
    ;;
  test)
    NPM_COMMAND="npm ci && npm run test"
    ;;
  qa)
    NPM_COMMAND="npm ci && npm run lint && npm run build && npm run test"
    ;;
  *)
    echo "Unknown target: ${TARGET}" >&2
    echo "Allowed targets: lint | build | test | qa" >&2
    exit 2
    ;;
esac

# This block runs checks with Node 20 in Docker for stable cross-machine reproducibility.
docker run --rm --platform linux/arm64 -u 0:0 -v "${TMP_WORKDIR}:/work" -w /work node:20-alpine sh -lc "${NPM_COMMAND}"
