#!/usr/bin/env bash
set -euo pipefail

if command -v node >/dev/null 2>&1 && [[ "$(node --version)" == v22.* ]] && \
   command -v claude >/dev/null 2>&1 && claude --version | grep -q '1\.0\.128'; then
  exit 0
fi

if ! command -v node >/dev/null 2>&1 || [[ "$(node --version)" != v22.* ]]; then
  apt-get update
  apt-get install -y ca-certificates curl
  export NVM_DIR="${NVM_DIR:-/root/.nvm}"
  curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.2/install.sh | bash
  source "$NVM_DIR/nvm.sh"
  nvm install 22
else
  if [[ -f /root/.nvm/nvm.sh ]]; then source /root/.nvm/nvm.sh; fi
fi

npm install -g @anthropic-ai/claude-code@1.0.128
claude --version | grep -q '1\.0\.128'
