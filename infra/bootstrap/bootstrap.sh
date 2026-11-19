#!/usr/bin/env bash
set -euo pipefail

TF_VERSION="1.17.2"
HASHICORP_FPR="C874011F0AB405110D02105534365D9472D7468F"
PROJECT="security-briefing"

cd "$(dirname "$0")"

install_terraform() {
  if command -v terraform >/dev/null && terraform version | head -1 | grep -qx "Terraform v${TF_VERSION}"; then
    return
  fi

  local arch tmp base zip
  case "$(uname -m)" in
    x86_64) arch="amd64" ;;
    aarch64) arch="arm64" ;;
    *) echo "[error] unsupported architecture" >&2; exit 1 ;;
  esac

  tmp="$(mktemp -d)"
  base="https://releases.hashicorp.com/terraform/${TF_VERSION}"
  zip="terraform_${TF_VERSION}_linux_${arch}.zip"

  curl -fsSL --proto '=https' -o "$tmp/$zip" "$base/$zip"
  curl -fsSL --proto '=https' -o "$tmp/SHA256SUMS" "$base/terraform_${TF_VERSION}_SHA256SUMS"
  curl -fsSL --proto '=https' -o "$tmp/SHA256SUMS.sig" "$base/terraform_${TF_VERSION}_SHA256SUMS.sig"
  curl -fsSL --proto '=https' -o "$tmp/hashicorp.asc" "https://www.hashicorp.com/.well-known/pgp-key.txt"

  export GNUPGHOME="$tmp/gnupg"
  mkdir -m 700 "$GNUPGHOME"
  gpg --batch --quiet --import "$tmp/hashicorp.asc" 2>/dev/null
  if ! gpg --batch --status-fd 1 --verify "$tmp/SHA256SUMS.sig" "$tmp/SHA256SUMS" 2>/dev/null \
      | grep -q "^\[GNUPG:\] VALIDSIG .* ${HASHICORP_FPR}$"; then
    echo "[error] terraform signature check failed" >&2
    exit 1
  fi
  (cd "$tmp" && grep " ${zip}$" SHA256SUMS | sha256sum -c --quiet -)

  unzip -q -o "$tmp/$zip" terraform -d "$tmp"
  mkdir -p "$HOME/.local/bin"
  install -m 755 "$tmp/terraform" "$HOME/.local/bin/terraform"
  unset GNUPGHOME
  rm -rf "$tmp"
}

main() {
  install_terraform
  export PATH="$HOME/.local/bin:$PATH"
  terraform version | head -1

  local account bucket
  account="$(aws sts get-caller-identity --query Account --output text)"
  bucket="${PROJECT}-tfstate-${account}"

  if aws s3api head-bucket --bucket "$bucket" 2>/dev/null; then
    terraform init -input=false -reconfigure -backend-config="bucket=${bucket}"
    terraform apply
  else
    printf 'terraform {\n  backend "local" {}\n}\n' > backend_override.tf
    terraform init -input=false -reconfigure
    terraform apply
    rm -f backend_override.tf
    terraform init -input=false -migrate-state -force-copy -backend-config="bucket=${bucket}"
    rm -f terraform.tfstate terraform.tfstate.backup
  fi

  echo
  echo "GitHub 에 넣을 값 (채팅·메모에 붙여넣지 말 것)"
  terraform output
}

main "$@"
