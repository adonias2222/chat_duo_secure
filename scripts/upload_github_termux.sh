#!/usr/bin/env bash
set -e
REPO_NAME="chat_duo_secure"
GITHUB_USER="adonias2222"
GIT_EMAIL="felipeadonias2@gmail.com"

git init
git branch -M main
git config --global user.name "$GITHUB_USER"
git config --global user.email "$GIT_EMAIL"
git add .
git commit -m "Primeira versão do Chat Duo Secure" || true

if command -v gh >/dev/null 2>&1; then
  gh repo create "$REPO_NAME" --public --source=. --remote=origin --push
else
  echo "Instale: pkg install gh -y"
  echo "Login: gh auth login"
  echo "Depois rode este script novamente."
fi
