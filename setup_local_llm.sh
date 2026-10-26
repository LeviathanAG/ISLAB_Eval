#!/usr/bin/env bash
# Install Pi, llama.cpp, and a local Qwen coding model without root access.
# Run from this repository: bash setup_local_llm.sh

set -euo pipefail

REPO_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INSTALL_ROOT=${INSTALL_ROOT:-/home/student/240911676}
LOCAL_PREFIX=${LOCAL_PREFIX:-"$INSTALL_ROOT/.local"}
LOCAL_BIN="$LOCAL_PREFIX/bin"
LLAMA_SRC=${LLAMA_SRC:-"$INSTALL_ROOT/llama.cpp"}
MODEL_DIR=${MODEL_DIR:-"$INSTALL_ROOT/models"}
MODEL_QUANT=${MODEL_QUANT:-Q4_K_M}
NODE_VERSION=${NODE_VERSION:-22.19.0}
PI_PACKAGE=@earendil-works/pi-coding-agent
MODEL_REPO=Qwen/Qwen2.5-Coder-7B-Instruct-GGUF

case "$(uname -s):$(uname -m)" in
  Linux:x86_64) NODE_ARCH=x64 ;;
  Linux:aarch64|Linux:arm64) NODE_ARCH=arm64 ;;
  *) echo "This script supports Linux x86_64 or aarch64 only." >&2; exit 1 ;;
esac

case "$MODEL_QUANT" in
  Q3_K_M|Q4_K_M|Q5_K_M) ;;
  *) echo "MODEL_QUANT must be Q3_K_M, Q4_K_M, or Q5_K_M." >&2; exit 1 ;;
esac

if [[ "${OFFLINE:-0}" == 1 ]]; then
  echo "Offline mode: no downloads will be attempted."
fi

need_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing command: $1" >&2
    exit 1
  }
}

mkdir -p "$INSTALL_ROOT"
[[ -w "$INSTALL_ROOT" ]] || {
  echo "Cannot write to $INSTALL_ROOT. Use a writable folder or set INSTALL_ROOT." >&2
  exit 1
}
# Keep caches and Pi configuration inside the requested install directory too.
export HOME="$INSTALL_ROOT"

node_is_new_enough() {
  command -v node >/dev/null 2>&1 || return 1
  node -e 'const [a,b,c]=process.versions.node.split(".").map(Number); process.exit(a > 22 || (a === 22 && (b > 19 || (b === 19 && c >= 0))) ? 0 : 1)' >/dev/null 2>&1
}

install_user_node() {
  local node_dir="$LOCAL_PREFIX/opt/node-v$NODE_VERSION-linux-$NODE_ARCH"
  if [[ ! -x "$node_dir/bin/node" ]]; then
    [[ "${OFFLINE:-0}" == 1 ]] && {
      echo "Node.js is missing or too old and OFFLINE=1 was requested." >&2
      exit 1
    }
    need_command curl
    mkdir -p "$LOCAL_PREFIX/opt"
    local tmp
    tmp=$(mktemp -d)
    curl -fL --retry 3 --retry-delay 2 \
      "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-linux-$NODE_ARCH.tar.xz" \
      -o "$tmp/node.tar.xz"
    tar -xJf "$tmp/node.tar.xz" -C "$LOCAL_PREFIX/opt"
    rm -rf "$tmp"
  fi
  export PATH="$node_dir/bin:$LOCAL_BIN:$PATH"
}

install_pi() {
  if [[ ! -x "$LOCAL_BIN/pi" ]]; then
    [[ "${OFFLINE:-0}" == 1 ]] && {
      echo "Pi is not installed and OFFLINE=1 was requested." >&2
      exit 1
    }
    npm install --prefix "$LOCAL_PREFIX" -g --ignore-scripts "$PI_PACKAGE"
  fi
}

build_llama_server() {
  need_command git
  need_command cmake
  need_command c++
  if [[ ! -d "$LLAMA_SRC/.git" ]]; then
    [[ "${OFFLINE:-0}" == 1 ]] && {
      echo "llama.cpp is not present and OFFLINE=1 was requested." >&2
      exit 1
    }
    mkdir -p "$(dirname -- "$LLAMA_SRC")"
    git clone --depth 1 https://github.com/ggml-org/llama.cpp.git "$LLAMA_SRC"
  fi
  cmake -S "$LLAMA_SRC" -B "$LLAMA_SRC/build" \
    -DCMAKE_BUILD_TYPE=Release -DGGML_NATIVE=ON \
    -DLLAMA_BUILD_SERVER=ON -DLLAMA_BUILD_TOOLS=ON
  cmake --build "$LLAMA_SRC/build" --target llama-server --parallel "${JOBS:-2}"
  mkdir -p "$LOCAL_BIN"
  ln -sf "$LLAMA_SRC/build/bin/llama-server" "$LOCAL_BIN/llama-server"
}

download_model() {
  local model_file="qwen2.5-coder-7b-instruct-${MODEL_QUANT,,}.gguf"
  local model_path="$MODEL_DIR/$model_file"
  if [[ -f "$model_path" ]]; then
    echo "Model already exists: $model_path"
    return
  fi
  [[ "${OFFLINE:-0}" == 1 ]] && {
    echo "Model is missing and OFFLINE=1 was requested: $model_path" >&2
    exit 1
  }
  need_command curl
  mkdir -p "$MODEL_DIR"
  echo "Downloading about 4–6 GB: $model_file"
  curl -fL --retry 5 --retry-delay 3 -C - \
    "https://huggingface.co/$MODEL_REPO/resolve/main/$model_file" \
    -o "$model_path.part"
  mv "$model_path.part" "$model_path"
}

write_local_skill() {
  local skill_dir="$INSTALL_ROOT/.pi/agent/skills/islab-offline"
  mkdir -p "$skill_dir"
  ln -sfn "$REPO_DIR/skills/islab-offline/SKILL.md" "$skill_dir/SKILL.md"
}

need_command tar
install_user_node
need_command npm
install_pi
build_llama_server
download_model
write_local_skill

MODEL_FILE="qwen2.5-coder-7b-instruct-${MODEL_QUANT,,}.gguf"
mkdir -p "$LOCAL_BIN"

cat <<EOF

Setup complete.

Model:  $MODEL_DIR/$MODEL_FILE
Pi:     $LOCAL_BIN/pi
Server: $LOCAL_BIN/llama-server

Terminal 1 — start the local model server:
  $LOCAL_BIN/llama-server --models-dir "$MODEL_DIR" --no-models-autoload --jinja --host 127.0.0.1 --port 8080 -ngl 999 -c "${LLAMA_CONTEXT:-16384}"

Terminal 2 — start Pi in this lab:
  export PATH="$LOCAL_BIN:$PATH"
  export HOME="$INSTALL_ROOT"
  export LLAMA_BASE_URL=http://127.0.0.1:8080
  cd "$REPO_DIR"
  pi

Inside Pi, run /llama once, select the Qwen model, then use /model.
Keep the server bound to 127.0.0.1 so it is not exposed to the network.

For a smaller download, rerun with MODEL_QUANT=Q3_K_M.
For a no-download check after copying all files to another machine, use OFFLINE=1.
EOF
