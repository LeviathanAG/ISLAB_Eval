# Local LLM setup for this lab

This repository includes a no-root setup for Pi, llama.cpp, and a local Qwen coding model.

## 1. Run the installer

```bash
cd /home/hesa6004/IS_LAB_prac/ISLAB_Eval
bash setup_local_llm.sh
```

Everything is installed under:

```text
/home/student/240911676
```

The default Q4 model needs roughly 5 GB of free disk space. Use the smaller model if needed:

```bash
MODEL_QUANT=Q3_K_M bash setup_local_llm.sh
```

The installer needs internet access the first time. After the files are copied to another machine, `OFFLINE=1` prevents downloads:

```bash
OFFLINE=1 bash setup_local_llm.sh
```

## 2. Start the local model

The setup script installs the server but does not leave it running. Start it in Terminal 1:

```bash
/home/student/240911676/.local/bin/llama-server \
  --models-dir /home/student/240911676/models \
  --no-models-autoload \
  --jinja \
  --host 127.0.0.1 \
  --port 8080 \
  -ngl 999 \
  -c 16384
```

Keep `127.0.0.1` so the model is available only on this computer.

## 3. Start Pi

In Terminal 2:

```bash
export HOME=/home/student/240911676
export PATH=/home/student/240911676/.local/bin:$PATH
export LLAMA_BASE_URL=http://127.0.0.1:8080

cd /home/hesa6004/IS_LAB_prac/ISLAB_Eval
pi
```

Inside Pi:

1. Run `/llama`.
2. Select the Qwen model.
3. Run `/model` and select it for the session.

The offline lab skill is installed at:

```text
/home/student/240911676/.pi/agent/skills/islab-offline/SKILL.md
```

It tells Pi to use the repository and local Python documentation instead of internet documentation.

## 4. Python lab dependencies

The Python dependencies are listed in `requirements.txt`. Install them into a virtual environment if Python packages are not already available:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

The shell installer does not install Python packages.

## Troubleshooting

### `Permission denied` for `/home/student/240911676`

The folder must be writable by your account. Check it with:

```bash
test -w /home/student/240911676 && echo writable || echo not-writable
```

If the folder is elsewhere, choose a writable location:

```bash
INSTALL_ROOT="$HOME/IS_LAB_LOCAL" bash setup_local_llm.sh
```

### Pi cannot see the offline skill

Make sure `HOME` is set before starting Pi:

```bash
export HOME=/home/student/240911676
```

### Model uses too much memory

Lower the context size:

```bash
# Replace -c 16384 in the server command with:
-c 8192
```

Or install the smaller Q3 model with `MODEL_QUANT=Q3_K_M`.

### Check that the server is running

```bash
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/models
```

Stop the server with `Ctrl+C` in Terminal 1.
