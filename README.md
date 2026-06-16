# Nemesis — Automated Vulnerability Retest Tool

Automates retesting of remediated vulnerabilities by pulling tickets from Jira, running nmap/curl scans via an SSH double-hop (jump server → Kali), and returning a verdict (Fixed / Not Fixed / Inconclusive).

---

## Prerequisites

- Docker installed and running:
  - **Mac / Windows** — [Docker Desktop](https://www.docker.com/products/docker-desktop/)
  - **Linux** — [Docker Engine + Compose plugin](https://docs.docker.com/engine/install/) (follow the guide for your distro, e.g. Ubuntu, Debian, Fedora)
- Access to the shared jump server (ask your team lead for credentials)
- A Jira API token — generate one at: **Jira → Account Settings → Security → API tokens**

---

## First-Time Setup

**1. Clone the repository**
```
git clone <repo-url>
cd retest-tool
```

**2. Create your config file**
```
cp config/config.example.yaml config/config.yaml
```

**3. Edit `config/config.yaml` with your details**

Open the file and fill in:
- Your Jira URL, email, and API token
- Jump server host, username, and password
- Your Kali machine details (port, username, password)
- The Jira project key and client label you're working with

The file has comments explaining every field. `config/config.yaml` is gitignored — it will never be committed.

**4. Start the tool**
```
docker compose up --build
```

> **Linux note:** If you get `docker: 'compose' is not a docker command`, your system has the older standalone Compose. Use `docker-compose` instead:
> ```
> docker-compose up --build
> ```

The first build takes about a minute to download dependencies. Subsequent starts are instant.

**5. Open the UI**

Go to [http://localhost:8000](http://localhost:8000) in your browser.

---

## Daily Use

Start:
```
docker compose up
```

Stop:
```
docker compose down
```

> Linux with old Compose: replace `docker compose` with `docker-compose` in all commands above.

---

## Updating After Someone Pushes Changes

```
git pull
docker compose up --build
```

---

## Adding a New Client / Kali Box

Open `config/config.yaml` and add a new block under `clients:`:

```yaml
clients:
  - label: "ClientA"
    name: "Client A"
    kali_port: 22
    kali_user: "kali"
    kali_password: "password"

  - label: "ClientB"         # add this block
    name: "Client B"
    kali_port: 22
    kali_user: "kali"
    kali_password: "password"
```

Restart the tool after saving.

---

## Running Tests

Tests run without Docker and do not require a real Jira connection or SSH access.

**Install test dependencies (one time):**

| Platform | Command |
|---|---|
| Mac / Linux | `pip3 install pytest pytest-mock` |
| Windows | `pip install pytest pytest-mock` |

Or if using the virtual environment (see below): `pip install pytest pytest-mock` inside the activated venv.

**Run tests:**

| Platform | Command |
|---|---|
| Mac / Linux | `.venv/bin/python -m pytest tests/ -v` |
| Windows | `.venv\Scripts\python -m pytest tests/ -v` |

Expected output: **148 passed, 1 skipped**.

---

## Running Without Docker (Development)

If you need to run the server directly (e.g. to use `--reload` during development):

**Mac / Linux:**
```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
.venv/bin/uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload-dir src --reload-dir config
```

**Windows:**
```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
.venv\Scripts\uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload-dir src --reload-dir config
```

---

## Project Structure

```
retest-tool/
├── config/
│   ├── config.yaml          ← your credentials (gitignored, never commit)
│   └── config.example.yaml  ← template to copy from
├── frontend/                ← HTML/CSS/JS UI
├── src/
│   ├── main.py              ← FastAPI app and endpoints
│   ├── scanner.py           ← job queue, scan execution, Jira polling
│   ├── jira_client.py       ← Jira API wrapper
│   ├── ssh_exec.py          ← SSH double-hop via paramiko
│   ├── vuln_rules.py        ← vulnerability → nmap/curl rule mappings
│   └── config.py            ← config dataclasses
└── tests/                   ← test suite (no credentials needed)
```
