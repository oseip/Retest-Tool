import yaml
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class JiraConfig:
    url: str
    username: str
    api_token: str
    project: str
    retest_status: str = "Remediated"
    poll_interval: int = 300


@dataclass
class JumpServerConfig:
    host: str
    port: int
    user: str
    password: str


@dataclass
class ClientConfig:
    label: str
    name: str
    kali_port: int
    kali_user: str
    kali_password: str
    nessus_access_key: Optional[str] = None
    nessus_secret_key: Optional[str] = None


@dataclass
class AppConfig:
    host: str = "0.0.0.0"
    port: int = 8000


@dataclass
class Config:
    jira: JiraConfig
    jump_server: JumpServerConfig
    clients: List[ClientConfig]
    app: AppConfig = field(default_factory=AppConfig)


def load_config(path: str = "config/config.yaml") -> Config:
    with open(path) as f:
        data = yaml.safe_load(f)
    jira = JiraConfig(**data["jira"])
    jump = JumpServerConfig(**data["jump_server"])
    clients = [ClientConfig(**c) for c in data["clients"]]
    app = AppConfig(**data.get("app", {}))
    return Config(jira=jira, jump_server=jump, clients=clients, app=app)


def load_catalog(path: str = "config/clients_catalog.yaml") -> dict:
    """Load the shared opco/Kali-credentials catalog used by the first-run
    Settings page. Raw dict — only consumed by src/setup.py."""
    with open(path) as f:
        return yaml.safe_load(f)
