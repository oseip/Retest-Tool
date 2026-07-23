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
class JiraSecondaryConfig:
    """Non-Axian / Jira Server instance — uses Bearer token (PAT) auth."""
    url: str
    api_token: str          # Personal Access Token (Bearer)
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
    nessus_username: Optional[str] = None   # unused — kept for config compatibility
    nessus_password: Optional[str] = None   # unused — kept for config compatibility
    sudo_nmap: bool = False                 # prepend sudo to nmap when opco Kali requires it


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
    jira_secondary: Optional[JiraSecondaryConfig] = None
    clients_secondary: List[ClientConfig] = field(default_factory=list)


def load_config(path: str = "config/config.yaml") -> Config:
    with open(path) as f:
        data = yaml.safe_load(f)
    jira = JiraConfig(**data["jira"])
    jump = JumpServerConfig(**data["jump_server"])
    clients = [ClientConfig(**c) for c in data["clients"]]
    app = AppConfig(**data.get("app", {}))

    jira_secondary = None
    if data.get("jira_secondary"):
        jira_secondary = JiraSecondaryConfig(**data["jira_secondary"])

    clients_secondary = [ClientConfig(**c) for c in data.get("clients_secondary", [])]

    return Config(
        jira=jira, jump_server=jump, clients=clients, app=app,
        jira_secondary=jira_secondary, clients_secondary=clients_secondary,
    )
