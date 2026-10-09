"""Connector registry.

`TESSERA_CONNECTORS` (comma separated) selects connectors, e.g.
`TESSERA_CONNECTORS=demo` (default) or `TESSERA_CONNECTORS=demo-workday,okta`.
Register a real connector by adding a factory to `FACTORIES`.
"""
from __future__ import annotations

import os
from typing import Callable

from .base import Connector
from .demo import (
    DemoAWSConnector,
    DemoGitHubConnector,
    DemoOktaConnector,
    DemoSnowflakeConnector,
    DemoWorkdayConnector,
    demo_connectors,
)

FACTORIES: dict[str, Callable[[], Connector]] = {
    "demo-workday": DemoWorkdayConnector,
    "demo-okta": DemoOktaConnector,
    "demo-aws": DemoAWSConnector,
    "demo-github": DemoGitHubConnector,
    "demo-snowflake": DemoSnowflakeConnector,
    # "okta": lambda: OktaConnector(org_url=os.environ["OKTA_ORG_URL"], token=os.environ["OKTA_API_TOKEN"]),
}


def load_connectors(spec: str | None = None) -> list[Connector]:
    spec = spec or os.environ.get("TESSERA_CONNECTORS", "demo")
    if spec == "demo":
        return demo_connectors()
    return [FACTORIES[name.strip()]() for name in spec.split(",") if name.strip()]
