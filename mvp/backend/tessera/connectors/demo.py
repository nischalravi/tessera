"""Demo connectors backed by the fictional `DemoCompany`.

Each class implements the same `Connector` interface a real connector would:
swap `DemoOktaConnector` for an `OktaConnector` that calls the Okta API and the
rest of the platform does not change.
"""
from __future__ import annotations

from datetime import datetime
from typing import Iterator

from .base import Connector, DiscoveryResult, Event
from .demo_company import DemoCompany, get_company


class _DemoConnector(Connector):
    def __init__(self, company: DemoCompany | None = None):
        self.company = company or get_company()

    def discover(self) -> DiscoveryResult:
        return self.company.r[self.system]

    def stream_events(self, since: datetime | None = None) -> Iterator[Event]:
        for ev in self.company.usage.get(self.system, []):
            if since is None or ev.day > since:
                yield ev


class DemoWorkdayConnector(_DemoConnector):
    system = "workday"
    display_name = "Workday (HRIS) - demo"

    def stream_events(self, since: datetime | None = None) -> Iterator[Event]:
        yield from super().stream_events(since)
        for ev in self.company.hris_events:
            yield ev


class DemoOktaConnector(_DemoConnector):
    system = "okta"
    display_name = "Okta - demo"


class DemoAWSConnector(_DemoConnector):
    system = "aws"
    display_name = "AWS - demo"


class DemoGitHubConnector(_DemoConnector):
    system = "github"
    display_name = "GitHub - demo"


class DemoSnowflakeConnector(_DemoConnector):
    system = "snowflake"
    display_name = "Snowflake - demo"


def demo_connectors(company: DemoCompany | None = None) -> list[Connector]:
    company = company or get_company()
    return [cls(company) for cls in (DemoWorkdayConnector, DemoOktaConnector, DemoAWSConnector,
                                     DemoGitHubConnector, DemoSnowflakeConnector)]
