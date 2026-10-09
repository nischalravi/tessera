"""A deterministic, entirely fictional company used by the demo connectors.

"Larkspur Labs" (larkspur.example) — ~60 employees, ~25 service accounts / API
keys and 6 AI agents spread across Workday, Okta, AWS, GitHub and Snowflake,
with 90 days of synthetic usage. Every name here is invented.

The model builds one `DiscoveryResult` per system; each demo connector simply
returns its slice. Real connectors replace these one system at a time.
"""
from __future__ import annotations

import random
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

from ..timeutil import utcnow
from .base import (
    AccountRecord,
    DelegationRecord,
    DiscoveryResult,
    EdgeRecord,
    GroupRecord,
    HrisEventRecord,
    IdentityRecord,
    IdentityRef,
    PermissionRecord,
    Ref,
    ResourceRecord,
    SecretRecord,
    UsageRecord,
)

DOMAIN = "larkspur.example"
SYSTEMS = ["workday", "okta", "aws", "github", "snowflake"]

FIRST_NAMES = [
    "Rosalind", "Caspian", "Mireille", "Kofi", "Alice", "Tomas", "Ingrid", "Rafael", "Sana", "Bastian",
    "Yara", "Callum", "Lena", "Marcus", "Oren", "Talia", "Joaquin", "Freya", "Idris", "Hana",
    "Wren", "Anika", "Desmond", "Ottilie", "Kenji", "Dmitri", "Teodor", "Esme", "Rohan", "Linnea",
    "Bram", "Ayasha", "Cyrus", "Delphine", "Femi", "Greer", "Priya", "Ilya", "Juno", "Leif",
    "Nikhil", "Odessa", "Pascal", "Quinn", "Hollis", "Soren", "Thandiwe", "Ulric", "Vesna", "Wim",
    "Xiomara", "Yusuf", "Zora", "Anders", "Beatrix", "Mei", "Dalia", "Emeric", "Zainab", "Marisol",
]
LAST_NAMES = [
    "Okafor", "Bellweather", "Ramaswamy", "Lindqvist", "Achterberg", "Mensah", "Castellanos", "Haverford",
    "Quillfeather", "Ostrowski", "Quennell", "Delacroix", "Nakamura-Reyes", "Ferreira", "Abernathy",
    "Kowalczyk", "Mokoena", "Sorensen", "Whitlock", "Iyer", "Marchetti", "Oyelaran", "Pemberton",
    "Rasmussen", "Szabo", "Thornbury", "Valdivia", "Winslow", "Zeller", "Arkwright",
]

# (department, team, size, title pool) - first member of each team list is its lead
ORG = [
    ("Executive", "exec", 3, ["Chief Executive Officer", "Chief Technology Officer", "Chief Financial Officer"]),
    ("Engineering", "backend", 7, ["Engineering Manager, Backend", "Senior Software Engineer", "Software Engineer"]),
    ("Engineering", "frontend", 5, ["Engineering Manager, Frontend", "Frontend Engineer"]),
    ("Engineering", "platform", 6, ["Platform Lead", "Site Reliability Engineer", "Platform Engineer"]),
    ("Data", "data", 7, ["Head of Data", "Data Engineer", "Analytics Engineer", "Data Scientist"]),
    ("Security", "security", 3, ["Head of Security", "Security Engineer"]),
    ("Finance", "finance", 8, ["Financial Controller", "AP Specialist", "Accountant", "FP&A Analyst"]),
    ("Sales", "sales", 10, ["VP Sales", "Account Executive", "Sales Development Rep", "Sales Ops Analyst"]),
    ("Support", "support", 7, ["Support Lead", "Support Engineer", "Customer Success Manager"]),
    ("People", "people", 4, ["Head of People", "HR Business Partner", "Recruiter"]),
]

# Names pinned to specific roles so the demo tells a story.
PINNED = {
    ("exec", 0): ("Rosalind", "Haverford"),
    ("exec", 1): ("Caspian", "Arkwright"),
    ("exec", 2): ("Mireille", "Delacroix"),
    ("backend", 0): ("Kofi", "Mensah"),
    ("backend", 1): ("Alice", "Okafor"),
    ("platform", 0): ("Ingrid", "Lindqvist"),
    ("platform", 1): ("Marcus", "Bellweather"),
    ("platform", 2): ("Oren", "Whitlock"),
    ("data", 0): ("Sana", "Iyer"),
    ("data", 1): ("Dmitri", "Ostrowski"),
    ("security", 0): ("Thandiwe", "Mokoena"),
    ("finance", 0): ("Beatrix", "Pemberton"),
    ("finance", 1): ("Priya", "Ramaswamy"),
    ("finance", 2): ("Tomas", "Szabo"),
    ("finance", 3): ("Linnea", "Sorensen"),
    ("sales", 0): ("Rafael", "Valdivia"),
    ("sales", 1): ("Hollis", "Brightwater"),
    ("support", 0): ("Yara", "Castellanos"),
    ("support", 1): ("Callum", "Ferreira"),
    ("people", 0): ("Esme", "Thornbury"),
}

TERMINATED = {"Hollis Brightwater": 35, "Dmitri Ostrowski": 50, "Oren Whitlock": 20}  # days ago


@dataclass
class Person:
    eid: str
    first: str
    last: str
    dept: str
    team: str
    title: str
    lead: bool
    manager_eid: str | None = None
    status: str = "active"
    hired_at: datetime | None = None
    terminated_at: datetime | None = None

    @property
    def name(self) -> str:
        return f"{self.first} {self.last}"

    @property
    def email(self) -> str:
        return f"{self.first.lower()}.{self.last.lower().replace(' ', '')}@{DOMAIN}"

    @property
    def gh(self) -> str:
        return f"{self.first.lower()}-{self.last.lower()[:5]}"

    @property
    def sf(self) -> str:
        return f"{self.first.upper()}_{self.last.upper().replace('-', '_')}"

    @property
    def ref(self) -> IdentityRef:
        return IdentityRef(external_id=self.eid)


class DemoCompany:
    def __init__(self, seed: int = 7, now: datetime | None = None):
        self.rng = random.Random(seed)
        self.now = (now or utcnow()).replace(hour=0, minute=0, second=0, microsecond=0)
        self.r: dict[str, DiscoveryResult] = {s: DiscoveryResult() for s in SYSTEMS}
        self.usage: dict[str, list[UsageRecord]] = defaultdict(list)
        self.hris_events: list[HrisEventRecord] = []
        self.people: list[Person] = []
        self.by_name: dict[str, Person] = {}
        self._children: dict[Ref, list[Ref]] = defaultdict(list)
        self._identity_accounts: dict[str, list[Ref]] = defaultdict(list)
        self._identity_type: dict[str, str] = {}
        self._perm_meta: dict[Ref, dict] = {}
        self._unused: set[tuple[str, str]] = set()  # (identity eid, perm xid) never used
        self._dormant: dict[str, int] = {}  # identity eid -> days since last activity
        self._build()

    # ------------------------------------------------------------- helpers
    def days_ago(self, n: float) -> datetime:
        return self.now - timedelta(days=n)

    def resource(self, system, xid, name, kind, env=None, tags=()):
        self.r[system].resources.append(ResourceRecord(system, xid, name, kind, env, list(tags)))

    def perm(self, system, action, res_xid, privileged=False) -> Ref:
        xid = f"{action}@{res_xid}"
        ref = Ref("perm", system, xid)
        if ref not in self._perm_meta:
            self.r[system].permissions.append(PermissionRecord(system, xid, action, res_xid, privileged))
            self._perm_meta[ref] = {"privileged": privileged, "action": action, "res": res_xid}
        return ref

    def group(self, system, xid, name=None, kind="group", privileged=False, requestable=False, desc=None) -> Ref:
        self.r[system].groups.append(GroupRecord(system, xid, name or xid, kind, privileged, requestable, desc))
        return Ref("group", system, xid)

    def edge(self, src: Ref, dst: Ref, relation: str, system: str | None = None):
        self.r[system or dst.system].edges.append(EdgeRecord(src, dst, relation))
        self._children[src].append(dst)

    def grant(self, group: Ref, *perms: Ref):
        for p in perms:
            self.edge(group, p, "grants")

    def account(self, system, xid, username, owner_eid: str | None, kind="user", status="active",
                created=None, last_login=None) -> Ref:
        self.r[system].accounts.append(AccountRecord(
            system, xid, username, IdentityRef(external_id=owner_eid) if owner_eid else None, kind, status,
            created or self.days_ago(self.rng.randint(120, 900)),
            last_login or (self.days_ago(self.rng.random() * 3) if status == "active" else None)))
        ref = Ref("account", system, xid)
        if owner_eid:
            self._identity_accounts[owner_eid].append(ref)
        return ref

    def member(self, acct: Ref, *groups: Ref):
        for g in groups:
            self.edge(acct, g, "member_of", system=acct.system)

    # ---------------------------------------------------------------- build
    def _build(self):
        self._build_people()
        self._build_workday()
        self._build_okta()
        self._build_aws()
        self._build_github()
        self._build_snowflake()
        self._build_nhis()
        self._build_agents()
        self._build_usage()
        self._build_hris_events()

    def _build_people(self):
        firsts = [f for f in FIRST_NAMES if f not in {n[0] for n in PINNED.values()}]
        self.rng.shuffle(firsts)
        n = 1001
        leads: dict[str, Person] = {}
        for dept, team, size, titles in ORG:
            for i in range(size):
                if (team, i) in PINNED:
                    first, last = PINNED[(team, i)]
                else:
                    first, last = firsts.pop(), self.rng.choice(LAST_NAMES)
                title = titles[0] if i == 0 else self.rng.choice(titles[1:] or titles)
                if team == "exec":
                    title = titles[i]
                p = Person(f"emp-{n}", first, last, dept, team, title, lead=(i == 0),
                           hired_at=self.days_ago(self.rng.randint(150, 2200)))
                n += 1
                if i == 0:
                    leads[team] = p
                self.people.append(p)
                self.by_name[p.name] = p
        ceo, cto, cfo = (self.by_name[n] for n in ("Rosalind Haverford", "Caspian Arkwright", "Mireille Delacroix"))
        exec_for = {"Engineering": cto, "Data": cto, "Security": cto, "Finance": cfo}
        for p in self.people:
            if p.team == "exec":
                p.manager_eid = None if p is ceo else ceo.eid
            elif p.lead:
                p.manager_eid = exec_for.get(p.dept, ceo).eid
            else:
                p.manager_eid = leads[p.team].eid
            if p.name in TERMINATED:
                p.status = "terminated"
                p.terminated_at = self.days_ago(TERMINATED[p.name])
            self._identity_type[p.eid] = "human"

    def team(self, team: str, active_only=False) -> list[Person]:
        return [p for p in self.people if p.team == team and (p.status == "active" or not active_only)]

    def P(self, name: str) -> Person:
        return self.by_name[name]

    # ----------------------------------------------------------- Workday HRIS
    def _build_workday(self):
        wd = self.r["workday"]
        for p in self.people:
            wd.identities.append(IdentityRecord(
                p.eid, p.name, "human", p.email, p.dept, p.title, p.status,
                manager=IdentityRef(external_id=p.manager_eid) if p.manager_eid else None,
                hired_at=p.hired_at, terminated_at=p.terminated_at))
        self.resource("workday", "supplier-payments", "Supplier Payments", "business_process", "prod",
                      ["payments", "financial"])
        self.resource("workday", "payroll", "Payroll", "business_process", "prod", ["payroll", "pii", "financial"])
        self.resource("workday", "worker-records", "Worker Records", "dataset", "prod", ["pii", "hr"])
        pc = self.perm("workday", "payments:create", "supplier-payments")
        pa = self.perm("workday", "payments:approve", "supplier-payments")
        pr = self.perm("workday", "payroll:run", "payroll", privileged=True)
        pv = self.perm("workday", "payroll:view", "payroll")
        wv = self.perm("workday", "workers:view", "worker-records")
        we = self.perm("workday", "workers:edit", "worker-records", privileged=True)
        g_clerk = self.group("workday", "sg-ap-clerk", "AP Clerk", "security_group", desc="Create supplier payments")
        g_appr = self.group("workday", "sg-ap-approver", "AP Approver", "security_group",
                            desc="Approve supplier payments")
        g_payroll = self.group("workday", "sg-payroll-admin", "Payroll Administrator", "security_group",
                               privileged=True)
        g_hrbp = self.group("workday", "sg-hr-partner", "HR Partner", "security_group")
        g_mgr = self.group("workday", "sg-manager-ss", "Manager Self-Service", "security_group")
        self.grant(g_clerk, pc)
        self.grant(g_appr, pa)
        self.grant(g_payroll, pr, pv)
        self.grant(g_hrbp, wv, we)
        self.grant(g_mgr, wv)
        self.wd_groups = {"clerk": g_clerk, "approver": g_appr, "payroll": g_payroll, "hrbp": g_hrbp, "mgr": g_mgr}
        self.wd_acct: dict[str, Ref] = {}
        for p in self.people:
            a = self.account("workday", p.eid, p.eid, p.eid, status="active" if p.status == "active" else "disabled",
                             created=p.hired_at)
            self.wd_acct[p.eid] = a
            if p.lead:
                self.member(a, g_mgr)
        fin = self.team("finance")
        # Priya holds both clerk and approver -> SoD violation
        self.member(self.wd_acct[self.P("Priya Ramaswamy").eid], g_clerk, g_appr)
        self.member(self.wd_acct[self.P("Tomas Szabo").eid], g_clerk)
        self.member(self.wd_acct[self.P("Linnea Sorensen").eid], g_appr)
        self.member(self.wd_acct[fin[4].eid], g_clerk)
        self.member(self.wd_acct[self.P("Mireille Delacroix").eid], g_appr)
        self.member(self.wd_acct[fin[0].eid], g_appr, g_payroll)
        for p in self.team("people"):
            self.member(self.wd_acct[p.eid], g_hrbp)
        self.member(self.wd_acct[self.team("people")[1].eid], g_payroll)

    # --------------------------------------------------------------- Okta
    def _build_okta(self):
        self.resource("okta", "tenant", "larkspur.okta.example", "idp_tenant", "prod", ["identity"])
        sa = self.perm("okta", "okta:SuperAdmin", "tenant", privileged=True)
        ua = self.perm("okta", "okta:UserAdmin", "tenant", privileged=True)
        self.okta = {
            "everyone": self.group("okta", "everyone", "Everyone"),
            "engineering": self.group("okta", "engineering", "engineering"),
            "eng-backend": self.group("okta", "eng-backend", "eng-backend"),
            "eng-frontend": self.group("okta", "eng-frontend", "eng-frontend"),
            "eng-platform": self.group("okta", "eng-platform", "eng-platform"),
            "data-team": self.group("okta", "data-team", "data-team"),
            "security-team": self.group("okta", "security-team", "security-team"),
            "finance": self.group("okta", "finance", "finance"),
            "sales": self.group("okta", "sales", "sales"),
            "support": self.group("okta", "support", "support"),
            "people-ops": self.group("okta", "people-ops", "people-ops"),
            "executives": self.group("okta", "executives", "executives"),
            "okta-super-admins": self.group("okta", "okta-super-admins", "okta-super-admins", privileged=True,
                                            desc="Okta Super Administrators"),
            "okta-helpdesk": self.group("okta", "okta-helpdesk", "okta-helpdesk", privileged=True),
        }
        self.grant(self.okta["okta-super-admins"], sa)
        self.grant(self.okta["okta-helpdesk"], ua)
        team_groups = {
            "exec": ["executives"], "backend": ["engineering", "eng-backend"],
            "frontend": ["engineering", "eng-frontend"], "platform": ["engineering", "eng-platform"],
            "data": ["data-team"], "security": ["security-team"], "finance": ["finance"], "sales": ["sales"],
            "support": ["support"], "people": ["people-ops"],
        }
        self.okta_acct: dict[str, Ref] = {}
        for p in self.people:
            status = "active"
            if p.status == "terminated" and p.name != "Oren Whitlock":  # Oren's Okta account was missed
                status = "disabled"
            a = self.account("okta", f"00u{p.eid[4:]}", p.email, p.eid, status=status, created=p.hired_at)
            self.okta_acct[p.eid] = a
            self.member(a, self.okta["everyone"], *(self.okta[g] for g in team_groups[p.team]))
        self.member(self.okta_acct[self.P("Thandiwe Mokoena").eid], self.okta["okta-super-admins"])
        self.member(self.okta_acct[self.P("Ingrid Lindqvist").eid], self.okta["okta-super-admins"])
        self.member(self.okta_acct[self.team("security")[1].eid], self.okta["okta-helpdesk"])
        self.member(self.okta_acct[self.team("support")[2].eid], self.okta["okta-helpdesk"])
        self.okta_team_groups = team_groups

    # ---------------------------------------------------------------- AWS
    def _build_aws(self):
        R = self.resource
        R("aws", "s3:customer-pii", "s3://customer-pii", "s3_bucket", "prod", ["pii"])
        R("aws", "s3:app-logs", "s3://app-logs", "s3_bucket", "prod", [])
        R("aws", "s3:finance-reports", "s3://finance-reports", "s3_bucket", "prod", ["financial"])
        R("aws", "s3:ml-artifacts", "s3://ml-artifacts", "s3_bucket", "staging", [])
        R("aws", "s3:terraform-state", "s3://terraform-state", "s3_bucket", "prod", ["infra"])
        R("aws", "rds:orders-db", "rds/orders-db", "rds_instance", "prod", ["pii"])
        R("aws", "ec2:prod-fleet", "ec2/prod-fleet", "ec2_fleet", "prod", [])
        R("aws", "acct:prod", "aws-account/larkspur-prod", "aws_account", "prod", [])
        R("aws", "acct:staging", "aws-account/larkspur-staging", "aws_account", "staging", [])
        R("aws", "kms:pii-key", "kms/pii-key", "kms_key", "prod", ["pii"])
        p = lambda a, r, priv=False: self.perm("aws", a, r, priv)  # noqa: E731
        get_pii, put_pii, del_pii = p("s3:GetObject", "s3:customer-pii"), p("s3:PutObject", "s3:customer-pii"), \
            p("s3:DeleteObject", "s3:customer-pii", True)
        get_logs, put_logs = p("s3:GetObject", "s3:app-logs"), p("s3:PutObject", "s3:app-logs")
        get_fin, put_fin = p("s3:GetObject", "s3:finance-reports"), p("s3:PutObject", "s3:finance-reports")
        get_ml, put_ml = p("s3:GetObject", "s3:ml-artifacts"), p("s3:PutObject", "s3:ml-artifacts")
        get_tf, put_tf = p("s3:GetObject", "s3:terraform-state"), p("s3:PutObject", "s3:terraform-state", True)
        rds_conn, rds_mod = p("rds:Connect", "rds:orders-db"), p("rds:ModifyDBInstance", "rds:orders-db", True)
        ec2_desc, ec2_term = p("ec2:DescribeInstances", "ec2:prod-fleet"), p("ec2:TerminateInstances", "ec2:prod-fleet", True)
        admin_prod, admin_stg = p("iam:*", "acct:prod", True), p("iam:*", "acct:staging", True)
        iam_read = p("iam:GetAccountAuthorizationDetails", "acct:prod")
        ce = p("ce:GetCostAndUsage", "acct:prod")
        kms = p("kms:Decrypt", "kms:pii-key")
        self.aws_perms = locals()
        role = lambda x, priv=False, req=False, d=None: self.group("aws", f"role/{x}", x, "role", priv, req, d)  # noqa: E731
        self.aws = {
            "DevAdmin": role("DevAdmin", True, d="Developer admin on staging (legacy: also reads customer-pii)"),
            "ProdReadOnly": role("ProdReadOnly", d="Read-only access to prod"),
            "ProdAdmin": role("ProdAdmin", True, True, "Full admin on the prod account"),
            "BreakGlassAdmin": role("BreakGlassAdmin", True, True, "Emergency admin (JIT only)"),
            "DataEngineer": role("DataEngineer", d="Data platform access"),
            "BillingAdmin": role("BillingAdmin", d="Cost and finance reporting"),
            "SecurityAudit": role("SecurityAudit", d="Security read-only audit"),
            "CIDeployRole": role("CIDeployRole", True, d="Assumed by CI to deploy infrastructure"),
            "SREAgentRole": role("SREAgentRole", d="Assumed by the SRE on-call agent"),
        }
        A = self.aws
        self.grant(A["DevAdmin"], admin_stg, get_ml, put_ml, get_pii, get_logs)
        self.grant(A["ProdReadOnly"], ec2_desc, get_logs, rds_conn)
        self.grant(A["ProdAdmin"], admin_prod, ec2_term, rds_mod, del_pii, put_tf, get_tf, ec2_desc)
        self.grant(A["BreakGlassAdmin"], admin_prod)
        self.grant(A["DataEngineer"], get_pii, put_pii, get_ml, put_ml, kms, rds_conn)
        self.grant(A["BillingAdmin"], ce, get_fin, put_fin)
        self.grant(A["SecurityAudit"], iam_read, get_logs, ec2_desc, get_tf)
        self.grant(A["CIDeployRole"], put_tf, get_tf, ec2_term, put_ml, get_ml)
        self.edge(A["SREAgentRole"], A["ProdReadOnly"], "maps_to")
        # SAML federation: Okta groups -> AWS roles
        O = self.okta
        for g, roles in {"engineering": ["DevAdmin", "ProdReadOnly"], "eng-platform": ["ProdAdmin"],
                         "data-team": ["DataEngineer"], "finance": ["BillingAdmin"],
                         "security-team": ["SecurityAudit", "ProdReadOnly"]}.items():
            for r in roles:
                self.edge(O[g], A[r], "maps_to", system="aws")

    # ------------------------------------------------------------- GitHub
    def _build_github(self):
        repos = {
            "payments-service": ("prod", ["payments"]), "web-app": ("prod", []), "mobile-app": ("prod", []),
            "infra-terraform": ("prod", ["infra"]), "data-pipelines": ("prod", []),
            "ml-models": ("staging", []), "docs-site": (None, []),
        }
        for r, (env, tags) in repos.items():
            self.resource("github", f"repo:{r}", f"larkspur/{r}", "repository", env, tags)
        self.resource("github", "org", "github.com/larkspur", "org", "prod", [])
        gp = lambda a, r: self.perm("github", f"repo:{a}", f"repo:{r}", a == "admin")  # noqa: E731
        org_admin = self.perm("github", "org:admin", "org", True)
        team = lambda x, priv=False: self.group("github", f"team/{x}", x, "team", priv)  # noqa: E731
        self.gh = {t: team(t) for t in ["backend", "frontend", "platform", "data", "security", "all-engineers"]}
        self.gh["org-owners"] = team("org-owners", True)
        T = self.gh
        self.grant(T["all-engineers"], *(gp("read", r) for r in repos))
        self.grant(T["backend"], gp("write", "payments-service"), gp("write", "web-app"))
        self.grant(T["frontend"], gp("write", "web-app"), gp("write", "mobile-app"), gp("write", "docs-site"))
        self.grant(T["platform"], gp("admin", "infra-terraform"), *(gp("write", r) for r in repos))
        self.grant(T["data"], gp("write", "data-pipelines"), gp("write", "ml-models"))
        self.grant(T["security"], gp("admin", "payments-service"), gp("read", "infra-terraform"))
        self.grant(T["org-owners"], org_admin)
        self.gh_perm = gp
        self.gh_repos = list(repos)
        self.gh_acct: dict[str, Ref] = {}
        for p in self.people:
            if p.team not in ("backend", "frontend", "platform", "data", "security") and p.name != "Caspian Arkwright":
                continue
            a = self.account("github", p.gh, p.gh, p.eid, created=p.hired_at)  # GitHub accounts not deprovisioned
            self.gh_acct[p.eid] = a
            teams = [T["all-engineers"]]
            if p.team in T:
                teams.append(T[p.team])
            self.member(a, *teams)
        for n in ("Caspian Arkwright", "Ingrid Lindqvist", "Kofi Mensah"):
            self.member(self.gh_acct[self.P(n).eid], T["org-owners"])

    # ---------------------------------------------------------- Snowflake
    def _build_snowflake(self):
        for db, tags in {"CUSTOMERS": ["pii"], "FINANCE": ["financial"], "EVENTS": [], "MARKETING": []}.items():
            self.resource("snowflake", f"db:{db}", f"snowflake/{db}", "database", "prod", tags)
        self.resource("snowflake", "account", "snowflake/LARKSPUR_SF", "warehouse_account", "prod", [])
        sp = lambda a, r, priv=False: self.perm("snowflake", f"snowflake:{a}", f"db:{r}", priv)  # noqa: E731
        acctadmin = self.perm("snowflake", "snowflake:ACCOUNTADMIN", "account", True)
        role = lambda x, priv=False, req=False: self.group("snowflake", f"role/{x}", x, "role", priv, req)  # noqa: E731
        self.sf = {r: role(r) for r in ["ANALYST", "PII_READER", "DATA_ENGINEER", "FINANCE_ANALYST", "LOADER",
                                        "REPORTING"]}
        self.sf["ACCOUNTADMIN"] = role("ACCOUNTADMIN", True, True)
        self.sf["SYSADMIN"] = role("SYSADMIN", True)
        S = self.sf
        self.grant(S["ANALYST"], sp("SELECT", "EVENTS"), sp("SELECT", "MARKETING"))
        self.grant(S["PII_READER"], sp("SELECT", "CUSTOMERS"))
        self.grant(S["DATA_ENGINEER"], sp("INSERT", "EVENTS"), sp("INSERT", "CUSTOMERS"), sp("INSERT", "MARKETING"))
        self.grant(S["FINANCE_ANALYST"], sp("SELECT", "FINANCE"))
        self.grant(S["LOADER"], sp("INSERT", "EVENTS"), sp("INSERT", "CUSTOMERS"))
        self.grant(S["REPORTING"], sp("SELECT", "EVENTS"), sp("SELECT", "FINANCE"))
        self.grant(S["ACCOUNTADMIN"], acctadmin)
        self.grant(S["SYSADMIN"], *(sp("OWNERSHIP", d, True) for d in ["CUSTOMERS", "FINANCE", "EVENTS", "MARKETING"]))
        # role hierarchy
        self.edge(S["DATA_ENGINEER"], S["ANALYST"], "maps_to")
        self.edge(S["DATA_ENGINEER"], S["PII_READER"], "maps_to")
        self.edge(S["ACCOUNTADMIN"], S["SYSADMIN"], "maps_to")
        self.sf_acct: dict[str, Ref] = {}

        def sfuser(p: Person, *roles):
            a = self.account("snowflake", p.sf, p.sf, p.eid, created=p.hired_at)
            self.sf_acct[p.eid] = a
            self.member(a, *(S[r] for r in roles))

        for p in self.team("data"):
            sfuser(p, "DATA_ENGINEER")
        for p in self.team("finance")[:5]:
            sfuser(p, "FINANCE_ANALYST")
        for p in self.team("sales")[:6]:
            sfuser(p, "ANALYST")
        for p in self.team("support")[:3]:
            sfuser(p, "ANALYST", "PII_READER")
        sfuser(self.P("Mireille Delacroix"), "FINANCE_ANALYST", "ANALYST")
        sfuser(self.P("Kofi Mensah"), "ANALYST")
        # standing ACCOUNTADMIN for two data folks (one never uses it)
        self.member(self.sf_acct[self.P("Sana Iyer").eid], S["ACCOUNTADMIN"])
        self.member(self.sf_acct[self.team("data")[2].eid], S["ACCOUNTADMIN"])

    # ---------------------------------------------------- non-human identities
    def _nhi(self, xid, name, system, owner: str | None, desc, kind="service"):
        owner_ref = IdentityRef(external_id=self.P(owner).eid) if owner else None
        self.r[system].identities.append(IdentityRecord(
            xid, name, "service", None, None, kind, "active", owner=owner_ref, description=desc))
        self._identity_type[xid] = "service"
        return xid

    def _secret(self, system, acct: Ref, kind, name, age, rotated=None, last_used=None):
        self.r[system].secrets.append(SecretRecord(
            system, f"{acct.external_id}/{name}", acct, kind, name, self.days_ago(age),
            self.days_ago(rotated) if rotated is not None else None,
            self.days_ago(last_used) if last_used is not None else None))

    def _build_nhis(self):
        A, T, S, O = self.aws, self.gh, self.sf, self.okta
        ap = self.aws_perms
        # ---- AWS IAM users with access keys
        aws_nhis = [
            ("svc-ci-deployer", "Ingrid Lindqvist", "CI/CD pipeline deployer", [A["CIDeployRole"]], [], 412, 0.1),
            ("svc-backup-agent", "Dmitri Ostrowski", "Nightly RDS/S3 backup job", [],
             [ap["get_pii"], ap["rds_conn"], ap["put_logs"]], 230, 0.5),
            ("svc-legacy-etl", None, "Legacy ETL from the 2022 data platform", [],
             [ap["get_pii"], ap["get_fin"], ap["kms"]], 780, 128),
            ("svc-log-shipper", "Thandiwe Mokoena", "Ships logs to the SIEM", [], [ap["put_logs"], ap["get_logs"]], 31, 0.1),
            ("svc-cost-exporter", "Beatrix Pemberton", "Exports cost data to finance", [], [ap["ce"], ap["put_fin"]], 95, 1),
            ("svc-terraform", "Ingrid Lindqvist", "Terraform Cloud runner", [], [ap["admin_prod"], ap["put_tf"]], 160, 2),
            ("svc-monitoring", "Marcus Bellweather", "Metrics collector", [], [ap["ec2_desc"]], 60, 0.1),
            ("svc-lambda-orders", "Kofi Mensah", "Orders Lambda execution identity", [], [ap["rds_conn"]], 12, 0.1),
            ("svc-data-export", "Oren Whitlock", "Ad-hoc customer export for a 2025 audit", [],
             [ap["get_pii"], ap["put_fin"]], 340, 74),
        ]
        for name, owner, desc, roles, perms, key_age, last_used in aws_nhis:
            xid = self._nhi(f"nhi-aws-{name}", name, "aws", owner, desc, "AWS IAM user")
            a = self.account("aws", f"iam-user/{name}", name, xid, kind="service")
            for r in roles:
                self.edge(a, r, "member_of", system="aws")
            for p in perms:
                self.edge(a, p, "direct_grant", system="aws")
            self._secret("aws", a, "access_key", f"AKIA{name.upper().replace('-', '')[:12]}", key_age,
                         last_used=last_used)
            if last_used > 60:
                self._dormant[xid] = int(last_used)
        # ---- GitHub apps / tokens
        gp = self.gh_perm
        gh_nhis = [
            ("release-bot", "Ingrid Lindqvist", "GitHub App that cuts releases", "github_app",
             [gp("write", r) for r in self.gh_repos], 45, 0.2),
            ("infra-deploy-key", None, "Deploy key on infra-terraform", "deploy_key",
             [gp("write", "infra-terraform")], 610, 3),
            ("jenkins-pat", "Oren Whitlock", "Personal access token used by legacy Jenkins", "pat",
             [gp("admin", "payments-service"), gp("write", "web-app")], 300, 0.5),
            ("dependabot-svc", "Thandiwe Mokoena", "Dependency update automation", "github_app",
             [gp("read", r) for r in self.gh_repos], 20, 0.1),
            ("docs-publisher", None, "Publishes docs-site on merge", "deploy_key",
             [gp("write", "docs-site")], 20, 1),
        ]
        for name, owner, desc, kind, perms, age, lu in gh_nhis:
            xid = self._nhi(f"nhi-gh-{name}", name, "github", owner, desc, f"GitHub {kind.replace('_', ' ')}")
            a = self.account("github", f"bot/{name}", name, xid, kind="service")
            for p in perms:
                self.edge(a, p, "direct_grant", system="github")
            self._secret("github", a, kind, f"{name}-token", age, last_used=lu)
        # ---- Snowflake service users
        sf_nhis = [
            ("FIVETRAN_LOADER", "Sana Iyer", "Fivetran ingestion", ["LOADER"], 70, 0.1),
            ("DBT_RUNNER", "Sana Iyer", "dbt transformations", ["DATA_ENGINEER"], 200, 0.1),
            ("LOOKER_SVC", "Dmitri Ostrowski", "Looker BI connection", ["ANALYST", "PII_READER"], 400, 0.2),
            ("TABLEAU_LEGACY", None, "Retired Tableau server", ["REPORTING"], 900, 150),
            ("REVERSE_ETL_SVC", "Rafael Valdivia", "Syncs customer segments to CRM", ["PII_READER"], 120, 0.5),
        ]
        for name, owner, desc, roles, age, lu in sf_nhis:
            xid = self._nhi(f"nhi-sf-{name.lower()}", name, "snowflake", owner, desc, "Snowflake service user")
            a = self.account("snowflake", f"svc/{name}", name, xid, kind="service")
            self.member(a, *(S[r] for r in roles))
            self._secret("snowflake", a, "keypair", f"{name}_rsa", age, last_used=lu)
            if lu > 60:
                self._dormant[xid] = int(lu)
        # ---- Okta API tokens
        okta_nhis = [
            ("scim-provisioner", "Thandiwe Mokoena", "SCIM provisioning token", [O["okta-super-admins"]], 88),
            ("hr-sync-token", "Esme Thornbury", "Workday -> Okta HR sync", [O["okta-helpdesk"]], 140),
            ("old-migration-token", None, "Token from the 2023 IdP migration", [O["okta-super-admins"]], 700),
        ]
        for name, owner, desc, groups, age in okta_nhis:
            xid = self._nhi(f"nhi-okta-{name}", name, "okta", owner, desc, "Okta API token")
            a = self.account("okta", f"svc/{name}", name, xid, kind="api_key")
            self.member(a, *groups)
            lu = 200 if name == "old-migration-token" else 0.3
            self._secret("okta", a, "api_token", name, age, last_used=lu)
            if lu > 60:
                self._dormant[xid] = int(lu)
        # ---- Workday integration system users
        wd_nhis = [
            ("ISU_Okta_Sync", "Esme Thornbury", "Integration user for Okta sync", [self.wd_groups["hrbp"]], 365),
            ("ISU_Payroll_Export", "Beatrix Pemberton", "Payroll export to bank", [self.wd_groups["payroll"]], 500),
            ("ISU_Expense_Bot", "Hollis Brightwater", "Expense report automation", [self.wd_groups["clerk"]], 260),
        ]
        for name, owner, desc, groups, age in wd_nhis:
            xid = self._nhi(f"nhi-wd-{name.lower()}", name, "workday", owner, desc, "Workday integration user")
            a = self.account("workday", f"isu/{name}", name, xid, kind="service")
            self.member(a, *groups)
            self._secret("workday", a, "password", f"{name}-password", age, last_used=1)

    # ---------------------------------------------------------- AI agents
    def _build_agents(self):
        S, A, T = self.sf, self.aws, self.gh
        gp = self.gh_perm
        agents = [
            ("agent-support-copilot", "Support Copilot", "Yara Castellanos",
             "Drafts replies to customer tickets using account history",
             [("Yara Castellanos", ["tickets:read", "customers:read"]),
              ("Callum Ferreira", ["tickets:read", "customers:read", "tickets:reply"])],
             lambda a: self.member(a, S["PII_READER"]), "snowflake", 25),
            ("agent-code-review", "Code Review Bot", "Kofi Mensah", "Reviews pull requests and suggests fixes",
             [("Alice Okafor", ["github:pull_request:comment", "github:repo:read"])],
             lambda a: [self.edge(a, gp("read", r), "direct_grant", "github") for r in self.gh_repos]
             + [self.edge(a, gp("write", "web-app"), "direct_grant", "github")], "github", 40),
            ("agent-finance-recon", "Finance Recon Agent", "Beatrix Pemberton",
             "Reconciles supplier invoices and prepares payments",
             [("Beatrix Pemberton", ["workday:payments:create", "snowflake:query:FINANCE"])],
             lambda a: self.member(a, self.wd_groups["clerk"]), "workday", 60),
            ("agent-data-analyst", "Data Analyst Agent", "Sana Iyer", "Answers ad-hoc analytics questions in Slack",
             [("Sana Iyer", ["snowflake:query"]), ("Rafael Valdivia", ["snowflake:query:MARKETING"])],
             lambda a: self.member(a, S["ANALYST"], S["PII_READER"]), "snowflake", 100),
            ("agent-sre-oncall", "SRE On-call Agent", "Marcus Bellweather",
             "Triages alerts and gathers diagnostics from prod",
             [("Marcus Bellweather", ["aws:ec2:describe", "aws:logs:read"])],
             lambda a: self.member(a, A["SREAgentRole"]), "aws", 15),
            ("agent-sales-research", "Sales Research Agent", "Hollis Brightwater",
             "Enriches leads and summarizes accounts before calls",
             [("Hollis Brightwater", ["snowflake:query:MARKETING", "crm:read"])],
             lambda a: self.member(a, S["ANALYST"], S["REPORTING"]), "snowflake", 210),
        ]
        okta_agents = self.group("okta", "ai-agents", "ai-agents", desc="Registered AI agent identities")
        for xid, name, owner, desc, delegations, wire, system, key_age in agents:
            self.r["okta"].identities.append(IdentityRecord(
                xid, name, "ai_agent", None, None, "AI agent", "active",
                owner=IdentityRef(external_id=self.P(owner).eid), description=desc))
            self._identity_type[xid] = "ai_agent"
            oa = self.account("okta", f"agent/{xid}", f"{xid}@agents.{DOMAIN}", xid, kind="agent")
            self.member(oa, okta_agents)
            sys_acct = self.account(system, f"agent/{xid}", xid, xid, kind="agent")
            wire(sys_acct)
            self._secret(system, sys_acct, "api_token", f"{xid}-key", key_age, last_used=0.1)
            for principal, scopes in delegations:
                self.r["okta"].delegations.append(DelegationRecord(
                    IdentityRef(external_id=xid), IdentityRef(external_id=self.P(principal).eid), scopes))
        self._agent_acct_sf = {}

    # --------------------------------------------------------------- usage
    def _reachable(self, eid: str) -> dict[Ref, Ref]:
        """perm ref -> account ref through which it is reached (model-level traversal)."""
        out: dict[Ref, Ref] = {}
        for acct in self._identity_accounts.get(eid, []):
            stack, seen = [acct], set()
            while stack:
                cur = stack.pop()
                for nxt in self._children.get(cur, []):
                    if nxt in seen:
                        continue
                    seen.add(nxt)
                    if nxt.kind == "perm":
                        out.setdefault(nxt, acct)
                    else:
                        stack.append(nxt)
        return out

    def _build_usage(self):
        rng = self.rng
        ids = [(p.eid, p) for p in self.people] + [(x, None) for x, t in self._identity_type.items() if t != "human"]
        # Story-specific "never used" grants
        alice = self.P("Alice Okafor").eid
        for perm_xid in ("s3:GetObject@s3:customer-pii", "iam:*@acct:staging", "s3:PutObject@s3:ml-artifacts"):
            self._unused.add((alice, perm_xid))
        # Legacy DevAdmin grant to customer-pii: no engineer actually uses it -> role-level trim
        for p in self.team("backend") + self.team("frontend") + self.team("platform"):
            self._unused.add((p.eid, "s3:GetObject@s3:customer-pii"))
        self._unused.add((self.team("data")[2].eid, "snowflake:ACCOUNTADMIN@account"))
        self._unused.add((self.P("Priya Ramaswamy").eid, "payments:approve@supplier-payments"))
        for eid, person in ids:
            perms = self._reachable(eid)
            if not perms:
                continue
            itype = self._identity_type[eid]
            last_active = 0
            if person is not None and person.status == "terminated":
                last_active = TERMINATED[person.name]
            if eid in self._dormant:
                last_active = self._dormant[eid]
            activity = rng.uniform(0.25, 0.7) if itype == "human" else rng.uniform(0.7, 1.0)
            for pref, acct in perms.items():
                meta = self._perm_meta[pref]
                if (eid, pref.external_id) in self._unused:
                    continue
                roll = rng.random()
                p_unused = 0.55 if meta["privileged"] else 0.25
                if itype != "human":
                    p_unused *= 0.5
                if roll < p_unused:
                    continue  # granted, never used
                window_end = last_active
                if roll < p_unused + 0.1 and itype == "human":
                    window_end = max(window_end, rng.randint(62, 85))  # used once, long ago
                    days = [rng.randint(window_end, 89)]
                else:
                    rate = activity * (0.3 if meta["privileged"] else 1.0)
                    days = [d for d in range(window_end, 90) if rng.random() < rate]
                for d in days:
                    cnt = rng.randint(1, 40 if itype != "human" else 12)
                    self.usage[pref.system].append(UsageRecord(
                        IdentityRef(external_id=eid), pref, self.days_ago(d), cnt, account=acct))

    # ----------------------------------------------------------- HRIS feed
    def _build_hris_events(self):
        marcus = self.P("Marcus Bellweather")
        mover = self.team("support")[3]
        self.hris_events = [
            HrisEventRecord("wd-evt-9001", "leaver", marcus.ref, self.now,
                            {"reason": "Resignation", "last_day": self.now.date().isoformat()}),
            HrisEventRecord("wd-evt-9002", "mover", mover.ref, self.now + timedelta(days=2),
                            {"from_department": "Support", "to_department": "Sales",
                             "from_team": "support", "to_team": "sales", "new_title": "Account Executive"}),
            HrisEventRecord("wd-evt-9003", "joiner", None, self.now + timedelta(days=3),
                            {"name": "Noor Achterberg", "email": f"noor.achterberg@{DOMAIN}", "department": "Data",
                             "team": "data", "title": "Analytics Engineer",
                             "manager_external_id": self.P("Sana Iyer").eid}),
        ]
        for p in self.people:
            if p.status == "terminated":
                self.hris_events.append(HrisEventRecord(
                    f"wd-evt-term-{p.eid}", "leaver", p.ref, p.terminated_at,
                    {"reason": "Voluntary", "historical": True}))


_CACHE: dict[tuple, DemoCompany] = {}


def get_company(seed: int = 7, now: datetime | None = None) -> DemoCompany:
    key = (seed, (now or utcnow()).date())
    if key not in _CACHE:
        _CACHE[key] = DemoCompany(seed, now)
    return _CACHE[key]
