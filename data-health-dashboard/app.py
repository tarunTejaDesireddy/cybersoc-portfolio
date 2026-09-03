import re
from datetime import timedelta

import pandas as pd
import requests
import streamlit as st
from azure.identity import ClientSecretCredential
from azure.monitor.query import LogsQueryClient

st.set_page_config(page_title="Sentinel Data Health", layout="wide", page_icon="📡")

ARM_BASE = "https://management.azure.com"
# Matches the api-version already proven working against this exact tenant in
# infrastructure/SETUP.md (alertRuleTemplates, incident comments) -- reusing a
# confirmed-good version string beats guessing a "probably also valid" one.
ARM_API_VERSION = "2024-01-01-preview"

FRESHNESS_WINDOW_DAYS = 30
STALE_AFTER_HOURS = 26  # a bit over a day -- catches "stopped ingesting" without flagging a normal overnight lull
CACHE_TTL_SECONDS = 300

# Logical connector groupings for THIS lab, not a query against Sentinel's
# Data Connector gallery. Reflects the architecture documented in the repo
# root README: Azure Activity Log and Entra ID sign-in/audit are subscription-
# and tenant-level *diagnostic settings*, Syslog and Windows Security Events
# are DCR/AMA-fed, and the AbuseIPDB feed is a custom script hitting the
# Threat Intelligence Indicators API directly -- none of those are
# Microsoft.SecurityInsights/dataConnectors resources, even though they are
# very real, active data sources. See "Why a logical grouping, not just the
# connector gallery" in this folder's README. Edit this dict if your own
# environment's table names differ.
CONNECTOR_TABLES = {
    "Azure Activity Log": ["AzureActivity"],
    "Entra ID (sign-in / audit)": ["SigninLogs", "AADNonInteractiveUserSignInLogs", "AuditLogs"],
    "Syslog (VM via AMA)": ["Syslog"],
    "Windows Security Events (Arc)": ["SecurityEvent"],
    "Custom Threat Intel (AbuseIPDB)": ["ThreatIntelIndicators"],
    "Detection health (built-in)": ["Heartbeat", "Usage", "Perf"],
}
TABLE_TO_CONNECTOR = {t: c for c, tables in CONNECTOR_TABLES.items() for t in tables}
KNOWN_TABLES = sorted(TABLE_TO_CONNECTOR)


@st.cache_resource
def get_credential():
    return ClientSecretCredential(
        tenant_id=st.secrets["azure"]["tenant_id"],
        client_id=st.secrets["azure"]["client_id"],
        client_secret=st.secrets["azure"]["client_secret"],
    )


@st.cache_resource
def get_logs_client():
    return LogsQueryClient(get_credential())


def workspace_resource_id() -> str:
    az = st.secrets["azure"]
    return (
        f"/subscriptions/{az['subscription_id']}/resourceGroups/{az['resource_group']}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{az['workspace_name']}"
    )


def arm_get(path: str) -> dict:
    # get_token() is cheap to call repeatedly -- azure-identity caches the
    # token internally and only actually refreshes when it's near expiry.
    token = get_credential().get_token("https://management.azure.com/.default").token
    url = f"{ARM_BASE}{path}?api-version={ARM_API_VERSION}"
    resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=15)
    resp.raise_for_status()
    return resp.json()


# --- Table freshness (KQL) ---------------------------------------------------
# union * over the whole workspace, but this lab's own architecture caps
# ingestion at 1 GB/day (see repo root README) -- at that size, even a
# 30-day union stays cheap. A larger workspace should shrink
# FRESHNESS_WINDOW_DAYS or scope the union to specific tables instead.
TABLE_FRESHNESS_QUERY = """
union withsource=SourceTable *
| summarize LastLog=max(TimeGenerated), RowCount=count() by SourceTable
"""


@st.cache_data(ttl=CACHE_TTL_SECONDS)
def fetch_table_freshness() -> pd.DataFrame:
    client = get_logs_client()
    workspace_id = st.secrets["azure"]["workspace_id"]
    response = client.query_workspace(
        workspace_id=workspace_id,
        query=TABLE_FRESHNESS_QUERY,
        timespan=timedelta(days=FRESHNESS_WINDOW_DAYS),
    )
    table = response.tables[0]
    return pd.DataFrame(data=table.rows, columns=table.columns)


def build_table_health(freshness_df: pd.DataFrame) -> pd.DataFrame:
    # A table with zero rows in the window simply never appears in `union`'s
    # result -- left-joining onto the full known-table list is what turns
    # "silently absent" into a visible "No data" row instead of the table
    # just vanishing from view.
    seen_tables = set(freshness_df["SourceTable"]) if "SourceTable" in freshness_df.columns else set()
    all_tables = sorted(set(KNOWN_TABLES) | seen_tables)
    base = pd.DataFrame({"Table": all_tables})

    freshness_df = freshness_df.rename(columns={"SourceTable": "Table"})
    merged = base.merge(freshness_df, on="Table", how="left")
    merged["LastLog"] = pd.to_datetime(merged["LastLog"], utc=True, errors="coerce")
    merged["RowCount"] = pd.to_numeric(merged["RowCount"], errors="coerce").fillna(0).astype(int)

    now = pd.Timestamp.now("UTC")
    merged["HoursSinceLastLog"] = (now - merged["LastLog"]).dt.total_seconds() / 3600

    def status(row) -> str:
        if pd.isna(row["LastLog"]):
            return f"🔴 No data in {FRESHNESS_WINDOW_DAYS}d"
        if row["HoursSinceLastLog"] > STALE_AFTER_HOURS:
            return "🟡 Stale"
        return "🟢 Healthy"

    merged["Status"] = merged.apply(status, axis=1)
    merged["Connector"] = merged["Table"].map(TABLE_TO_CONNECTOR).fillna("Unmapped / other table")
    return merged.sort_values(["Connector", "Table"]).reset_index(drop=True)


# --- Analytics rules (ARM) ---------------------------------------------------
@st.cache_data(ttl=CACHE_TTL_SECONDS)
def fetch_analytics_rules() -> pd.DataFrame:
    path = f"{workspace_resource_id()}/providers/Microsoft.SecurityInsights/alertRules"
    try:
        data = arm_get(path)
    except requests.RequestException as e:
        st.error(f"Couldn't list analytics rules: {e}")
        return pd.DataFrame(columns=["RuleId", "DisplayName", "Enabled", "Severity", "Query"])

    rows = []
    for item in data.get("value", []):
        props = item.get("properties", {})
        rows.append({
            "RuleId": item.get("name", ""),
            "DisplayName": props.get("displayName", "(unnamed)"),
            "Enabled": bool(props.get("enabled", False)),
            "Severity": props.get("severity", ""),
            "Query": props.get("query", ""),
        })
    return pd.DataFrame(rows)


def detect_tables_in_query(query: str) -> list:
    # Heuristic: match each KNOWN_TABLES name as a whole-word token in the
    # rule's raw KQL text. Misses a rule that only reaches a table through a
    # function or saved view; can false-positive on a table name that only
    # appears in a comment. There's no structured "which tables does this
    # rule read" field anywhere in the ARM model -- this is the same kind of
    # first-pass heuristic as the MITRE classification in ip-threat-dashboard,
    # not a guaranteed-accurate join.
    if not query:
        return []
    return [t for t in KNOWN_TABLES if re.search(rf"\b{re.escape(t)}\b", query)]


def build_rules_by_table(rules_df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, r in rules_df.iterrows():
        tables = detect_tables_in_query(r["Query"])
        target_tables = tables if tables else ["(no known table detected)"]
        for t in target_tables:
            rows.append({
                "Table": t,
                "Rule": r["DisplayName"],
                "Severity": r["Severity"],
                "Enabled": "✅" if r["Enabled"] else "⏸️",
            })
    return pd.DataFrame(rows, columns=["Table", "Rule", "Severity", "Enabled"])


# --- Data connector resources (ARM, best-effort) -----------------------------
@st.cache_data(ttl=CACHE_TTL_SECONDS)
def fetch_data_connectors() -> pd.DataFrame:
    path = f"{workspace_resource_id()}/providers/Microsoft.SecurityInsights/dataConnectors"
    try:
        data = arm_get(path)
    except requests.RequestException as e:
        st.warning(f"Couldn't list Data Connector resources: {e}")
        return pd.DataFrame(columns=["Name", "Kind"])

    rows = [{"Name": item.get("name", ""), "Kind": item.get("kind", "")} for item in data.get("value", [])]
    return pd.DataFrame(rows)


# --- UI -----------------------------------------------------------------------
st.title("📡 Sentinel Data Health")
st.caption(
    f"Table freshness, connector grouping, and analytics-rule coverage for this workspace. "
    f"Cached {CACHE_TTL_SECONDS}s — reload the page to force a refresh, this isn't a live-tick dashboard."
)

table_health_df = build_table_health(fetch_table_freshness())
rules_df = fetch_analytics_rules()
rules_by_table_df = build_rules_by_table(rules_df)
connectors_df = fetch_data_connectors()

c1, c2, c3, c4 = st.columns(4)
c1.metric("Tables tracked", len(table_health_df))
c2.metric("Healthy", int((table_health_df["Status"] == "🟢 Healthy").sum()))
c3.metric("Stale / no data", int((table_health_df["Status"] != "🟢 Healthy").sum()))
c4.metric("Analytics rules", len(rules_df))

st.divider()
st.subheader("Table health, by connector")
if table_health_df.empty:
    st.info("No tables found.")
else:
    for connector, group in table_health_df.groupby("Connector", sort=False):
        st.markdown(f"**{connector}**")
        display = group[["Table", "Status", "LastLog", "HoursSinceLastLog", "RowCount"]].copy()
        display["LastLog"] = display["LastLog"].dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        display["LastLog"] = display["LastLog"].fillna(f"No data in {FRESHNESS_WINDOW_DAYS}d")
        display["HoursSinceLastLog"] = display["HoursSinceLastLog"].round(1)
        st.dataframe(
            display.rename(columns={
                "LastLog": "Last log",
                "HoursSinceLastLog": "Hours since last log",
                "RowCount": f"Rows ({FRESHNESS_WINDOW_DAYS}d)",
            }),
            use_container_width=True,
            hide_index=True,
        )

st.divider()
st.subheader("Analytics rules by table")
st.caption(
    "Table detection is heuristic — string-matched against each rule's raw KQL, not a structured "
    "relationship. See this folder's README for what that misses."
)
if rules_by_table_df.empty:
    st.info("No analytics rules found, or the query above failed — check the error message if one appeared.")
else:
    for table, group in rules_by_table_df.groupby("Table"):
        with st.expander(f"{table} ({len(group)} rule{'s' if len(group) != 1 else ''})"):
            st.dataframe(
                group[["Rule", "Severity", "Enabled"]],
                use_container_width=True,
                hide_index=True,
            )

st.divider()
st.subheader("Data Connector resources (Sentinel gallery)")
if connectors_df.empty:
    st.info(
        "No classic Data Connector resources found. Expected here — this lab's sources are "
        "diagnostic settings and DCR/AMA-fed, not gallery connectors. See the README."
    )
else:
    st.dataframe(connectors_df, use_container_width=True, hide_index=True)
