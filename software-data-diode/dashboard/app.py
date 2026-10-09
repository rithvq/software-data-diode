from __future__ import annotations

from datetime import datetime
import html
import json
import os

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st


MONITORING_API_URL = os.getenv("MONITORING_API_URL", "http://monitoring-api:8000")
REFRESH_SECONDS = max(1, int(os.getenv("DASHBOARD_REFRESH_SECONDS", "3")))
PRIORITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f59e0b",
    "MEDIUM": "#22c55e",
    "LOW": "#38bdf8",
}
SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "WARNING": "#facc15",
    "INFO": "#38bdf8",
}

st.set_page_config(
    page_title="Data Diode Observatory",
    page_icon=":material/security:",
    layout="wide",
    initial_sidebar_state="auto",
)


def load_snapshot() -> dict[str, object]:
    response = requests.get(f"{MONITORING_API_URL}/api/snapshot", timeout=4)
    response.raise_for_status()
    document = response.json()
    if not isinstance(document, dict):
        raise ValueError("Monitoring snapshot is not an object")
    return document


def inject_styles() -> None:
    st.markdown(
        """
        <style>
        :root {
            --background: #0b0f14;
            --sidebar: #0f151b;
            --surface: #131a21;
            --surface-2: #18212a;
            --surface-3: #0f161d;
            --border: #31404e;
            --border-strong: #435669;
            --text: #f3f7fa;
            --muted: #a8bac9;
            --muted-2: #7f93a5;
            --cyan: #35c2f4;
            --green: #38d97a;
            --amber: #ffb020;
            --red: #ff5c69;
        }
        .stApp { background: var(--background); color: var(--text); }
        .block-container { max-width: 1560px; padding: 1.5rem 2rem 3rem; }
        [data-testid="stSidebar"] {
            background: var(--sidebar);
            border-right: 1px solid var(--border);
        }
        [data-testid="stSidebar"] .block-container { padding: 1.5rem 1.2rem; }
        [data-testid="stSidebar"] p,
        [data-testid="stSidebar"] label,
        [data-testid="stSidebar"] [data-testid="stWidgetLabel"] p { color: var(--muted) !important; }
        [data-testid="stHeader"] { background: color-mix(in srgb, var(--background) 88%, transparent); }
        h1, h2, h3, h4, p { letter-spacing: 0 !important; }
        h1 { font-size: 1.8rem !important; font-weight: 700 !important; color: var(--text) !important; }
        h2 { font-size: 1.18rem !important; margin-top: 0.4rem !important; color: var(--text) !important; }
        h3 { font-size: 1rem !important; color: var(--text) !important; }
        h4 { font-size: 0.9rem !important; color: var(--muted) !important; }
        p, li { color: var(--text); }

        .product-mark { margin-bottom: 1.4rem; }
        .product-name { color: var(--text); font-size: 1.15rem; font-weight: 700; }
        .product-scope {
            color: var(--cyan); font-size: 0.68rem; font-weight: 700;
            margin-top: 3px; text-transform: uppercase;
        }
        .sidebar-status {
            display: flex; align-items: center; gap: 8px; color: var(--muted);
            background: var(--surface); border: 1px solid var(--border);
            border-radius: 6px; padding: 10px 11px; margin: 0.5rem 0 1.2rem;
            font-size: 0.78rem;
        }
        .sidebar-status strong { color: var(--text); font-weight: 600; }

        .page-header {
            display: flex; justify-content: space-between; align-items: flex-end;
            gap: 20px; margin: 0 0 1.15rem;
        }
        .page-eyebrow {
            color: #7ddcff !important; font-size: 0.7rem; font-weight: 750;
            text-transform: uppercase; margin-bottom: 5px;
        }
        .page-title {
            color: var(--text); font-size: 1.8rem; line-height: 1.15;
            font-weight: 720; margin: 0;
        }
        .status-strip {
            display: flex; align-items: center; flex-wrap: wrap; gap: 8px;
            color: var(--muted); font-size: 0.78rem; white-space: nowrap;
        }
        .status-divider { color: var(--border-strong); }
        .live-dot {
            width: 8px; height: 8px; flex: 0 0 8px; border-radius: 50%;
            background: var(--green); box-shadow: 0 0 0 3px rgba(56,217,122,0.12);
        }

        .kpi-grid {
            display: grid; grid-template-columns: repeat(6, minmax(0, 1fr));
            gap: 12px; margin: 0 0 1.25rem;
        }
        .kpi-card {
            position: relative; min-width: 0; min-height: 104px;
            background: var(--surface); border: 1px solid var(--border);
            border-radius: 6px; padding: 14px 15px; overflow: hidden;
        }
        .kpi-card::before {
            content: ""; position: absolute; inset: 0 auto 0 0; width: 3px;
            background: var(--border-strong);
        }
        .kpi-card.info::before { background: var(--cyan); }
        .kpi-card.success::before { background: var(--green); }
        .kpi-card.warning::before { background: var(--amber); }
        .kpi-card.danger::before { background: var(--red); }
        .kpi-label { color: var(--muted); font-size: 0.72rem; font-weight: 600; }
        .kpi-value {
            color: var(--text); font-size: 1.42rem; line-height: 1.2;
            font-weight: 680; margin-top: 7px; white-space: normal; overflow-wrap: anywhere;
        }
        .kpi-context { color: var(--muted-2); font-size: 0.66rem; margin-top: 6px; }

        [data-testid="stMetric"] {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 0.78rem 0.9rem;
            min-height: 92px;
        }
        [data-testid="stMetricLabel"] p { color: var(--muted) !important; font-size: 0.74rem !important; }
        [data-testid="stMetricValue"] > div { color: var(--text) !important; font-size: 1.35rem !important; }
        /* Keep the last complete snapshot readable during a fragment refresh. */
        [data-testid="stElementContainer"][data-stale="true"] {
            opacity: 1 !important;
            transition: none !important;
        }
        [data-testid="stButtonGroup"] { margin: 0.2rem 0 0.9rem; }
        [data-testid="stButtonGroup"] button { border-radius: 4px !important; }
        [data-testid="stDataFrame"] {
            border: 1px solid var(--border); border-radius: 6px; overflow: hidden;
        }

        .architecture {
            display: grid; grid-template-columns: 1.15fr 38px 1fr 38px 1fr 38px 1.15fr;
            gap: 8px; align-items: stretch; margin: 0.5rem 0 1rem;
        }
        .arch-zone {
            background: var(--surface); border: 1px solid var(--border);
            border-radius: 6px; padding: 13px; min-height: 250px;
        }
        .arch-zone-title {
            color: var(--text); font-size: 0.72rem; font-weight: 750;
            padding-bottom: 10px; margin-bottom: 8px; border-bottom: 1px solid var(--border);
        }
        .arch-zone-subtitle { color: var(--muted-2); font-size: 0.65rem; font-weight: 500; margin-top: 2px; }
        .arch-node {
            display: flex; justify-content: space-between; align-items: center;
            gap: 8px; border-left: 3px solid var(--cyan); background: var(--surface-3);
            padding: 8px 9px; margin: 6px 0; font-size: 0.75rem;
        }
        .arch-node.transport { border-left-color: var(--amber); }
        .arch-node.fog { border-left-color: var(--green); }
        .health { font-size: 0.61rem; font-weight: 750; white-space: nowrap; }
        .health.healthy, .health.active, .health.connected { color: var(--green); }
        .health.stale { color: var(--amber); }
        .health.unknown, .health.unavailable { color: var(--red); }
        .arch-detail { color: var(--muted-2); font-size: 0.68rem; line-height: 1.55; margin: 11px 3px 0; }
        .arch-arrow {
            display: grid; place-items: center; color: var(--cyan);
            font-size: 1.25rem; font-weight: 700;
        }
        .section-label { color: var(--muted); font-size: 0.72rem; text-transform: uppercase; margin: 8px 0; }
        .severity-critical { color: var(--red); font-weight: 700; }
        .severity-high { color: #f97316; font-weight: 700; }
        .severity-warning { color: #facc15; font-weight: 700; }

        [data-testid="stExpander"] {
            background: var(--surface); border: 1px solid var(--border) !important;
            border-radius: 6px !important;
        }
        [data-testid="stAlert"] { border-radius: 6px; }
        .stButton > button, .stDownloadButton > button { border-radius: 5px; }
        [data-baseweb="select"] > div,
        [data-baseweb="input"] > div { background: var(--surface) !important; border-color: var(--border) !important; }

        @media (max-width: 1280px) {
            .kpi-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
        }
        @media (max-width: 1050px) {
            .block-container { padding: 1rem 1rem 2rem; }
            .kpi-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
            .page-header { align-items: flex-start; flex-direction: column; gap: 8px; }
            .architecture { grid-template-columns: 1fr; }
            .arch-arrow { min-height: 26px; transform: rotate(90deg); }
        }
        @media (max-width: 520px) {
            .kpi-grid { grid-template-columns: 1fr; }
            .page-title { font-size: 1.5rem; }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def fmt_number(value: object) -> str:
    return f"{float(value or 0):,.0f}"


def fmt_rate(value: object, suffix: str = "/s") -> str:
    return f"{float(value or 0):,.2f}{suffix}"


def fmt_latency(value: object) -> str:
    return f"{float(value or 0) * 1000:,.1f} ms"


def render_kpis(overview: dict[str, object]) -> None:
    metrics = [
        ("Generated", fmt_number(overview.get("generated_messages")), "Edge, current run", "info"),
        ("Accepted", fmt_number(overview.get("accepted_messages")), "Fog, stored total", "success"),
        (
            "Rejected",
            fmt_number(overview.get("rejected_messages")),
            "Validation failures",
            "warning" if float(overview.get("rejected_messages", 0) or 0) else "neutral",
        ),
        ("Message rate", fmt_rate(overview.get("messages_per_second")), "Last 60 seconds", "info"),
        ("Data rate", fmt_rate(overview.get("bytes_per_second"), " B/s"), "Accepted payload", "info"),
        ("Average latency", fmt_latency(overview.get("average_latency")), "End-to-end", "neutral"),
        ("P95 latency", fmt_latency(overview.get("p95_latency")), "End-to-end", "neutral"),
        ("Queue depth", fmt_number(overview.get("current_queue_size")), "Buffered messages", "neutral"),
        (
            "Queue utilization",
            f"{float(overview.get('queue_utilization', 0)):.1%}",
            "Diode capacity",
            "warning" if float(overview.get("queue_utilization", 0) or 0) >= 0.75 else "success",
        ),
        ("Active Edge nodes", f"{int(overview.get('active_edge_nodes', 0))}/5", "Device health", "success"),
        (
            "Critical alerts",
            fmt_number(overview.get("critical_alerts")),
            "Unacknowledged",
            "danger" if float(overview.get("critical_alerts", 0) or 0) else "success",
        ),
        ("Filtered", f"{float(overview.get('filtering_percentage', 0)):.1f}%", "Bandwidth reduction", "success"),
    ]
    cards = "".join(
        f'<div class="kpi-card {tone}"><div class="kpi-label">{html.escape(label)}</div>'
        f'<div class="kpi-value">{html.escape(value)}</div>'
        f'<div class="kpi-context">{html.escape(context)}</div></div>'
        for label, value, context, tone in metrics
    )
    st.markdown(f'<div class="kpi-grid">{cards}</div>', unsafe_allow_html=True)


def health_badge(status: str) -> str:
    value = (status or "UNKNOWN").upper()
    style = value.lower() if value in {"HEALTHY", "ACTIVE", "CONNECTED", "STALE", "UNKNOWN", "UNAVAILABLE"} else "unknown"
    return f'<span class="health {style}">{html.escape(value)}</span>'


def render_architecture(architecture: dict[str, object]) -> None:
    edge_nodes = architecture.get("edge_devices", [])
    edge_html = "".join(
        f'<div class="arch-node"><span>{html.escape(str(node.get("device_id", "Edge")))}</span>'
        f'{health_badge(str(node.get("health", "UNKNOWN")))}</div>'
        for node in edge_nodes
    ) or '<div class="arch-node"><span>No Edge activity</span>' + health_badge("UNKNOWN") + "</div>"
    gateway = architecture.get("gateway", {})
    diode = architecture.get("data_diode", {})
    fog_services = architecture.get("fog_services", [])
    fog_html = "".join(
        f'<div class="arch-node fog"><span>{html.escape(str(item.get("service")))}</span>'
        f'{health_badge(str(item.get("status")))}</div>'
        for item in fog_services
    )
    st.markdown(
        f"""
        <div class="architecture">
          <div class="arch-zone">
            <div class="arch-zone-title">EDGE NETWORK<div class="arch-zone-subtitle">Five isolated telemetry sources</div></div>
            {edge_html}
          </div>
          <div class="arch-arrow">&#8594;</div>
          <div class="arch-zone"><div class="arch-zone-title">EDGE GATEWAY<div class="arch-zone-subtitle">Preprocessing boundary</div></div>
            <div class="arch-node"><span>Signing & filtering</span>{health_badge(str(gateway.get('status', 'UNKNOWN')))}</div>
            <div class="arch-detail">Concurrent ingress<br>Sequence tracking<br>Local priority assignment</div>
          </div>
          <div class="arch-arrow">&#8594;</div>
          <div class="arch-zone"><div class="arch-zone-title">DATA DIODE<div class="arch-zone-subtitle">One-way transport</div></div>
            <div class="arch-node transport"><span>Adaptive transport</span>{health_badge(str(diode.get('status', 'UNKNOWN')))}</div>
            <div class="arch-node transport"><span>Logical boundary</span><span class="health">CONFIGURED</span></div>
            <div class="arch-detail">Bounded priority queue<br>Congestion control<br>No reverse route</div>
          </div>
          <div class="arch-arrow">&#8594;</div>
          <div class="arch-zone">
            <div class="arch-zone-title">FOG NETWORK<div class="arch-zone-subtitle">Analytics and persistence</div></div>
            {fog_html}
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_edge_inspector(architecture: dict[str, object]) -> None:
    edge_nodes = architecture.get("edge_devices", [])
    if not edge_nodes:
        return

    node_by_id = {str(node.get("device_id", "Edge")): node for node in edge_nodes}
    with st.expander("Inspect Edge node", icon=":material/memory:"):
        selected_id = st.selectbox(
            "Device",
            options=list(node_by_id),
            key="edge_device_inspector",
        )
        node = node_by_id[selected_id]
        last_seen = node.get("last_seen")
        if last_seen:
            last_seen_text = datetime.fromisoformat(str(last_seen)).strftime("%H:%M:%S UTC")
        else:
            last_seen_text = "Never"

        columns = st.columns(6)
        device_metrics = [
            ("Health", str(node.get("health", "UNKNOWN"))),
            ("Message rate", f"{float(node.get('message_rate_per_minute', 0) or 0):,.1f}/min"),
            ("Last sequence", fmt_number(node.get("last_sequence_number"))),
            ("Forwarded", fmt_number(node.get("forwarded_count"))),
            ("Filtered", fmt_number(node.get("filtered_count"))),
            ("Recent activity", fmt_number(node.get("recent_activity_count"))),
        ]
        for column, (label, value) in zip(columns, device_metrics):
            column.metric(label, value)
        st.caption(f"Last activity: {last_seen_text}")

        priority_stats = node.get("priority_statistics", {})
        filtering_stats = node.get("filtering_statistics", {})
        priority_col, filtering_col = st.columns(2)
        with priority_col:
            st.markdown("#### Priority distribution")
            if priority_stats:
                priority_rows = pd.DataFrame(
                    [{"priority": key, "messages": value} for key, value in priority_stats.items()]
                )
                chart = px.bar(
                    priority_rows,
                    x="priority",
                    y="messages",
                    color="priority",
                    color_discrete_map=PRIORITY_COLORS,
                    labels={"priority": "", "messages": "Messages"},
                )
                st.plotly_chart(style_chart(chart, height=245), width="stretch")
            else:
                st.info("No priority activity recorded.")
        with filtering_col:
            st.markdown("#### Filtering outcomes")
            if filtering_stats:
                filter_rows = pd.DataFrame(
                    [{"reason": key, "messages": value} for key, value in filtering_stats.items()]
                )
                chart = px.bar(
                    filter_rows,
                    x="messages",
                    y="reason",
                    orientation="h",
                    color_discrete_sequence=["#ffb020"],
                    labels={"reason": "", "messages": "Messages"},
                )
                st.plotly_chart(style_chart(chart, height=245), width="stretch")
            else:
                st.success("No messages filtered for this device.")


def render_scheduler(scheduler: dict[str, object]) -> None:
    policy = scheduler.get("information_policy")
    if policy:
        st.subheader("Information preservation")
        local = policy.get("local_state", {})
        state_col, queue_col, forecast_col = st.columns(3)
        state_col.metric("Predicted congestion", local.get("congestion_state", "UNKNOWN"))
        queue_col.metric("Edge policy queue", local.get("queue_length", 0))
        forecast_col.metric("Forecast queue", f"{local.get('predicted_queue_length', 0):.1f}")
        decision_rows = pd.DataFrame(policy.get("recent_decisions", []))
        if not decision_rows.empty:
            selected_actions = st.multiselect(
                "Policy actions", ["SEND", "DELAY", "AGGREGATE", "SAMPLE", "SUPERSEDE", "DROP"],
                default=["SEND", "DELAY", "AGGREGATE", "SAMPLE", "SUPERSEDE", "DROP"],
                key="information_policy_actions",
            )
            visible = decision_rows[decision_rows["action"].isin(selected_actions)]
            st.dataframe(
                visible[["message_id", "device_id", "action", "utility_score", "utility_density", "congestion_state", "reason"]],
                hide_index=True, width="stretch",
            )
            with st.expander("Utility components"):
                st.json(policy["recent_decisions"][-1])
    rows = pd.DataFrame(scheduler.get("by_priority", []))
    selected_priorities = list(PRIORITY_COLORS)
    if not rows.empty:
        available_priorities = rows["priority"].dropna().astype(str).tolist()
        selected_priorities = st.multiselect(
            "Priorities",
            options=available_priorities,
            default=available_priorities,
            key="scheduler_priority_filter",
        )
        rows = rows[rows["priority"].isin(selected_priorities)]

    left, right = st.columns([1.35, 1])
    with left:
        st.subheader("Priority throughput")
        if not rows.empty:
            chart = px.bar(
                rows,
                x="priority",
                y="throughput",
                color="priority",
                color_discrete_map=PRIORITY_COLORS,
                labels={"throughput": "Messages / second", "priority": ""},
            )
            st.plotly_chart(style_chart(chart), width="stretch")
        else:
            st.info("Waiting for scheduler data.")
    with right:
        st.subheader("Queue state")
        queue = scheduler.get("queue", {})
        c1, c2 = st.columns(2)
        c1.metric("Congestion", scheduler.get("congestion_state", "UNKNOWN"))
        c2.metric("Scheduler", str(scheduler.get("mode", "unknown")).upper())
        st.metric(
            "Incoming / outgoing",
            f"{float(queue.get('incoming_rate', 0) or 0):.2f} / "
            f"{float(queue.get('outgoing_rate', 0) or 0):.2f} msg/s",
        )

    latency_col, score_col = st.columns(2)
    with latency_col:
        st.subheader("Latency by priority")
        if not rows.empty:
            melted = rows.melt(
                id_vars="priority",
                value_vars=["average_latency", "average_queue_wait", "p95_latency"],
                var_name="measurement",
                value_name="seconds",
            ).dropna()
            chart = px.bar(
                melted,
                x="priority",
                y="seconds",
                color="measurement",
                barmode="group",
                labels={"seconds": "Seconds", "priority": ""},
                color_discrete_sequence=["#38bdf8", "#f59e0b", "#22c55e"],
            )
            st.plotly_chart(style_chart(chart), width="stretch")
    with score_col:
        st.subheader("Scheduler score distribution")
        score_rows = [
            {"priority": priority, "score": score}
            for priority, scores in scheduler.get("score_distribution", {}).items()
            if priority in selected_priorities
            for score in scores
        ]
        if score_rows:
            chart = px.histogram(
                pd.DataFrame(score_rows),
                x="score",
                color="priority",
                barmode="overlay",
                color_discrete_map=PRIORITY_COLORS,
            )
            st.plotly_chart(style_chart(chart), width="stretch")
        else:
            st.info("Scores appear after scheduled messages are delivered.")

    if not rows.empty:
        table = rows[["priority", "delivered", "dropped", "average_queue_wait", "p95_latency"]].copy()
        table.columns = ["Priority", "Delivered", "Dropped", "Avg queue wait", "P95 latency"]
        st.dataframe(
            table,
            width="stretch",
            hide_index=True,
            column_config={
                "Avg queue wait": st.column_config.NumberColumn(format="%.3f s"),
                "P95 latency": st.column_config.NumberColumn(format="%.3f s"),
            },
        )


def render_security(security: dict[str, object]) -> None:
    counts = security.get("counts", {})
    labels = [
        ("Invalid signatures", "invalid_signatures"),
        ("Hash mismatches", "hash_mismatches"),
        ("Replay attempts", "replay_attempts"),
        ("Duplicates", "duplicates"),
        ("Malformed", "malformed_messages"),
        ("Rate limited", "rate_limit_violations"),
    ]
    columns = st.columns(6)
    for column, (label, key) in zip(columns, labels):
        column.metric(label, int(counts.get(key, 0)))

    st.subheader("Audit integrity")
    audit_rows = pd.DataFrame(security.get("audit_logs", []))
    if not audit_rows.empty:
        audit_rows["state"] = (
            audit_rows["valid"].map({True: "VALID", False: "FAILED"}).fillna("CHECKING")
        )
        st.dataframe(
            audit_rows[["service", "state", "detail"]],
            width="stretch",
            hide_index=True,
        )


def render_analytics(analytics: dict[str, object]) -> None:
    severity_order = ["CRITICAL", "HIGH", "WARNING", "INFO"]
    selected_severities = st.multiselect(
        "Severity",
        options=severity_order,
        default=severity_order,
        key="analytics_severity_filter",
    )

    timeline_col, severity_col = st.columns([1.6, 1])
    timeline = pd.DataFrame(analytics.get("anomaly_timeline", []))
    if not timeline.empty:
        timeline = timeline[timeline["severity"].isin(selected_severities)]
    with timeline_col:
        st.subheader("Anomaly timeline")
        if not timeline.empty:
            timeline["timestamp"] = pd.to_datetime(timeline["timestamp"])
            chart = px.area(
                timeline,
                x="timestamp",
                y="count",
                color="severity",
                color_discrete_map=SEVERITY_COLORS,
            )
            st.plotly_chart(style_chart(chart), width="stretch")
        else:
            st.info("No anomalies in the selected time window.")
    with severity_col:
        st.subheader("Alert severity")
        alerts = pd.DataFrame(analytics.get("alerts", []))
        if not alerts.empty:
            alerts = alerts[alerts["severity"].isin(selected_severities)]
        if not alerts.empty:
            severity = alerts.groupby("severity").size().reset_index(name="count")
            chart = px.pie(
                severity,
                names="severity",
                values="count",
                hole=0.58,
                color="severity",
                color_discrete_map=SEVERITY_COLORS,
            )
            st.plotly_chart(style_chart(chart), width="stretch")
        else:
            st.info("No alerts recorded.")

    st.subheader("Telemetry trends")
    trends = pd.DataFrame(analytics.get("telemetry_trends", []))
    if not trends.empty:
        trends["timestamp"] = pd.to_datetime(trends["timestamp"])
        chart = px.line(
            trends,
            x="timestamp",
            y="messages",
            color="telemetry_type",
            markers=True,
            labels={"messages": "Accepted messages", "telemetry_type": "Telemetry"},
            color_discrete_sequence=["#38bdf8", "#22c55e", "#f59e0b", "#ef4444", "#a78bfa"],
        )
        st.plotly_chart(style_chart(chart), width="stretch")

    anomaly_col, alert_col = st.columns(2)
    with anomaly_col:
        st.subheader("Latest anomalies")
        anomalies = pd.DataFrame(analytics.get("latest_anomalies", []))
        if not anomalies.empty:
            anomalies = anomalies[anomalies["severity"].isin(selected_severities)]
        if not anomalies.empty:
            anomalies["timestamp"] = pd.to_datetime(anomalies["timestamp"], utc=True)
            st.dataframe(
                anomalies[["timestamp", "device_id", "detector", "metric", "observed_value", "severity"]],
                width="stretch",
                hide_index=True,
                column_config={
                    "timestamp": st.column_config.DatetimeColumn("Time", format="HH:mm:ss"),
                    "observed_value": st.column_config.NumberColumn("Observed", format="%.2f"),
                },
            )
        else:
            st.info("No anomalies recorded.")
    with alert_col:
        st.subheader("Active alerts")
        active = pd.DataFrame(analytics.get("active_alerts", []))
        if not active.empty:
            active = active[active["severity"].isin(selected_severities)]
        if not active.empty:
            active["timestamp"] = pd.to_datetime(active["timestamp"], utc=True)
            st.dataframe(
                active[["timestamp", "alert_type", "severity", "source_devices"]],
                width="stretch",
                hide_index=True,
                column_config={
                    "timestamp": st.column_config.DatetimeColumn("Time", format="HH:mm:ss"),
                    "source_devices": st.column_config.ListColumn("Sources"),
                },
            )
        else:
            st.success("No active alerts.")


def style_chart(figure: go.Figure, height: int = 330) -> go.Figure:
    figure.update_layout(
        height=height,
        margin=dict(l=8, r=8, t=18, b=8),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#c7d3dc", size=12),
        legend_title_text="",
        hoverlabel=dict(bgcolor="#18212a", bordercolor="#435669", font_color="#f3f7fa"),
        hovermode="x unified",
        transition_duration=0,
        xaxis=dict(gridcolor="#283642", zerolinecolor="#31404e"),
        yaxis=dict(gridcolor="#283642", zerolinecolor="#31404e"),
    )
    return figure


inject_styles()

with st.sidebar:
    st.markdown(
        """
        <div class="product-mark">
          <div class="product-name">Diode Observatory</div>
          <div class="product-scope">Fog control plane</div>
        </div>
        <div class="sidebar-status">
          <span class="live-dot"></span><span><strong>Live monitoring</strong><br>Fog-side data only</span>
        </div>
        """,
        unsafe_allow_html=True,
    )
    auto_refresh = st.toggle(
        "Auto refresh",
        value=True,
        key="auto_refresh_enabled",
    )
    refresh_options = sorted({3, 5, 10, 30, REFRESH_SECONDS})
    refresh_seconds = st.segmented_control(
        "Auto-refresh cadence",
        options=refresh_options,
        default=REFRESH_SECONDS,
        format_func=lambda value: f"{value}s",
        selection_mode="single",
        disabled=not auto_refresh,
        key="refresh_interval_seconds",
    )
    refresh_seconds = int(refresh_seconds or REFRESH_SECONDS)
    if st.button("Refresh now", icon=":material/refresh:", width="stretch"):
        st.rerun()
    with st.expander("Connection", icon=":material/hub:"):
        st.caption("Monitoring API")
        st.code(MONITORING_API_URL.removeprefix("http://"), language=None)
        st.caption("Network scope")
        st.write("Fog network")


@st.fragment(run_every=refresh_seconds if auto_refresh else None)
def live_dashboard() -> None:
    stale = False
    try:
        snapshot = load_snapshot()
        st.session_state["last_good_snapshot"] = snapshot
    except (requests.RequestException, ValueError) as exc:
        snapshot = st.session_state.get("last_good_snapshot")
        st.warning("Fog monitoring is unavailable. Showing the last received snapshot." if snapshot else
                   "Fog monitoring data is temporarily unavailable.")
        if snapshot is None:
            return
        stale = True

    observed = snapshot.get("observed_at")
    observed_text = (
        datetime.fromisoformat(str(observed).replace("Z", "+00:00")).strftime("%H:%M:%S UTC")
        if observed
        else "unknown"
    )
    refresh_status = f"Every {refresh_seconds}s" if auto_refresh else "Paused"
    title_col, action_col = st.columns([5, 1], vertical_alignment="bottom")
    with title_col:
        st.markdown(
            f"""
            <div class="page-header">
              <div>
                <div class="page-eyebrow">Fog observability</div>
                <div class="page-title">Data Diode Observatory</div>
              </div>
              <div class="status-strip">
                <span class="live-dot" style="background: {'var(--amber)' if stale else 'var(--green)'}"></span><span>{'Stale' if stale else 'Live'}</span>
                <span class="status-divider">|</span><span>{refresh_status}</span>
                <span class="status-divider">|</span><span>Updated {html.escape(observed_text)}</span>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with action_col:
        st.download_button(
            "Snapshot",
            data=json.dumps(snapshot, indent=2, default=str),
            file_name="data-diode-snapshot.json",
            mime="application/json",
            icon=":material/download:",
            width="stretch",
        )
    render_kpis(snapshot.get("overview", {}))

    selected_view = st.segmented_control(
        "Dashboard view",
        options=["Architecture", "Scheduler", "Security", "Fog analytics"],
        default="Architecture",
        selection_mode="single",
        label_visibility="collapsed",
        key="dashboard_view",
    ) or "Architecture"
    if selected_view == "Architecture":
        st.subheader("Trust-zone architecture")
        render_architecture(snapshot.get("architecture", {}))
        render_edge_inspector(snapshot.get("architecture", {}))
    elif selected_view == "Scheduler":
        render_scheduler(snapshot.get("scheduler", {}))
    elif selected_view == "Security":
        render_security(snapshot.get("security", {}))
    elif selected_view == "Fog analytics":
        render_analytics(snapshot.get("analytics", {}))


live_dashboard()
