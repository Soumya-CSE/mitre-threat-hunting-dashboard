import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

import db
from mitre_data import TECHNIQUES, TACTICS, TACTIC_COLORS, get_technique

# --------------------------------------------------------------------------
# Page config + global styling
# --------------------------------------------------------------------------
st.set_page_config(
    page_title="MITRE ATT&CK Threat Hunting Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

CUSTOM_CSS = """
<style>
    #MainMenu, footer, header {visibility: hidden;}
    .stApp {
        background: radial-gradient(circle at top left, #0d1420 0%, #090d14 55%, #05070b 100%);
        color: #d7e2ea;
    }
    section[data-testid="stSidebar"] {
        background: #0a0f18;
        border-right: 1px solid #1c2836;
    }
    section[data-testid="stSidebar"] * { color: #c7d3de !important; }

    h1, h2, h3, h4 { color: #eaf2f8 !important; font-family: 'Segoe UI', sans-serif; }

    .soc-badge {
        display:inline-block; padding:2px 10px; border-radius:20px;
        font-size:0.72rem; font-weight:700; letter-spacing:.4px;
    }
    .sev-Critical { background:#3b0d10; color:#ff6b6b; border:1px solid #ff6b6b55;}
    .sev-High     { background:#3a1c05; color:#ff9f43; border:1px solid #ff9f4355;}
    .sev-Medium   { background:#3a3305; color:#ffd93d; border:1px solid #ffd93d55;}
    .sev-Low      { background:#062b1a; color:#4ade80; border:1px solid #4ade8055;}

    .status-New           { background:#0d2038; color:#5db8ff; border:1px solid #5db8ff55;}
    .status-Investigating { background:#301c40; color:#c084fc; border:1px solid #c084fc55;}
    .status-Escalated     { background:#3b0d10; color:#ff6b6b; border:1px solid #ff6b6b55;}
    .status-Resolved      { background:#062b1a; color:#4ade80; border:1px solid #4ade8055;}
    .status-False.Positive, .status-False-Positive { background:#1c1c1c; color:#9ca3af; border:1px solid #9ca3af55;}

    .metric-card {
        background: linear-gradient(145deg, #0f1826, #0a121c);
        border: 1px solid #1e2c3d;
        border-radius: 14px;
        padding: 18px 20px;
        text-align:left;
    }
    .metric-card .label { font-size:0.78rem; color:#7d92a8; text-transform:uppercase; letter-spacing:.6px;}
    .metric-card .value { font-size:2.0rem; font-weight:700; color:#f2f7fb; margin-top:2px;}

    .pipeline-card {
        background: linear-gradient(145deg, #101b29, #0b131e);
        border: 1px solid #223146;
        border-left: 4px solid #2f6fed;
        border-radius: 10px;
        padding: 14px 18px;
        margin-bottom: 6px;
    }
    .pipeline-card .stage-label { font-size:0.7rem; color:#5f9cf0; text-transform:uppercase; font-weight:700; letter-spacing:1px;}
    .pipeline-card .stage-value { font-size:1.05rem; color:#eef4fa; font-weight:600; margin-top:2px;}
    .pipeline-card .stage-sub { font-size:0.85rem; color:#93a5b8; margin-top:4px;}
    .pipeline-arrow { text-align:center; color:#3a4c60; font-size:1.3rem; margin: -2px 0 -2px 0;}

    .alert-row {
        background:#0d1520; border:1px solid #1c2836; border-radius:10px;
        padding:12px 16px; margin-bottom:8px;
    }
    .code-box {
        background:#050a10; border:1px solid #1c2836; border-radius:8px;
        padding:10px 14px; font-family:'Courier New', monospace; font-size:0.85rem;
        color:#8ee6b8; overflow-x:auto; white-space:pre-wrap; word-break:break-all;
    }
    .step-item {
        background:#0d1520; border:1px solid #1c2836; border-left:3px solid #2f6fed;
        border-radius:6px; padding:10px 14px; margin-bottom:6px; font-size:0.92rem;
    }
    .matrix-cell {
        border-radius:8px; padding:10px; margin-bottom:8px; font-size:0.78rem;
        color:#fff; min-height:56px;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

db.init_db()

if "selected_alert_id" not in st.session_state:
    st.session_state.selected_alert_id = None
if "page" not in st.session_state:
    st.session_state.page = "Dashboard"


def badge(text, css_class):
    return f'<span class="soc-badge {css_class}">{text}</span>'


def status_class(status):
    return "status-" + status.replace(" ", "-")


# --------------------------------------------------------------------------
# Sidebar navigation
# --------------------------------------------------------------------------
st.sidebar.markdown("## 🛡️ ThreatHunt SOC")
st.sidebar.caption("MITRE ATT&CK Threat Hunting Dashboard")
st.sidebar.markdown("---")

page = st.sidebar.radio(
    "Navigate",
    ["🏠 Dashboard", "📋 Alert Queue", "🔍 Investigation", "🗺️ ATT&CK Matrix", "📈 Timeline"],
    label_visibility="collapsed",
)
st.sidebar.markdown("---")

df_all = db.get_all_alerts_df()
open_count = len(df_all[~df_all["status"].isin(["Resolved", "False Positive"])])
critical_open = len(df_all[(df_all["severity"] == "Critical") & (~df_all["status"].isin(["Resolved", "False Positive"]))])

st.sidebar.markdown(f"**Open alerts:** {open_count}")
st.sidebar.markdown(f"**Critical (open):** :red[{critical_open}]")
if st.sidebar.button("🔄 Reset sample data"):
    db.reset_db()
    st.session_state.selected_alert_id = None
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.caption("Built for SOC / Blue Team portfolio use · Streamlit + Python")

# --------------------------------------------------------------------------
# DASHBOARD
# --------------------------------------------------------------------------
if page == "🏠 Dashboard":
    st.title("Threat Hunting Overview")
    st.caption("Live posture across all ingested alerts, mapped to MITRE ATT&CK.")

    df = df_all.copy()
    df["tactic"] = df["technique_id"].map(lambda t: TECHNIQUES.get(t, {}).get("tactic", "Unknown"))
    df["technique_name"] = df["technique_id"].map(lambda t: TECHNIQUES.get(t, {}).get("name", t))

    c1, c2, c3, c4, c5 = st.columns(5)
    for col, label, value in zip(
        [c1, c2, c3, c4, c5],
        ["Total Alerts", "Open", "Critical (Open)", "Hosts Affected", "Techniques Seen"],
        [len(df), open_count, critical_open, df["host"].nunique(), df["technique_id"].nunique()],
    ):
        col.markdown(
            f'<div class="metric-card"><div class="label">{label}</div>'
            f'<div class="value">{value}</div></div>',
            unsafe_allow_html=True,
        )

    st.markdown("<br>", unsafe_allow_html=True)
    colA, colB = st.columns([1.1, 1])

    with colA:
        st.subheader("Alerts by Tactic")
        tactic_counts = df["tactic"].value_counts().reindex(TACTICS).fillna(0).reset_index()
        tactic_counts.columns = ["tactic", "count"]
        fig = px.bar(
            tactic_counts, x="count", y="tactic", orientation="h",
            color="tactic", color_discrete_map=TACTIC_COLORS,
        )
        fig.update_layout(
            showlegend=False, height=420, margin=dict(l=10, r=10, t=10, b=10),
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            font_color="#c7d3de", yaxis=dict(categoryorder="total ascending"),
        )
        st.plotly_chart(fig, width='stretch')

    with colB:
        st.subheader("Severity Breakdown")
        sev_order = ["Critical", "High", "Medium", "Low"]
        sev_counts = df["severity"].value_counts().reindex(sev_order).fillna(0).reset_index()
        sev_counts.columns = ["severity", "count"]
        sev_colors = {"Critical": "#ef4444", "High": "#f97316", "Medium": "#eab308", "Low": "#22c55e"}
        fig2 = px.pie(
            sev_counts, names="severity", values="count", hole=0.55,
            color="severity", color_discrete_map=sev_colors,
        )
        fig2.update_layout(
            height=420, margin=dict(l=10, r=10, t=10, b=10),
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            font_color="#c7d3de", legend=dict(orientation="h", y=-0.1),
        )
        st.plotly_chart(fig2, width='stretch')

    st.subheader("Top Techniques Observed")
    top_tech = df["technique_name"].value_counts().head(8).reset_index()
    top_tech.columns = ["technique", "count"]
    fig3 = px.bar(top_tech, x="count", y="technique", orientation="h")
    fig3.update_traces(marker_color="#2f6fed")
    fig3.update_layout(
        height=350, margin=dict(l=10, r=10, t=10, b=10),
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        font_color="#c7d3de", yaxis=dict(categoryorder="total ascending"),
    )
    st.plotly_chart(fig3, width='stretch')

    st.subheader("Most Recent Alerts")
    recent = df.head(6)
    for _, r in recent.iterrows():
        cols = st.columns([2.2, 3, 1.4, 1.2, 1.2, 1])
        cols[0].write(f"**{r['id']}**  \n{r['timestamp']}")
        cols[1].write(f"{r['alert_name']}")
        cols[2].write(f"`{r['technique_id']}`")
        cols[3].markdown(badge(r["severity"], f"sev-{r['severity']}"), unsafe_allow_html=True)
        cols[4].markdown(badge(r["status"], status_class(r["status"])), unsafe_allow_html=True)
        if cols[5].button("Open ▶", key=f"open_{r['id']}"):
            st.session_state.selected_alert_id = r["id"]
            st.session_state.page = "🔍 Investigation"
            st.rerun()

# --------------------------------------------------------------------------
# ALERT QUEUE
# --------------------------------------------------------------------------
elif page == "📋 Alert Queue":
    st.title("Alert Queue")
    st.caption("Triage incoming alerts, filter by priority, and jump into investigation.")

    df = df_all.copy()
    f1, f2, f3, f4 = st.columns(4)
    sev_filter = f1.multiselect("Severity", ["Critical", "High", "Medium", "Low"], default=[])
    status_filter = f2.multiselect("Status", ["New", "Investigating", "Escalated", "Resolved", "False Positive"], default=[])
    host_filter = f3.multiselect("Host", sorted(df["host"].unique()), default=[])
    search = f4.text_input("Search alert name / IOC")

    if sev_filter:
        df = df[df["severity"].isin(sev_filter)]
    if status_filter:
        df = df[df["status"].isin(status_filter)]
    if host_filter:
        df = df[df["host"].isin(host_filter)]
    if search:
        s = search.lower()
        df = df[df["alert_name"].str.lower().str.contains(s) | df["ioc_value"].str.lower().str.contains(s)]

    st.caption(f"Showing {len(df)} of {len(df_all)} alerts")

    for _, r in df.iterrows():
        with st.container():
            st.markdown('<div class="alert-row">', unsafe_allow_html=True)
            cols = st.columns([1.3, 2.6, 1.3, 1.4, 1.1, 1.1, 1])
            cols[0].markdown(f"**{r['id']}**  \n<span style='color:#7d92a8;font-size:0.8rem'>{r['timestamp']}</span>", unsafe_allow_html=True)
            cols[1].markdown(f"**{r['alert_name']}**  \n<span style='color:#7d92a8;font-size:0.8rem'>{r['host']} · {r['user']}</span>", unsafe_allow_html=True)
            tname = TECHNIQUES.get(r["technique_id"], {}).get("name", "")
            cols[2].markdown(f"`{r['technique_id']}`  \n<span style='color:#7d92a8;font-size:0.78rem'>{tname[:22]}</span>", unsafe_allow_html=True)
            cols[3].markdown(f"<span style='color:#7d92a8;font-size:0.8rem'>{r['ioc_type']}</span>  \n{r['ioc_value'][:28]}", unsafe_allow_html=True)
            cols[4].markdown(badge(r["severity"], f"sev-{r['severity']}"), unsafe_allow_html=True)
            cols[5].markdown(badge(r["status"], status_class(r["status"])), unsafe_allow_html=True)
            if cols[6].button("Investigate", key=f"inv_{r['id']}"):
                st.session_state.selected_alert_id = r["id"]
                st.session_state.page = "🔍 Investigation"
                st.rerun()
            st.markdown("</div>", unsafe_allow_html=True)

# --------------------------------------------------------------------------
# INVESTIGATION (the core pipeline view)
# --------------------------------------------------------------------------
elif page == "🔍 Investigation":
    st.title("Alert Investigation")

    ids = df_all["id"].tolist()
    default_idx = ids.index(st.session_state.selected_alert_id) if st.session_state.selected_alert_id in ids else 0
    chosen = st.selectbox("Select an alert to investigate", ids, index=default_idx if ids else 0,
                           format_func=lambda i: f"{i} — {db.get_alert(i)['alert_name']}")
    st.session_state.selected_alert_id = chosen

    alert = db.get_alert(chosen)
    if not alert:
        st.warning("No alert selected.")
        st.stop()

    tech = get_technique(alert["technique_id"]) or {}
    tactic = tech.get("tactic", "Unknown")
    tactic_color = TACTIC_COLORS.get(tactic, "#2f6fed")

    sev_badge = badge(alert["severity"], f"sev-{alert['severity']}")
    status_badge = badge(alert["status"], status_class(alert["status"]))
    st.markdown(
        f"### {alert['alert_name']} {sev_badge} {status_badge}",
        unsafe_allow_html=True,
    )
    st.caption(f"Alert ID: {alert['id']}  ·  Detected: {alert['timestamp']} UTC")

    st.markdown("#### 🔗 Investigation Pipeline")
    st.caption("Alert → IOC → Technique → MITRE ATT&CK → Affected Host → Timeline → Recommended Investigation")

    def stage(label, value, sub=""):
        st.markdown(
            f'<div class="pipeline-card"><div class="stage-label">{label}</div>'
            f'<div class="stage-value">{value}</div>'
            f'{f"<div class=stage-sub>{sub}</div>" if sub else ""}</div>',
            unsafe_allow_html=True,
        )
        st.markdown('<div class="pipeline-arrow">↓</div>', unsafe_allow_html=True)

    stage("① Alert", alert["alert_name"], alert["raw_log"])
    stage("② IOC (Indicator of Compromise)", f"{alert['ioc_type'].upper()}: {alert['ioc_value']}")
    stage("③ Technique", f"{alert['technique_id']} — {tech.get('name','Unknown')}")
    st.markdown(
        f'<div class="pipeline-card" style="border-left-color:{tactic_color}">'
        f'<div class="stage-label">④ MITRE ATT&CK Tactic</div>'
        f'<div class="stage-value">{tactic}</div>'
        f'<div class="stage-sub">{tech.get("description","")}</div></div>',
        unsafe_allow_html=True,
    )
    st.markdown('<div class="pipeline-arrow">↓</div>', unsafe_allow_html=True)
    stage("⑤ Affected Host", alert["host"], f"IP {alert['host_ip']} · User: {alert['user']}")

    related = db.get_alerts_for_host(alert["host"], exclude_id=alert["id"])
    stage("⑥ Timeline Context", f"{len(related)} other alert(s) on this host", "See full timeline below")

    st.markdown(
        f'<div class="pipeline-card" style="border-left-color:#22c55e">'
        f'<div class="stage-label">⑦ Recommended Investigation</div>'
        f'<div class="stage-value">See checklist below</div></div>',
        unsafe_allow_html=True,
    )

    st.markdown("<br>", unsafe_allow_html=True)
    left, right = st.columns([1.3, 1])

    with left:
        st.markdown("#### 🕒 Related Activity on This Host")
        host_alerts = db.get_alerts_for_host(alert["host"]) + [alert]
        host_alerts = sorted(host_alerts, key=lambda a: a["timestamp"])
        if len(host_alerts) > 1:
            tdf = pd.DataFrame(host_alerts)
            tdf["technique_name"] = tdf["technique_id"].map(lambda t: TECHNIQUES.get(t, {}).get("name", t))
            tdf["ts"] = pd.to_datetime(tdf["timestamp"])
            tdf["end"] = tdf["ts"] + pd.Timedelta(minutes=20)
            fig = px.timeline(
                tdf, x_start="ts", x_end="end", y="host",
                color="severity", hover_data=["alert_name", "technique_id"],
                color_discrete_map={"Critical": "#ef4444", "High": "#f97316", "Medium": "#eab308", "Low": "#22c55e"},
            )
            fig.update_yaxes(visible=False)
            fig.update_layout(
                height=180, margin=dict(l=10, r=10, t=10, b=10),
                plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                font_color="#c7d3de", showlegend=True,
            )
            st.plotly_chart(fig, width='stretch')
            for ha in host_alerts:
                mark = "👉 " if ha["id"] == alert["id"] else "・ "
                ha_badge = badge(ha["severity"], f"sev-{ha['severity']}")
                st.markdown(
                    f"{mark}**{ha['timestamp']}** — {ha['alert_name']} "
                    f"(`{ha['technique_id']}`) {ha_badge}",
                    unsafe_allow_html=True,
                )
        else:
            st.info("No other alerts observed on this host in the current window — isolated event.")

        st.markdown("#### 📜 Raw Log / Command Line")
        st.markdown(f'<div class="code-box">{alert["raw_log"]}</div>', unsafe_allow_html=True)

    with right:
        st.markdown("#### ✅ Recommended Investigation Steps")
        for i, step in enumerate(tech.get("investigation_steps", []), 1):
            st.markdown(f'<div class="step-item">{i}. {step}</div>', unsafe_allow_html=True)

        with st.expander("🛡️ Detection & Mitigation Guidance"):
            st.markdown(f"**Detection:** {tech.get('detection','—')}")
            st.markdown(f"**Mitigation:** {tech.get('mitigation','—')}")

    st.markdown("---")
    st.markdown("#### 📝 Analyst Workbench")
    c1, c2 = st.columns([1, 2])
    with c1:
        new_status = st.selectbox(
            "Update status",
            ["New", "Investigating", "Escalated", "Resolved", "False Positive"],
            index=["New", "Investigating", "Escalated", "Resolved", "False Positive"].index(alert["status"]),
        )
        if st.button("💾 Save status"):
            db.update_alert(alert["id"], status=new_status)
            st.success("Status updated.")
            st.rerun()
    with c2:
        notes = st.text_area("Analyst notes", value=alert.get("analyst_notes") or "", height=120,
                              placeholder="Document findings, false-positive rationale, escalation details...")
        if st.button("💾 Save notes"):
            db.update_alert(alert["id"], analyst_notes=notes)
            st.success("Notes saved.")

# --------------------------------------------------------------------------
# ATT&CK MATRIX
# --------------------------------------------------------------------------
elif page == "🗺️ ATT&CK Matrix":
    st.title("MITRE ATT&CK Matrix Coverage")
    st.caption("Techniques observed in your environment, grouped by tactic. Click a technique below for full detail.")

    df = df_all.copy()
    counts = df["technique_id"].value_counts().to_dict()

    cols = st.columns(len(TACTICS))
    for col, tactic in zip(cols, TACTICS):
        with col:
            st.markdown(
                f"<div style='background:{TACTIC_COLORS[tactic]}22; border:1px solid {TACTIC_COLORS[tactic]}55; "
                f"border-radius:8px; padding:6px; text-align:center; font-size:0.72rem; font-weight:700; "
                f"color:{TACTIC_COLORS[tactic]}; margin-bottom:8px;'>{tactic}</div>",
                unsafe_allow_html=True,
            )
            techs = [tid for tid, meta in TECHNIQUES.items() if meta["tactic"] == tactic]
            for tid in techs:
                n = counts.get(tid, 0)
                opacity = "1" if n > 0 else "0.35"
                bg = TACTIC_COLORS[tactic] if n > 0 else "#1c2836"
                st.markdown(
                    f"<div class='matrix-cell' style='background:{bg}; opacity:{opacity};'>"
                    f"<b>{tid}</b><br>{TECHNIQUES[tid]['name'][:38]}"
                    f"{'...' if len(TECHNIQUES[tid]['name'])>38 else ''}"
                    f"<br><span style='opacity:.85'>{n} alert(s)</span></div>",
                    unsafe_allow_html=True,
                )

    st.markdown("---")
    st.subheader("Technique Detail Lookup")
    tid_sel = st.selectbox("Choose a technique", sorted(TECHNIQUES.keys()),
                            format_func=lambda t: f"{t} — {TECHNIQUES[t]['name']}")
    t = TECHNIQUES[tid_sel]
    st.markdown(f"**Tactic:** {t['tactic']}")
    st.markdown(f"**Description:** {t['description']}")
    st.markdown(f"**Detection:** {t['detection']}")
    st.markdown(f"**Mitigation:** {t['mitigation']}")
    st.markdown(f"**Alerts observed:** {counts.get(tid_sel, 0)}")
    st.markdown(f"[View on attack.mitre.org ↗](https://attack.mitre.org/techniques/{tid_sel.replace('.', '/')}/)")

# --------------------------------------------------------------------------
# TIMELINE
# --------------------------------------------------------------------------
elif page == "📈 Timeline":
    st.title("Global Alert Timeline")
    st.caption("Cross-host view for spotting coordinated / multi-stage attack activity.")

    df = df_all.copy()
    hosts_sel = st.multiselect("Filter by host", sorted(df["host"].unique()), default=[])
    if hosts_sel:
        df = df[df["host"].isin(hosts_sel)]

    if df.empty:
        st.info("No alerts match the current filter.")
    else:
        df["ts"] = pd.to_datetime(df["timestamp"])
        df["end"] = df["ts"] + pd.Timedelta(minutes=25)
        df["technique_name"] = df["technique_id"].map(lambda t: TECHNIQUES.get(t, {}).get("name", t))
        fig = px.timeline(
            df.sort_values("ts"), x_start="ts", x_end="end", y="host",
            color="severity", hover_data=["alert_name", "technique_id", "technique_name"],
            color_discrete_map={"Critical": "#ef4444", "High": "#f97316", "Medium": "#eab308", "Low": "#22c55e"},
        )
        fig.update_layout(
            height=max(420, 40 * df["host"].nunique()),
            margin=dict(l=10, r=10, t=10, b=10),
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            font_color="#c7d3de",
        )
        st.plotly_chart(fig, width='stretch')

        st.subheader("Alert Volume Over Time")
        vol = df.set_index("ts").resample("6h").size().reset_index(name="count")
        fig2 = go.Figure()
        fig2.add_trace(go.Scatter(x=vol["ts"], y=vol["count"], mode="lines+markers",
                                   line=dict(color="#2f6fed", width=2), fill="tozeroy",
                                   fillcolor="rgba(47,111,237,0.15)"))
        fig2.update_layout(
            height=280, margin=dict(l=10, r=10, t=10, b=10),
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            font_color="#c7d3de",
        )
        st.plotly_chart(fig2, width='stretch')
