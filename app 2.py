"""
OMNI-SCAN v2.0 - Streamlit Web Application
Advanced Internet Scanner & Exploitation Platform
"""

import streamlit as st
import asyncio
import json
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import time
import os

# Import custom modules
from database import Database
from scanners import OmniScanner
from exploits import ExploitEngine, ZombieManager
from utils import severity_color, format_timestamp

# Page configuration
st.set_page_config(
    page_title="OMNI-SCAN",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main { padding-top: 1rem; }
    .stTabs [data-baseweb="tab-list"] button { font-weight: bold; }
    h1 { color: #FF0000; text-align: center; }
    h2 { color: #FF6600; }
    .metric-card { 
        background: #1f1f1f; 
        padding: 1rem; 
        border-radius: 0.5rem;
        border-left: 4px solid #FF0000;
    }
    .vulnerability {
        background: #fff0f0;
        padding: 1rem;
        border-left: 4px solid #FF0000;
        border-radius: 0.3rem;
        margin: 0.5rem 0;
    }
    .success {
        background: #f0fff0;
        padding: 1rem;
        border-left: 4px solid #00AA00;
        border-radius: 0.3rem;
        margin: 0.5rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if "db" not in st.session_state:
    st.session_state.db = Database()

if "scanner" not in st.session_state:
    st.session_state.scanner = OmniScanner()

if "exploit_engine" not in st.session_state:
    st.session_state.exploit_engine = ExploitEngine()

if "zombie_manager" not in st.session_state:
    st.session_state.zombie_manager = ZombieManager()

if "scan_history" not in st.session_state:
    st.session_state.scan_history = []

# ==================== SIDEBAR ====================

with st.sidebar:
    st.image("https://via.placeholder.com/200x60/FF0000/FFFFFF?text=OMNI-SCAN", width=200)
    
    st.markdown("---")
    st.subheader("⚙️ Configuration")
    
    max_threads = st.slider("Max Concurrent Threads", 10, 500, 100)
    timeout = st.slider("Scan Timeout (seconds)", 1, 10, 3)
    
    st.markdown("---")
    
    # Database controls
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("📊 Stats", use_container_width=True):
            st.session_state.current_page = "stats"
    with col2:
        if st.button("🗑️ Clear", use_container_width=True):
            if st.checkbox("Confirm clear all data"):
                st.session_state.db.clear_all()
                st.success("Database cleared!")
    with col3:
        if st.button("📤 Export", use_container_width=True):
            st.session_state.current_page = "export"

# ==================== MAIN CONTENT ====================

st.title("🔥 OMNI-SCAN v2.0")
st.markdown("*Advanced Network Reconnaissance & Exploitation Platform*")
st.markdown("---")

# Tabs
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "🔎 Port Scanner",
    "🎯 Full Scan",
    "💉 Exploit Engine",
    "🧟 Zombie Network",
    "📊 Dashboard",
    "⚙️ Settings"
])

# ==================== TAB 1: PORT SCANNER ====================

with tab1:
    st.subheader("Quick Port Scanner")
    
    col1, col2 = st.columns(2)
    
    with col1:
        scan_type = st.selectbox(
            "Scan Type",
            ["Single IP", "IP Range", "Subnet"]
        )
        
        if scan_type == "Single IP":
            target_ip = st.text_input("Target IP", "8.8.8.8")
        elif scan_type == "IP Range":
            col_a, col_b = st.columns(2)
            with col_a:
                start_ip = st.text_input("Start IP", "8.8.8.0")
            with col_b:
                end_ip = st.text_input("End IP", "8.8.8.10")
            target_ip = f"{start_ip}-{end_ip}"
        else:
            target_ip = st.text_input("Subnet", "8.8.8.0/24")
    
    with col2:
        st.write("")
        ports_preset = st.selectbox(
            "Ports to Scan",
            ["Top 100", "Top 1000", "Common", "Custom"]
        )
        
        port_map = {
            "Top 100": [20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995],
            "Top 1000": None,  # All ports
            "Common": [21, 22, 80, 443, 3306, 5432, 6379, 27017],
            "Custom": []
        }
        
        if ports_preset == "Custom":
            custom_ports = st.text_input("Enter ports (comma-separated)")
            if custom_ports:
                port_map["Custom"] = [int(p.strip()) for p in custom_ports.split(",")]
        
        selected_ports = port_map[ports_preset]
    
    if st.button("▶️ Start Scan", use_container_width=True, key="port_scan"):
        with st.spinner("Scanning..."):
            try:
                start_time = time.time()
                
                if scan_type == "Single IP":
                    result = asyncio.run(st.session_state.scanner.full_scan(target_ip, selected_ports))
                    
                    # Display results
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("Target", target_ip)
                    with col2:
                        st.metric("Open Ports", len(result["ports"]))
                    with col3:
                        st.metric("Vulnerabilities", len(result["vulnerabilities"]))
                    with col4:
                        st.metric("Time", f"{time.time() - start_time:.2f}s")
                    
                    st.markdown("### 🔌 Open Ports")
                    if result["ports"]:
                        st.json(result["ports"])
                    else:
                        st.info("No open ports found")
                    
                    # Vulnerabilities
                    if result["vulnerabilities"]:
                        st.markdown("### ⚠️ Vulnerabilities")
                        for vuln in result["vulnerabilities"]:
                            severity = vuln.get("severity", "unknown").lower()
                            st.markdown(f"""
                            <div class='vulnerability'>
                            <strong>{vuln.get('cve', 'N/A')}</strong> - {vuln.get('desc', vuln.get('severity', 'N/A'))}<br>
                            Port: {vuln.get('port')} | Service: {vuln.get('service')}
                            </div>
                            """, unsafe_allow_html=True)
                    
                    # IoT Detection
                    if result["iot_devices"]:
                        st.markdown("### 🤖 IoT Devices")
                        for device in result["iot_devices"]:
                            st.info(f"**{device.get('type')}** - Port {device.get('port')}")
                    
                    # GeoIP info
                    if result["geo"]["country"] != "Unknown":
                        st.markdown("### 🌍 GeoIP Information")
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.metric("Country", result["geo"]["country"])
                        with col2:
                            st.metric("City", result["geo"]["city"])
                        with col3:
                            st.metric("ISP", result["geo"]["isp"])
                        with col4:
                            st.metric("Timezone", result["geo"]["timezone"])
                    
                    # OS Detection
                    if result["os"]["os"] != "Unknown":
                        st.markdown("### 🖥️ OS Detection")
                        col1, col2 = st.columns(2)
                        with col1:
                            st.metric("Operating System", result["os"]["os"])
                        with col2:
                            st.metric("Accuracy", f"{result['os']['accuracy']}%")
                    
                    st.session_state.scan_history.append(result)
                
            except Exception as e:
                st.error(f"Scan error: {str(e)}")

# ==================== TAB 2: FULL SCAN ====================

with tab2:
    st.subheader("Advanced Full Scan")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        full_target = st.text_input("Target IP/Range", "8.8.8.8")
    with col2:
        full_scan_type = st.selectbox("Scan Profile", ["Quick", "Thorough", "Aggressive"])
    with col3:
        st.write("")
        if st.button("▶️ Start Full Scan", use_container_width=True):
            with st.spinner("Running full scan..."):
                try:
                    result = asyncio.run(st.session_state.scanner.full_scan(full_target))
                    
                    # Store result
                    host_id = st.session_state.db.insert_host(full_target)
                    st.session_state.db.update_host_alive(full_target)
                    
                    # Display comprehensive results
                    st.success("Scan completed!")
                    
                    # Summary cards
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("💾 Hosts", 1)
                    with col2:
                        st.metric("🔌 Ports", len(result["ports"]))
                    with col3:
                        st.metric("⚠️ Vulns", len(result["vulnerabilities"]))
                    with col4:
                        st.metric("🤖 IoT", len(result["iot_devices"]))
                    
                    # Detailed tabs
                    dettab1, dettab2, dettab3, dettab4 = st.tabs(["Ports", "Vulnerabilities", "Web Services", "OAuth"])
                    
                    with dettab1:
                        if result["ports"]:
                            st.json(result["ports"])
                            
                            # Port pie chart
                            service_map = {}
                            for port_info in result["ports"]:
                                service = port_info.get("service", "Unknown")
                                service_map[service] = service_map.get(service, 0) + 1
                            
                            fig = px.pie(
                                values=list(service_map.values()),
                                names=list(service_map.keys()),
                                title="Services Distribution"
                            )
                            st.plotly_chart(fig, use_container_width=True)
                    
                    with dettab2:
                        if result["vulnerabilities"]:
                            for vuln in result["vulnerabilities"]:
                                col1, col2 = st.columns([3, 1])
                                with col1:
                                    st.markdown(f"**{vuln.get('cve')}**: {vuln.get('desc')}")
                                    st.caption(f"Port: {vuln.get('port')} | Service: {vuln.get('service')}")
                                with col2:
                                    severity = vuln.get("severity", "unknown").lower()
                                    st.markdown(f"<span style='color:{severity_color(severity)}'>{severity.upper()}</span>", 
                                              unsafe_allow_html=True)
                        else:
                            st.info("No vulnerabilities detected")
                    
                    with dettab3:
                        if result["web"]:
                            for port, web_data in result["web"].items():
                                with st.expander(f"Port {port} - {web_data.get('title', 'Unknown')}"):
                                    col1, col2 = st.columns(2)
                                    with col1:
                                        st.write(f"**Status:** {web_data.get('status')}")
                                        st.write(f"**Title:** {web_data.get('title')}")
                                        if web_data.get("endpoints"):
                                            st.write("**Endpoints:**")
                                            for endpoint in web_data["endpoints"][:10]:
                                                st.caption(endpoint)
                                    with col2:
                                        if web_data.get("vulnerable"):
                                            st.warning("⚠️ Vulnerabilities found")
                                            for vuln in web_data["vulnerable"]:
                                                st.caption(f"- {vuln.get('type')}")
                                        if web_data.get("cloud_resources"):
                                            st.warning("☁️ Cloud resources detected")
                                            for resource in web_data["cloud_resources"]:
                                                st.caption(f"- {resource.get('provider')}: {resource.get('bucket_name')}")
                        else:
                            st.info("No web services found")
                    
                    with dettab4:
                        if result["oauth"]:
                            for port, oauth_data in result["oauth"].items():
                                with st.expander(f"Port {port}"):
                                    if oauth_data.get("config"):
                                        st.json(oauth_data["config"])
                                    else:
                                        st.info("No OAuth configuration found")
                        else:
                            st.info("No OAuth endpoints detected")
                    
                except Exception as e:
                    st.error(f"Error: {str(e)}")

# ==================== TAB 3: EXPLOIT ENGINE ====================

with tab3:
    st.subheader("🎯 Exploit Engine")
    
    col1, col2 = st.columns(2)
    with col1:
        exploit_target = st.text_input("Target IP", "127.0.0.1")
    with col2:
        exploit_port = st.number_input("Port", min_value=1, max_value=65535, value=22)
    
    st.markdown("---")
    
    exp_col1, exp_col2, exp_col3, exp_col4 = st.columns(4)
    
    with exp_col1:
        if st.button("🔑 SSH", use_container_width=True):
            with st.spinner("Testing SSH..."):
                creds = st.session_state.exploit_engine.test_ssh(exploit_target, exploit_port)
                if creds:
                    st.success(f"✅ SSH compromised: `{creds[0]}:{creds[1]}`")
                    st.session_state.zombie_manager.add_zombie(
                        exploit_target, exploit_port, "SSH", creds, "SSH_DefaultCreds"
                    )
                else:
                    st.warning("❌ SSH default creds failed")
    
    with exp_col2:
        if st.button("🐬 MySQL", use_container_width=True):
            with st.spinner("Testing MySQL..."):
                creds = st.session_state.exploit_engine.test_mysql(exploit_target, exploit_port)
                if creds:
                    st.success(f"✅ MySQL compromised: `{creds[0]}:{creds[1]}`")
                    st.session_state.zombie_manager.add_zombie(
                        exploit_target, exploit_port, "MySQL", creds, "MySQL_DefaultCreds"
                    )
                else:
                    st.warning("❌ MySQL default creds failed")
    
    with exp_col3:
        if st.button("🔴 Redis", use_container_width=True):
            with st.spinner("Testing Redis..."):
                if st.session_state.exploit_engine.test_redis(exploit_target, exploit_port):
                    st.success("✅ Redis unauthenticated")
                    redis_data = st.session_state.exploit_engine.get_redis_data(exploit_target, exploit_port)
                    if redis_data:
                        st.json(redis_data)
                    st.session_state.zombie_manager.add_zombie(
                        exploit_target, exploit_port, "Redis", None, "Redis_Unauthenticated"
                    )
                else:
                    st.warning("❌ Redis authentication required")
    
    with exp_col4:
        if st.button("🍃 MongoDB", use_container_width=True):
            with st.spinner("Testing MongoDB..."):
                if st.session_state.exploit_engine.test_mongodb(exploit_target, exploit_port):
                    st.success("✅ MongoDB unauthenticated")
                    dbs = st.session_state.exploit_engine.get_mongodb_databases(exploit_target, exploit_port)
                    if dbs:
                        st.info(f"Databases: {', '.join(dbs)}")
                    st.session_state.zombie_manager.add_zombie(
                        exploit_target, exploit_port, "MongoDB", None, "MongoDB_Unauthenticated"
                    )
                else:
                    st.warning("❌ MongoDB authentication required")
    
    st.markdown("---")
    
    # Run all tests
    if st.button("🔥 Run All Tests", use_container_width=True, key="run_all_exploits"):
        with st.spinner("Running all exploit tests..."):
            open_ports = {22, 21, 3306, 5432, 6379, 27017, exploit_port}
            results = st.session_state.exploit_engine.run_all_tests(exploit_target, open_ports)
            
            st.markdown("### Results")
            for service, result in results.items():
                if result:
                    with st.expander(f"✅ {service.upper()}", expanded=True):
                        st.json(result)

# ==================== TAB 4: ZOMBIE NETWORK ====================

with tab4:
    st.subheader("🧟 Zombie Network Management")
    
    zombies = st.session_state.zombie_manager.list_zombies()
    stats = st.session_state.zombie_manager.get_stats()
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Zombies", stats["total"])
    with col2:
        st.metric("Active", stats["active"])
    with col3:
        st.metric("By Service", len(stats["by_service"]))
    
    st.markdown("---")
    
    if zombies:
        st.json(zombies)
        
        # Service distribution pie chart
        service_counts = stats["by_service"]
        if service_counts:
            fig = px.pie(
                values=list(service_counts.values()),
                names=list(service_counts.keys()),
                title="Zombies by Service"
            )
            st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No compromised hosts yet. Run exploits to populate zombie network.")

# ==================== TAB 5: DASHBOARD ====================

with tab5:
    st.subheader("📊 Security Dashboard")
    
    stats = st.session_state.db.get_statistics()
    
    # Summary metrics
    col1, col2, col3, col4, col5, col6 = st.columns(6)
    
    metrics = [
        (col1, "Hosts Scanned", stats["total_hosts"], "🖥️"),
        (col2, "Alive Hosts", stats["alive_hosts"], "✅"),
        (col3, "Open Ports", stats["open_ports"], "🔌"),
        (col4, "Vulnerabilities", stats["vulnerabilities"], "⚠️"),
        (col5, "Credentials", stats["credentials_found"], "🔑"),
        (col6, "IoT Devices", stats["iot_devices"], "🤖"),
    ]
    
    for col, label, value, icon in metrics:
        with col:
            st.metric(f"{icon} {label}", value)
    
    st.markdown("---")
    
    # Charts
    col1, col2 = st.columns(2)
    
    with col1:
        # Severity distribution
        if stats["vulnerabilities"] > 0:
            severity_data = {
                "Critical": 5,
                "High": 10,
                "Medium": 20,
                "Low": 15
            }
            fig = px.bar(
                x=list(severity_data.keys()),
                y=list(severity_data.values()),
                title="Vulnerability Severity Distribution",
                color=list(severity_data.keys()),
                color_discrete_sequence=[
                    "#FF0000", "#FF6600", "#FFCC00", "#00CC00"
                ]
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Scan activity
        if st.session_state.scan_history:
            activity_data = {
                "Port Scans": len([s for s in st.session_state.scan_history if "ports" in s]),
                "Web Scans": len([s for s in st.session_state.scan_history if "web" in s]),
                "Exploits": stats["credentials_found"],
            }
            fig = px.bar(
                x=list(activity_data.keys()),
                y=list(activity_data.values()),
                title="Scan Activity",
                color_discrete_sequence=["#FF0000", "#FF6600", "#FFCC00"]
            )
            st.plotly_chart(fig, use_container_width=True)

# ==================== TAB 6: SETTINGS ====================

with tab6:
    st.subheader("⚙️ Settings & Configuration")
    
    st.markdown("### Scanner Configuration")
    col1, col2, col3 = st.columns(3)
    with col1:
        default_timeout = st.number_input("Default Timeout (s)", 1, 30, 3)
    with col2:
        default_threads = st.number_input("Default Threads", 10, 500, 100)
    with col3:
        max_scan_rate = st.number_input("Max Scan Rate (ports/s)", 100, 10000, 1000)
    
    st.markdown("---")
    st.markdown("### Database Management")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("📊 View Database", use_container_width=True):
            st.write(st.session_state.db.get_statistics())
    
    with col2:
        if st.button("📤 Export Data", use_container_width=True):
            data = st.session_state.db.get_statistics()
            st.download_button(
                label="Download JSON",
                data=json.dumps(data, indent=2),
                file_name=f"omni_scan_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
    
    with col3:
        if st.button("🗑️ Clear Database", use_container_width=True):
            if st.checkbox("I understand this will delete all data"):
                st.session_state.db.clear_all()
                st.success("Database cleared!")
    
    st.markdown("---")
    st.markdown("### About")
    st.info("""
    **OMNI-SCAN v2.0**
    
    Advanced Network Reconnaissance & Exploitation Platform
    
    *For authorized security testing only*
    """)

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #888; font-size: 0.8rem;'>
OMNI-SCAN v2.0 | Advanced Offensive Security Platform | Use responsibly
</div>
""", unsafe_allow_html=True)
