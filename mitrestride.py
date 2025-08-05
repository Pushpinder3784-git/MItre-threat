import streamlit as st
import pandas as pd
import json
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import networkx as nx
from datetime import datetime
import uuid

# Configure Streamlit page
st.set_page_config(
    page_title="STRIDE Threat Modeling Tool",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Security Controls Database
SECURITY_CONTROLS = {
    "P-AC-01": {
        "name": "Account Management",
        "description": "Establish processes for account lifecycle management",
        "domain": "People",
        "mitre_techniques": ["T1078.001", "T1078.002", "T1078.003"],
        "stride_categories": ["Spoofing", "Elevation of Privilege"],
        "implementation_effort": "Medium",
        "cost": "Low"
    },
    "P-AC-03": {
        "name": "Multi-Factor Authentication",
        "description": "Require MFA for all user accounts",
        "domain": "People",
        "mitre_techniques": ["T1078", "T1556.001"],
        "stride_categories": ["Spoofing", "Elevation of Privilege"],
        "implementation_effort": "Low",
        "cost": "Low"
    },
    "A-SI-01": {
        "name": "Input Validation",
        "description": "Validate all input data for type, length, format",
        "domain": "Application",
        "mitre_techniques": ["T1190", "T1059.007"],
        "stride_categories": ["Tampering", "Information Disclosure", "Elevation of Privilege"],
        "implementation_effort": "High",
        "cost": "Medium"
    },
    "N-AC-01": {
        "name": "Network Segmentation",
        "description": "Implement network segmentation and micro-segmentation",
        "domain": "Network",
        "mitre_techniques": ["T1021", "T1090.003"],
        "stride_categories": ["Spoofing", "Information Disclosure", "Elevation of Privilege"],
        "implementation_effort": "High",
        "cost": "High"
    },
    "D-SC-01": {
        "name": "Data Encryption",
        "description": "Encrypt sensitive data at rest and in transit",
        "domain": "Data",
        "mitre_techniques": ["T1560.001", "T1041"],
        "stride_categories": ["Information Disclosure", "Tampering"],
        "implementation_effort": "Medium",
        "cost": "Medium"
    },
    "PA-AU-01": {
        "name": "User Activity Logging",
        "description": "Log all user activities in applications",
        "domain": "People-Application",
        "mitre_techniques": ["T1562.006", "T1070"],
        "stride_categories": ["Repudiation", "Information Disclosure"],
        "implementation_effort": "Medium",
        "cost": "Low"
    },
    "N-SI-03": {
        "name": "DDoS Protection",
        "description": "Implement DDoS mitigation controls",
        "domain": "Network",
        "mitre_techniques": ["T1498.001", "T1498.002"],
        "stride_categories": ["Denial of Service"],
        "implementation_effort": "Medium",
        "cost": "High"
    },
    "ZT-ID-01": {
        "name": "Continuous Authentication",
        "description": "Implement continuous user and device verification",
        "domain": "Zero Trust",
        "mitre_techniques": ["T1078", "T1087", "T1033"],
        "stride_categories": ["Spoofing", "Elevation of Privilege"],
        "implementation_effort": "High",
        "cost": "High"
    },
    "SOAR-IR-01": {
        "name": "Automated Threat Detection",
        "description": "AI/ML-based threat detection and alerting",
        "domain": "Automation",
        "mitre_techniques": ["All tactics"],
        "stride_categories": ["Spoofing", "Tampering", "Information Disclosure", "Denial of Service", "Elevation of Privilege"],
        "implementation_effort": "High",
        "cost": "High"
    },
    "RW-PREV-01": {
        "name": "Backup Immutability",
        "description": "Implement immutable backup solutions",
        "domain": "Data",
        "mitre_techniques": ["T1490", "T1485"],
        "stride_categories": ["Denial of Service", "Tampering"],
        "implementation_effort": "Medium",
        "cost": "Medium"
    }
}

# STRIDE Threat Templates
STRIDE_THREATS = {
    "Spoofing": {
        "description": "Impersonating something or someone else",
        "examples": ["Identity theft", "IP spoofing", "Email spoofing", "Certificate spoofing"],
        "mitre_tactics": ["Initial Access", "Defense Evasion"],
        "common_techniques": ["T1078", "T1557", "T1556"]
    },
    "Tampering": {
        "description": "Modifying data or code",
        "examples": ["Data corruption", "Code injection", "Configuration changes", "File modification"],
        "mitre_tactics": ["Defense Evasion", "Impact"],
        "common_techniques": ["T1565", "T1554", "T1562", "T1070"]
    },
    "Repudiation": {
        "description": "Claiming to have not performed an action",
        "examples": ["Log deletion", "Audit trail tampering", "Transaction denial", "Action disavowal"],
        "mitre_tactics": ["Defense Evasion"],
        "common_techniques": ["T1070", "T1562.006", "T1070.001"]
    },
    "Information Disclosure": {
        "description": "Exposing information to unauthorized individuals",
        "examples": ["Data breach", "Memory dumps", "Network sniffing", "Error messages"],
        "mitre_tactics": ["Collection", "Exfiltration"],
        "common_techniques": ["T1005", "T1213", "T1040", "T1041"]
    },
    "Denial of Service": {
        "description": "Denying or degrading service availability",
        "examples": ["DDoS attacks", "Resource exhaustion", "System crashes", "Ransomware"],
        "mitre_tactics": ["Impact"],
        "common_techniques": ["T1498", "T1499", "T1486", "T1490"]
    },
    "Elevation of Privilege": {
        "description": "Gaining capabilities without proper authorization",
        "examples": ["Privilege escalation", "Admin access", "Root compromise", "Cloud escalation"],
        "mitre_tactics": ["Privilege Escalation", "Persistence"],
        "common_techniques": ["T1078", "T1134", "T1068", "T1543"]
    }
}

# Component Types and Their Domains
COMPONENT_TYPES = {
    "User": {"domain": "People", "color": "#FF6B6B", "icon": "👤"},
    "Application": {"domain": "Application", "color": "#4ECDC4", "icon": "💻"},
    "Database": {"domain": "Data", "color": "#45B7D1", "icon": "🗄️"},
    "Web Server": {"domain": "Application", "color": "#96CEB4", "icon": "🌐"},
    "Network": {"domain": "Network", "color": "#FFEAA7", "icon": "🌐"},
    "Cloud Service": {"domain": "Application", "color": "#DDA0DD", "icon": "☁️"},
    "External System": {"domain": "Network", "color": "#FFB347", "icon": "🔗"},
    "Mobile App": {"domain": "Application", "color": "#87CEEB", "icon": "📱"},
    "API Gateway": {"domain": "Network", "color": "#F0E68C", "icon": "🚪"},
    "Load Balancer": {"domain": "Network", "color": "#D3D3D3", "icon": "⚖️"}
}

def initialize_session_state():
    """Initialize session state variables"""
    if 'components' not in st.session_state:
        st.session_state.components = []
    if 'data_flows' not in st.session_state:
        st.session_state.data_flows = []
    if 'threats' not in st.session_state:
        st.session_state.threats = []
    if 'mitigations' not in st.session_state:
        st.session_state.mitigations = []
    if 'threat_model_name' not in st.session_state:
        st.session_state.threat_model_name = "New Threat Model"

def add_component(name, component_type, description, trust_level):
    """Add a component to the threat model"""
    component = {
        "id": str(uuid.uuid4()),
        "name": name,
        "type": component_type,
        "description": description,
        "trust_level": trust_level,
        "domain": COMPONENT_TYPES[component_type]["domain"],
        "color": COMPONENT_TYPES[component_type]["color"],
        "icon": COMPONENT_TYPES[component_type]["icon"]
    }
    st.session_state.components.append(component)
    return component["id"]

def add_data_flow(source_id, target_id, data_type, protocol, description):
    """Add a data flow between components"""
    data_flow = {
        "id": str(uuid.uuid4()),
        "source_id": source_id,
        "target_id": target_id,
        "data_type": data_type,
        "protocol": protocol,
        "description": description
    }
    st.session_state.data_flows.append(data_flow)
    return data_flow["id"]

def generate_stride_threats(data_flow):
    """Generate STRIDE threats for a data flow"""
    threats = []
    source_comp = next((c for c in st.session_state.components if c["id"] == data_flow["source_id"]), None)
    target_comp = next((c for c in st.session_state.components if c["id"] == data_flow["target_id"]), None)
    
    if not source_comp or not target_comp:
        return threats
    
    # Generate threats based on component types and data flow characteristics
    for stride_category, stride_info in STRIDE_THREATS.items():
        # Determine if this STRIDE category applies to this data flow
        threat_applies = False
        risk_level = "Low"
        
        # Logic to determine threat applicability and risk
        if stride_category == "Spoofing":
            if source_comp["trust_level"] != "High" or target_comp["trust_level"] != "High":
                threat_applies = True
                risk_level = "High" if data_flow["protocol"] in ["HTTP", "Telnet", "FTP"] else "Medium"
        
        elif stride_category == "Tampering":
            if data_flow["data_type"] in ["Personal Data", "Financial Data", "Configuration"]:
                threat_applies = True
                risk_level = "Critical" if data_flow["protocol"] in ["HTTP", "Unencrypted"] else "High"
        
        elif stride_category == "Repudiation":
            if target_comp["type"] in ["Database", "Application", "Cloud Service"]:
                threat_applies = True
                risk_level = "Medium"
        
        elif stride_category == "Information Disclosure":
            if data_flow["data_type"] in ["Personal Data", "Financial Data", "Confidential"]:
                threat_applies = True
                risk_level = "Critical" if data_flow["protocol"] in ["HTTP", "Unencrypted"] else "High"
        
        elif stride_category == "Denial of Service":
            if target_comp["type"] in ["Web Server", "Application", "API Gateway"]:
                threat_applies = True
                risk_level = "High" if target_comp["trust_level"] == "Low" else "Medium"
        
        elif stride_category == "Elevation of Privilege":
            if target_comp["type"] in ["Database", "Application"] and source_comp["type"] == "User":
                threat_applies = True
                risk_level = "High" if source_comp["trust_level"] == "Low" else "Medium"
        
        if threat_applies:
            threat = {
                "id": str(uuid.uuid4()),
                "data_flow_id": data_flow["id"],
                "category": stride_category,
                "description": f"{stride_category} threat on {source_comp['name']} → {target_comp['name']}",
                "detailed_description": f"Potential {stride_category.lower()} attack targeting the {data_flow['data_type']} data flow from {source_comp['name']} to {target_comp['name']} via {data_flow['protocol']}",
                "risk_level": risk_level,
                "mitre_techniques": stride_info["common_techniques"],
                "source_component": source_comp["name"],
                "target_component": target_comp["name"],
                "data_type": data_flow["data_type"],
                "protocol": data_flow["protocol"]
            }
            threats.append(threat)
    
    return threats

def get_relevant_mitigations(threat):
    """Get relevant security controls for a threat"""
    mitigations = []
    
    for control_id, control in SECURITY_CONTROLS.items():
        # Check if control applies to this STRIDE category
        if threat["category"] in control["stride_categories"]:
            # Check if control applies to relevant MITRE techniques
            technique_match = any(tech in control["mitre_techniques"] for tech in threat["mitre_techniques"])
            if technique_match or "All tactics" in control["mitre_techniques"]:
                mitigation = {
                    "control_id": control_id,
                    "control_name": control["name"],
                    "description": control["description"],
                    "domain": control["domain"],
                    "implementation_effort": control["implementation_effort"],
                    "cost": control["cost"],
                    "effectiveness": calculate_effectiveness(threat, control)
                }
                mitigations.append(mitigation)
    
    # Sort by effectiveness score
    mitigations.sort(key=lambda x: x["effectiveness"], reverse=True)
    return mitigations[:5]  # Return top 5 most effective controls

def calculate_effectiveness(threat, control):
    """Calculate control effectiveness for a specific threat"""
    base_score = 70
    
    # Bonus for exact STRIDE category match
    if threat["category"] in control["stride_categories"]:
        base_score += 20
    
    # Bonus for MITRE technique match
    if any(tech in control["mitre_techniques"] for tech in threat["mitre_techniques"]):
        base_score += 10
    
    # Adjust for risk level
    risk_multipliers = {"Critical": 1.2, "High": 1.1, "Medium": 1.0, "Low": 0.9}
    base_score *= risk_multipliers.get(threat["risk_level"], 1.0)
    
    # Adjust for implementation effort (easier = more effective in practice)
    effort_multipliers = {"Low": 1.1, "Medium": 1.0, "High": 0.9}
    base_score *= effort_multipliers.get(control["implementation_effort"], 1.0)
    
    return min(100, max(0, base_score))

def create_architecture_diagram():
    """Create an interactive architecture diagram"""
    if not st.session_state.components:
        st.info("Add components to see the architecture diagram")
        return None
    
    # Create network graph
    G = nx.Graph()
    
    # Add nodes
    for comp in st.session_state.components:
        G.add_node(comp["id"], 
                  label=comp["name"], 
                  type=comp["type"],
                  domain=comp["domain"],
                  color=comp["color"])
    
    # Add edges
    for flow in st.session_state.data_flows:
        G.add_edge(flow["source_id"], flow["target_id"],
                  data_type=flow["data_type"],
                  protocol=flow["protocol"])
    
    # Create layout
    pos = nx.spring_layout(G, k=3, iterations=50)
    
    # Create Plotly figure
    fig = go.Figure()
    
    # Add edges
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        flow_data = next((f for f in st.session_state.data_flows 
                         if f["source_id"] == edge[0] and f["target_id"] == edge[1]), None)
        
        fig.add_trace(go.Scatter(
            x=[x0, x1, None],
            y=[y0, y1, None],
            mode='lines',
            line=dict(width=2, color='gray'),
            hoverinfo='text',
            hovertext=f"Data: {flow_data['data_type']}<br>Protocol: {flow_data['protocol']}" if flow_data else "",
            showlegend=False
        ))
    
    # Add nodes
    for node in G.nodes():
        x, y = pos[node]
        comp = next((c for c in st.session_state.components if c["id"] == node), None)
        if comp:
            fig.add_trace(go.Scatter(
                x=[x],
                y=[y],
                mode='markers+text',
                marker=dict(size=30, color=comp["color"]),
                text=comp["icon"],
                textposition="middle center",
                hoverinfo='text',
                hovertext=f"{comp['name']}<br>Type: {comp['type']}<br>Domain: {comp['domain']}<br>Trust: {comp['trust_level']}",
                name=comp["name"],
                showlegend=True
            ))
    
    fig.update_layout(
        title="System Architecture Diagram",
        showlegend=True,
        hovermode='closest',
        margin=dict(b=20,l=5,r=5,t=40),
        annotations=[
            dict(
                text="Drag nodes to rearrange. Hover for details.",
                showarrow=False,
                xref="paper", yref="paper",
                x=0.005, y=-0.002,
                xanchor='left', yanchor='bottom',
                font=dict(color='gray', size=12)
            )
        ],
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        height=500
    )
    
    return fig

def create_threat_heatmap():
    """Create a STRIDE threat heatmap"""
    if not st.session_state.threats:
        return None
    
    # Count threats by category and risk level
    threat_data = []
    stride_categories = list(STRIDE_THREATS.keys())
    risk_levels = ["Low", "Medium", "High", "Critical"]
    
    for category in stride_categories:
        for risk in risk_levels:
            count = len([t for t in st.session_state.threats 
                        if t["category"] == category and t["risk_level"] == risk])
            threat_data.append({
                "STRIDE Category": category,
                "Risk Level": risk,
                "Count": count
            })
    
    df = pd.DataFrame(threat_data)
    pivot_df = df.pivot(index="STRIDE Category", columns="Risk Level", values="Count")
    
    fig = px.imshow(
        pivot_df,
        labels=dict(x="Risk Level", y="STRIDE Category", color="Threat Count"),
        x=risk_levels,
        y=stride_categories,
        color_continuous_scale="Reds",
        title="STRIDE Threat Risk Heatmap"
    )
    
    return fig

def main():
    """Main application function"""
    initialize_session_state()
    
    st.title("🛡️ STRIDE Threat Modeling Tool")
    st.markdown("**Comprehensive threat modeling with automated STRIDE analysis and security control recommendations**")
    
    # Sidebar for navigation
    with st.sidebar:
        st.header("Navigation")
        tab = st.radio("Select Section", [
            "📋 Project Setup",
            "🏗️ Architecture Builder", 
            "⚠️ Threat Analysis",
            "🛡️ Mitigation Planning",
            "📊 Risk Dashboard",
            "📄 Export Report"
        ])
    
    # Project Setup Tab
    if tab == "📋 Project Setup":
        st.header("Project Setup")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Project Information")
            st.session_state.threat_model_name = st.text_input(
                "Threat Model Name", 
                value=st.session_state.threat_model_name
            )
            
            project_description = st.text_area(
                "Project Description",
                "Describe the system or application being threat modeled..."
            )
            
            security_objectives = st.multiselect(
                "Security Objectives",
                ["Confidentiality", "Integrity", "Availability", "Authentication", "Authorization", "Non-repudiation"],
                default=["Confidentiality", "Integrity", "Availability"]
            )
        
        with col2:
            st.subheader("Compliance Requirements")
            compliance_frameworks = st.multiselect(
                "Applicable Frameworks",
                ["GDPR", "HIPAA", "PCI DSS", "SOX", "NIST CSF", "ISO 27001", "SOC 2"],
                help="Select all applicable compliance frameworks"
            )
            
            threat_actors = st.multiselect(
                "Relevant Threat Actors",
                ["Script Kiddies", "Cybercriminals", "Nation State", "Insiders", "Competitors", "Hacktivists"],
                help="Select potential threat actors for this system"
            )
            
            system_criticality = st.selectbox(
                "System Criticality",
                ["Low", "Medium", "High", "Critical"],
                help="Business criticality of the system"
            )
        
        if st.button("Save Project Configuration"):
            st.success("Project configuration saved!")
    
    # Architecture Builder Tab
    elif tab == "🏗️ Architecture Builder":
        st.header("Architecture Builder")
        
        col1, col2 = st.columns([1, 2])
        
        with col1:
            st.subheader("Add Components")
            
            with st.form("component_form"):
                comp_name = st.text_input("Component Name")
                comp_type = st.selectbox("Component Type", list(COMPONENT_TYPES.keys()))
                comp_description = st.text_area("Description")
                trust_level = st.selectbox("Trust Level", ["Low", "Medium", "High"])
                
                if st.form_submit_button("Add Component"):
                    if comp_name:
                        add_component(comp_name, comp_type, comp_description, trust_level)
                        st.success(f"Added component: {comp_name}")
                        st.rerun()
            
            st.subheader("Add Data Flows")
            
            if len(st.session_state.components) >= 2:
                with st.form("dataflow_form"):
                    source_options = {f"{c['name']} ({c['type']})": c['id'] for c in st.session_state.components}
                    target_options = {f"{c['name']} ({c['type']})": c['id'] for c in st.session_state.components}
                    
                    source_name = st.selectbox("Source Component", list(source_options.keys()))
                    target_name = st.selectbox("Target Component", list(target_options.keys()))
                    
                    data_type = st.selectbox(
                        "Data Type", 
                        ["Personal Data", "Financial Data", "Configuration", "Log Data", "Authentication", "Business Data"]
                    )
                    protocol = st.selectbox(
                        "Protocol/Method",
                        ["HTTPS", "HTTP", "SQL", "API", "SSH", "RDP", "Email", "File Transfer", "Unencrypted"]
                    )
                    flow_description = st.text_area("Flow Description")
                    
                    if st.form_submit_button("Add Data Flow"):
                        if source_name != target_name:
                            source_id = source_options[source_name]
                            target_id = target_options[target_name]
                            add_data_flow(source_id, target_id, data_type, protocol, flow_description)
                            st.success(f"Added data flow: {source_name} → {target_name}")
                            st.rerun()
                        else:
                            st.error("Source and target must be different components")
            else:
                st.info("Add at least 2 components to create data flows")
        
        with col2:
            st.subheader("Architecture Diagram")
            diagram = create_architecture_diagram()
            if diagram:
                st.plotly_chart(diagram, use_container_width=True)
            
            # Component and Data Flow Lists
            if st.session_state.components:
                st.subheader("Components")
                comp_df = pd.DataFrame([{
                    "Name": c["name"],
                    "Type": c["type"],
                    "Domain": c["domain"],
                    "Trust Level": c["trust_level"]
                } for c in st.session_state.components])
                st.dataframe(comp_df, use_container_width=True)
            
            if st.session_state.data_flows:
                st.subheader("Data Flows")
                flow_df = pd.DataFrame([{
                    "Source": next((c["name"] for c in st.session_state.components if c["id"] == f["source_id"]), "Unknown"),
                    "Target": next((c["name"] for c in st.session_state.components if c["id"] == f["target_id"]), "Unknown"),
                    "Data Type": f["data_type"],
                    "Protocol": f["protocol"]
                } for f in st.session_state.data_flows])
                st.dataframe(flow_df, use_container_width=True)
    
    # Threat Analysis Tab
    elif tab == "⚠️ Threat Analysis":
        st.header("STRIDE Threat Analysis")
        
        if not st.session_state.data_flows:
            st.warning("Please add components and data flows in the Architecture Builder first.")
            return
        
        col1, col2 = st.columns([1, 1])
        
        with col1:
            st.subheader("Generate Threats")
            
            if st.button("🔍 Auto-Generate STRIDE Threats", type="primary"):
                st.session_state.threats = []
                
                with st.spinner("Analyzing data flows for STRIDE threats..."):
                    for data_flow in st.session_state.data_flows:
                        threats = generate_stride_threats(data_flow)
                        st.session_state.threats.extend(threats)
                
                st.success(f"Generated {len(st.session_state.threats)} potential threats")
                st.rerun()
            
            st.subheader("Manual Threat Entry")
            with st.form("manual_threat_form"):
                if st.session_state.data_flows:
                    flow_options = {
                        f"{next((c['name'] for c in st.session_state.components if c['id'] == f['source_id']), 'Unknown')} → {next((c['name'] for c in st.session_state.components if c['id'] == f['target_id']), 'Unknown')}": f['id'] 
                        for f in st.session_state.data_flows
                    }
                    
                    selected_flow = st.selectbox("Select Data Flow", list(flow_options.keys()))
                    stride_category = st.selectbox("STRIDE Category", list(STRIDE_THREATS.keys()))
                    custom_description = st.text_area("Threat Description")
                    risk_level = st.selectbox("Risk Level", ["Low", "Medium", "High", "Critical"])
                    
                    if st.form_submit_button("Add Manual Threat"):
                        if selected_flow and custom_description:
                            flow_id = flow_options[selected_flow]
                            threat = {
                                "id": str(uuid.uuid4()),
                                "data_flow_id": flow_id,
                                "category": stride_category,
                                "description": custom_description,
                                "detailed_description": custom_description,
                                "risk_level": risk_level,
                                "mitre_techniques": STRIDE_THREATS[stride_category]["common_techniques"],
                                "manual": True
                            }
                            st.session_state.threats.append(threat)
                            st.success("Manual threat added!")
                            st.rerun()
        
        with col2:
            st.subheader("Threat Summary")
            
            if st.session_state.threats:
                # Threat statistics
                threat_stats = pd.DataFrame(st.session_state.threats)
                
                # STRIDE category distribution
                stride_counts = threat_stats["category"].value_counts()
                fig_stride = px.bar(
                    x=stride_counts.index,
                    y=stride_counts.values,
                    title="Threats by STRIDE Category",
                    labels={"x": "STRIDE Category", "y": "Count"}
                )
                st.plotly_chart(fig_stride, use_container_width=True)
                
                # Risk level distribution
                risk_counts = threat_stats["risk_level"].value_counts()
                fig_risk = px.pie(
                    values=risk_counts.values,
                    names=risk_counts.index,
                    title="Threats by Risk Level"
                )
                st.plotly_chart(fig_risk, use_container_width=True)
                
                # Threat heatmap
                heatmap = create_threat_heatmap()
                if heatmap:
                    st.plotly_chart(heatmap, use_container_width=True)
        
        # Detailed Threat List
        if st.session_state.threats:
            st.subheader("Identified Threats")
            
            # Filter options
            filter_col1, filter_col2, filter_col3 = st.columns(3)
            
            with filter_col1:
                category_filter = st.multiselect(
                    "Filter by STRIDE Category",
                    list(STRIDE_THREATS.keys()),
                    default=list(STRIDE_THREATS.keys())
                )
            
            with filter_col2:
                risk_filter = st.multiselect(
                    "Filter by Risk Level",
                    ["Low", "Medium", "High", "Critical"],
                    default=["High", "Critical"]
                )
            
            with filter_col3:
                show_all = st.checkbox("Show All Threats", value=False)
            
            # Apply filters
            filtered_threats = [
                t for t in st.session_state.threats
                if (show_all or t["category"] in category_filter) and
                   (show_all or t["risk_level"] in risk_filter)
            ]
            
            # Display filtered threats
            for i, threat in enumerate(filtered_threats):
                with st.expander(f"🚨 {threat['category']} - {threat['description']} (Risk: {threat['risk_level']})"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write("**Detailed Description:**")
                        st.write(threat["detailed_description"])
                        
                        st.write("**MITRE ATT&CK Techniques:**")
                        for technique in threat["mitre_techniques"]:
                            st.code(technique)
                    
                    with col2:
                        st.write("**Affected Data Flow:**")
                        flow = next((f for f in st.session_state.data_flows if f["id"] == threat["data_flow_id"]), None)
                        if flow:
                            source_comp = next((c for c in st.session_state.components if c["id"] == flow["source_id"]), None)
                            target_comp = next((c for c in st.session_state.components if c["id"] == flow["target_id"]), None)
                            if source_comp and target_comp:
                                st.write(f"• **Source:** {source_comp['name']} ({source_comp['type']})")
                                st.write(f"• **Target:** {target_comp['name']} ({target_comp['type']})")
                                st.write(f"• **Data Type:** {flow['data_type']}")
                                st.write(f"• **Protocol:** {flow['protocol']}")
                        
                        if st.button(f"Generate Mitigations", key=f"gen_mit_{i}"):
                            mitigations = get_relevant_mitigations(threat)
                            st.session_state.mitigations.extend([{
                                **mit, 
                                "threat_id": threat["id"],
                                "threat_category": threat["category"]
                            } for mit in mitigations])
                            st.success(f"Generated {len(mitigations)} mitigations for this threat")
                            st.rerun()
    
    # Mitigation Planning Tab
    elif tab == "🛡️ Mitigation Planning":
        st.header("Security Control Recommendations")
        
        if not st.session_state.threats:
            st.warning("Please generate threats in the Threat Analysis section first.")
            return
        
        col1, col2 = st.columns([1, 1])
        
        with col1:
            st.subheader("Generate All Mitigations")
            
            if st.button("🛡️ Generate Comprehensive Mitigation Plan", type="primary"):
                st.session_state.mitigations = []
                
                with st.spinner("Analyzing threats and generating security control recommendations..."):
                    for threat in st.session_state.threats:
                        mitigations = get_relevant_mitigations(threat)
                        for mitigation in mitigations:
                            # Avoid duplicates
                            existing = next((m for m in st.session_state.mitigations 
                                           if m["control_id"] == mitigation["control_id"] and 
                                              m["threat_id"] == threat["id"]), None)
                            if not existing:
                                st.session_state.mitigations.append({
                                    **mitigation,
                                    "threat_id": threat["id"],
                                    "threat_category": threat["category"],
                                    "threat_risk": threat["risk_level"]
                                })
                
                st.success(f"Generated {len(st.session_state.mitigations)} security control recommendations")
                st.rerun()
            
            st.subheader("Control Priority Matrix")
            if st.session_state.mitigations:
                # Calculate control priorities
                control_priorities = {}
                for mitigation in st.session_state.mitigations:
                    control_id = mitigation["control_id"]
                    if control_id not in control_priorities:
                        control_priorities[control_id] = {
                            "name": mitigation["control_name"],
                            "domain": mitigation["domain"],
                            "threats_covered": 0,
                            "avg_effectiveness": 0,
                            "high_risk_threats": 0,
                            "implementation_effort": mitigation["implementation_effort"],
                            "cost": mitigation["cost"]
                        }
                    
                    control_priorities[control_id]["threats_covered"] += 1
                    control_priorities[control_id]["avg_effectiveness"] += mitigation["effectiveness"]
                    if mitigation["threat_risk"] in ["High", "Critical"]:
                        control_priorities[control_id]["high_risk_threats"] += 1
                
                # Calculate averages and priority scores
                for control_id, data in control_priorities.items():
                    data["avg_effectiveness"] = data["avg_effectiveness"] / data["threats_covered"]
                    # Priority score: effectiveness * threats covered * high risk multiplier
                    high_risk_multiplier = 1 + (data["high_risk_threats"] * 0.3)
                    data["priority_score"] = data["avg_effectiveness"] * data["threats_covered"] * high_risk_multiplier
                
                # Create priority dataframe
                priority_df = pd.DataFrame.from_dict(control_priorities, orient='index')
                priority_df = priority_df.sort_values('priority_score', ascending=False)
                
                # Display top controls
                st.write("**Top Priority Controls:**")
                for i, (control_id, row) in enumerate(priority_df.head(10).iterrows()):
                    with st.expander(f"#{i+1} {control_id}: {row['name']} (Score: {row['priority_score']:.1f})"):
                        col_a, col_b = st.columns(2)
                        with col_a:
                            st.metric("Threats Covered", int(row['threats_covered']))
                            st.metric("Avg Effectiveness", f"{row['avg_effectiveness']:.1f}%")
                        with col_b:
                            st.metric("High Risk Threats", int(row['high_risk_threats']))
                            st.write(f"**Domain:** {row['domain']}")
                            st.write(f"**Effort:** {row['implementation_effort']}")
                            st.write(f"**Cost:** {row['cost']}")
        
        with col2:
            st.subheader("Implementation Roadmap")
            
            if st.session_state.mitigations:
                # Group mitigations by implementation effort and cost
                roadmap_data = []
                effort_order = {"Low": 1, "Medium": 2, "High": 3}
                cost_order = {"Low": 1, "Medium": 2, "High": 3}
                
                unique_controls = {}
                for mitigation in st.session_state.mitigations:
                    control_id = mitigation["control_id"]
                    if control_id not in unique_controls:
                        unique_controls[control_id] = mitigation
                
                for control in unique_controls.values():
                    roadmap_data.append({
                        "Control": f"{control['control_id']}: {control['control_name']}",
                        "Domain": control['domain'],
                        "Effort": control['implementation_effort'],
                        "Cost": control['cost'],
                        "Effort_Order": effort_order[control['implementation_effort']],
                        "Cost_Order": cost_order[control['cost']]
                    })
                
                roadmap_df = pd.DataFrame(roadmap_data)
                
                # Create implementation phases
                st.write("**Recommended Implementation Phases:**")
                
                # Phase 1: Low effort, Low/Medium cost
                phase1 = roadmap_df[
                    (roadmap_df['Effort_Order'] == 1) & 
                    (roadmap_df['Cost_Order'].isin([1, 2]))
                ]
                if not phase1.empty:
                    st.write("**Phase 1 (Quick Wins - 0-3 months):**")
                    for _, row in phase1.iterrows():
                        st.write(f"• {row['Control']}")
                
                # Phase 2: Medium effort, any cost
                phase2 = roadmap_df[
                    (roadmap_df['Effort_Order'] == 2)
                ]
                if not phase2.empty:
                    st.write("**Phase 2 (Medium Term - 3-9 months):**")
                    for _, row in phase2.iterrows():
                        st.write(f"• {row['Control']}")
                
                # Phase 3: High effort, any cost
                phase3 = roadmap_df[
                    (roadmap_df['Effort_Order'] == 3)
                ]
                if not phase3.empty:
                    st.write("**Phase 3 (Long Term - 9-18 months):**")
                    for _, row in phase3.iterrows():
                        st.write(f"• {row['Control']}")
                
                # Effort vs Cost scatter plot
                fig_roadmap = px.scatter(
                    roadmap_df,
                    x="Cost_Order",
                    y="Effort_Order",
                    color="Domain",
                    hover_name="Control",
                    title="Implementation Effort vs Cost Analysis",
                    labels={"Cost_Order": "Implementation Cost", "Effort_Order": "Implementation Effort"}
                )
                fig_roadmap.update_xaxis(tickvals=[1, 2, 3], ticktext=["Low", "Medium", "High"])
                fig_roadmap.update_yaxis(tickvals=[1, 2, 3], ticktext=["Low", "Medium", "High"])
                st.plotly_chart(fig_roadmap, use_container_width=True)
        
        # Detailed Mitigation List
        if st.session_state.mitigations:
            st.subheader("Detailed Security Control Recommendations")
            
            # Group mitigations by domain
            domain_filter = st.multiselect(
                "Filter by Domain",
                ["People", "Application", "Network", "Data", "Zero Trust", "Automation"],
                default=["People", "Application", "Network", "Data"]
            )
            
            # Group mitigations by domain
            mitigations_by_domain = {}
            for mitigation in st.session_state.mitigations:
                domain = mitigation["domain"]
                if domain not in mitigations_by_domain:
                    mitigations_by_domain[domain] = []
                mitigations_by_domain[domain].append(mitigation)
            
            for domain in domain_filter:
                if domain in mitigations_by_domain:
                    st.write(f"### {domain} Domain Controls")
                    
                    # Get unique controls for this domain
                    unique_domain_controls = {}
                    for mitigation in mitigations_by_domain[domain]:
                        control_id = mitigation["control_id"]
                        if control_id not in unique_domain_controls:
                            unique_domain_controls[control_id] = mitigation
                            unique_domain_controls[control_id]["applicable_threats"] = []
                        
                        # Find the threat this mitigation addresses
                        threat = next((t for t in st.session_state.threats if t["id"] == mitigation["threat_id"]), None)
                        if threat:
                            unique_domain_controls[control_id]["applicable_threats"].append(threat["category"])
                    
                    for control_id, control in unique_domain_controls.items():
                        with st.expander(f"{control_id}: {control['control_name']}"):
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                st.write("**Description:**")
                                st.write(control["description"])
                                
                                st.write("**Applicable STRIDE Categories:**")
                                unique_threats = list(set(control["applicable_threats"]))
                                for threat_cat in unique_threats:
                                    st.write(f"• {threat_cat}")
                            
                            with col2:
                                st.metric("Effectiveness Score", f"{control['effectiveness']:.1f}%")
                                st.write(f"**Implementation Effort:** {control['implementation_effort']}")
                                st.write(f"**Cost:** {control['cost']}")
                                st.write(f"**Domain:** {control['domain']}")
    
    # Risk Dashboard Tab
    elif tab == "📊 Risk Dashboard":
        st.header("Risk Assessment Dashboard")
        
        if not st.session_state.threats:
            st.warning("Please generate threats first to see risk metrics.")
            return
        
        # Risk Metrics Overview
        col1, col2, col3, col4 = st.columns(4)
        
        total_threats = len(st.session_state.threats)
        critical_threats = len([t for t in st.session_state.threats if t["risk_level"] == "Critical"])
        high_threats = len([t for t in st.session_state.threats if t["risk_level"] == "High"])
        mitigated_threats = len(set([m["threat_id"] for m in st.session_state.mitigations]))
        
        with col1:
            st.metric("Total Threats", total_threats)
        with col2:
            st.metric("Critical Risk", critical_threats, delta=f"{(critical_threats/total_threats)*100:.1f}%" if total_threats > 0 else "0%")
        with col3:
            st.metric("High Risk", high_threats, delta=f"{(high_threats/total_threats)*100:.1f}%" if total_threats > 0 else "0%")
        with col4:
            st.metric("Mitigated", mitigated_threats, delta=f"{(mitigated_threats/total_threats)*100:.1f}%" if total_threats > 0 else "0%")
        
        # Risk Visualization
        col1, col2 = st.columns(2)
        
        with col1:
            # Risk Level Distribution
            threat_df = pd.DataFrame(st.session_state.threats)
            risk_counts = threat_df["risk_level"].value_counts()
            
            fig_risk_dist = px.pie(
                values=risk_counts.values,
                names=risk_counts.index,
                title="Threat Distribution by Risk Level",
                color_discrete_map={
                    "Critical": "#FF0000",
                    "High": "#FF8C00", 
                    "Medium": "#FFD700",
                    "Low": "#90EE90"
                }
            )
            st.plotly_chart(fig_risk_dist, use_container_width=True)
            
            # Domain Risk Analysis
            domain_risks = []
            for component in st.session_state.components:
                domain = component["domain"]
                domain_threats = []
                
                for flow in st.session_state.data_flows:
                    if flow["source_id"] == component["id"] or flow["target_id"] == component["id"]:
                        flow_threats = [t for t in st.session_state.threats if t["data_flow_id"] == flow["id"]]
                        domain_threats.extend(flow_threats)
                
                if domain_threats:
                    avg_risk_score = sum([
                        {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}[t["risk_level"]] 
                        for t in domain_threats
                    ]) / len(domain_threats)
                    
                    domain_risks.append({
                        "Domain": domain,
                        "Component": component["name"],
                        "Threat Count": len(domain_threats),
                        "Avg Risk Score": avg_risk_score
                    })
            
            if domain_risks:
                domain_risk_df = pd.DataFrame(domain_risks)
                fig_domain_risk = px.scatter(
                    domain_risk_df,
                    x="Threat Count",
                    y="Avg Risk Score",
                    color="Domain",
                    size="Threat Count",
                    hover_name="Component",
                    title="Domain Risk Analysis"
                )
                st.plotly_chart(fig_domain_risk, use_container_width=True)
        
        with col2:
            # STRIDE Category Risk Heatmap
            heatmap = create_threat_heatmap()
            if heatmap:
                st.plotly_chart(heatmap, use_container_width=True)
            
            # Mitigation Coverage Analysis
            if st.session_state.mitigations:
                coverage_data = []
                
                for stride_cat in STRIDE_THREATS.keys():
                    cat_threats = [t for t in st.session_state.threats if t["category"] == stride_cat]
                    mitigated_cat_threats = [
                        t for t in cat_threats 
                        if any(m["threat_id"] == t["id"] for m in st.session_state.mitigations)
                    ]
                    
                    coverage_pct = (len(mitigated_cat_threats) / len(cat_threats) * 100) if cat_threats else 0
                    
                    coverage_data.append({
                        "STRIDE Category": stride_cat,
                        "Total Threats": len(cat_threats),
                        "Mitigated": len(mitigated_cat_threats),
                        "Coverage %": coverage_pct
                    })
                
                coverage_df = pd.DataFrame(coverage_data)
                fig_coverage = px.bar(
                    coverage_df,
                    x="STRIDE Category",
                    y="Coverage %",
                    title="Mitigation Coverage by STRIDE Category",
                    color="Coverage %",
                    color_continuous_scale="RdYlGn"
                )
                st.plotly_chart(fig_coverage, use_container_width=True)
        
        # Risk Timeline and Trends
        st.subheader("Risk Treatment Plan")
        
        if st.session_state.mitigations:
            # Create implementation timeline
            timeline_data = []
            
            # Group controls by implementation phase
            for mitigation in st.session_state.mitigations:
                effort = mitigation["implementation_effort"]
                cost = mitigation["cost"]
                
                # Assign to phases based on effort and cost
                if effort == "Low" and cost in ["Low", "Medium"]:
                    phase = "Phase 1 (0-3 months)"
                    timeline_data.append({
                        "Phase": phase,
                        "Control": mitigation["control_id"],
                        "Threats Addressed": 1,
                        "Risk Reduction": mitigation["effectiveness"] / 100
                    })
                elif effort == "Medium":
                    phase = "Phase 2 (3-9 months)"
                    timeline_data.append({
                        "Phase": phase,
                        "Control": mitigation["control_id"],
                        "Threats Addressed": 1,
                        "Risk Reduction": mitigation["effectiveness"] / 100
                    })
                else:
                    phase = "Phase 3 (9-18 months)"
                    timeline_data.append({
                        "Phase": phase,
                        "Control": mitigation["control_id"],
                        "Threats Addressed": 1,
                        "Risk Reduction": mitigation["effectiveness"] / 100
                    })
            
            if timeline_data:
                timeline_df = pd.DataFrame(timeline_data)
                
                # Aggregate by phase
                phase_summary = timeline_df.groupby("Phase").agg({
                    "Control": "nunique",
                    "Threats Addressed": "sum",
                    "Risk Reduction": "mean"
                }).reset_index()
                
                # Calculate cumulative risk reduction
                phase_summary["Cumulative Risk Reduction"] = phase_summary["Risk Reduction"].cumsum()
                
                fig_timeline = px.bar(
                    phase_summary,
                    x="Phase",
                    y="Control",
                    title="Security Control Implementation Timeline",
                    labels={"Control": "Number of Controls", "Phase": "Implementation Phase"}
                )
                st.plotly_chart(fig_timeline, use_container_width=True)
                
                # Display phase summary table
                st.subheader("Implementation Phase Summary")
                st.dataframe(phase_summary, use_container_width=True)
    
    # Export Report Tab
    elif tab == "📄 Export Report":
        st.header("Export Threat Model Report")
        
        # Report Configuration
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Report Options")
            
            include_sections = st.multiselect(
                "Include Sections",
                [
                    "Executive Summary",
                    "System Architecture", 
                    "Threat Analysis",
                    "Risk Assessment",
                    "Mitigation Plan",
                    "Implementation Roadmap",
                    "Appendices"
                ],
                default=[
                    "Executive Summary",
                    "System Architecture", 
                    "Threat Analysis",
                    "Risk Assessment",
                    "Mitigation Plan"
                ]
            )
            
            report_format = st.selectbox(
                "Report Format",
                ["JSON", "CSV", "Markdown"]
            )
            
            include_diagrams = st.checkbox("Include Diagrams", value=True)
            include_detailed_controls = st.checkbox("Include Detailed Controls", value=True)
        
        with col2:
            st.subheader("Report Preview")
            
            # Generate preview metrics
            st.write("**Report will include:**")
            st.write(f"• {len(st.session_state.components)} System Components")
            st.write(f"• {len(st.session_state.data_flows)} Data Flows")
            st.write(f"• {len(st.session_state.threats)} Identified Threats")
            st.write(f"• {len(set([m['control_id'] for m in st.session_state.mitigations]))} Security Controls")
            
            estimated_pages = len(include_sections) * 2 + len(st.session_state.threats) * 0.1
            st.write(f"• Estimated Length: {estimated_pages:.0f} pages")
        
        # Generate Report
        if st.button("📄 Generate Report", type="primary"):
            if not st.session_state.components:
                st.error("Please add components to generate a report.")
                return
            
            # Prepare report data
            report_data = {
                "metadata": {
                    "report_name": st.session_state.threat_model_name,
                    "generated_date": datetime.now().isoformat(),
                    "version": "1.0",
                    "sections_included": include_sections
                },
                "system_architecture": {
                    "components": st.session_state.components,
                    "data_flows": st.session_state.data_flows
                },
                "threat_analysis": {
                    "threats": st.session_state.threats,
                    "total_threats": len(st.session_state.threats),
                    "threats_by_category": pd.DataFrame(st.session_state.threats)["category"].value_counts().to_dict() if st.session_state.threats else {},
                    "threats_by_risk": pd.DataFrame(st.session_state.threats)["risk_level"].value_counts().to_dict() if st.session_state.threats else {}
                },
                "mitigation_plan": {
                    "mitigations": st.session_state.mitigations,
                    "unique_controls": len(set([m["control_id"] for m in st.session_state.mitigations])),
                    "coverage_analysis": {}
                }
            }
            
            # Format based on selected format
            if report_format == "JSON":
                report_content = json.dumps(report_data, indent=2, default=str)
                file_extension = "json"
                mime_type = "application/json"
            
            elif report_format == "CSV":
                # Create multiple CSV sections
                report_content = "THREAT MODEL REPORT\n"
                report_content += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                
                # Components CSV
                if st.session_state.components:
                    report_content += "COMPONENTS\n"
                    comp_df = pd.DataFrame(st.session_state.components)
                    report_content += comp_df.to_csv(index=False) + "\n"
                
                # Threats CSV
                if st.session_state.threats:
                    report_content += "THREATS\n"
                    threat_df = pd.DataFrame(st.session_state.threats)
                    report_content += threat_df.to_csv(index=False) + "\n"
                
                # Mitigations CSV
                if st.session_state.mitigations:
                    report_content += "MITIGATIONS\n"
                    mit_df = pd.DataFrame(st.session_state.mitigations)
                    report_content += mit_df.to_csv(index=False) + "\n"
                
                file_extension = "csv"
                mime_type = "text/csv"
            
            else:  # Markdown
                report_content = f"# {st.session_state.threat_model_name}\n\n"
                report_content += f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                
                if "Executive Summary" in include_sections:
                    report_content += "## Executive Summary\n\n"
                    report_content += f"This threat model identifies {len(st.session_state.threats)} potential security threats "
                    report_content += f"across {len(st.session_state.components)} system components. "
                    if st.session_state.mitigations:
                        unique_controls = len(set([m["control_id"] for m in st.session_state.mitigations]))
                        report_content += f"A total of {unique_controls} security controls have been recommended "
                        report_content += "to mitigate the identified risks.\n\n"
                
                if "System Architecture" in include_sections:
                    report_content += "## System Architecture\n\n"
                    report_content += "### Components\n\n"
                    for comp in st.session_state.components:
                        report_content += f"- **{comp['name']}** ({comp['type']}) - {comp['description']}\n"
                    report_content += "\n"
                    
                    report_content += "### Data Flows\n\n"
                    for flow in st.session_state.data_flows:
                        source_comp = next((c for c in st.session_state.components if c["id"] == flow["source_id"]), {"name": "Unknown"})
                        target_comp = next((c for c in st.session_state.components if c["id"] == flow["target_id"]), {"name": "Unknown"})
                        report_content += f"- {source_comp['name']} → {target_comp['name']} ({flow['data_type']} via {flow['protocol']})\n"
                    report_content += "\n"
                
                if "Threat Analysis" in include_sections and st.session_state.threats:
                    report_content += "## Threat Analysis\n\n"
                    
                    # Group threats by STRIDE category
                    threats_by_category = {}
                    for threat in st.session_state.threats:
                        category = threat["category"]
                        if category not in threats_by_category:
                            threats_by_category[category] = []
                        threats_by_category[category].append(threat)
                    
                    for category, category_threats in threats_by_category.items():
                        report_content += f"### {category} Threats\n\n"
                        for threat in category_threats:
                            report_content += f"**{threat['description']}** (Risk: {threat['risk_level']})\n\n"
                            report_content += f"{threat['detailed_description']}\n\n"
                            report_content += f"*MITRE ATT&CK Techniques: {', '.join(threat['mitre_techniques'])}*\n\n"
                
                if "Mitigation Plan" in include_sections and st.session_state.mitigations:
                    report_content += "## Recommended Security Controls\n\n"
                    
                    # Group mitigations by domain
                    unique_controls = {}
                    for mitigation in st.session_state.mitigations:
                        control_id = mitigation["control_id"]
                        if control_id not in unique_controls:
                            unique_controls[control_id] = mitigation
                    
                    controls_by_domain = {}
                    for control in unique_controls.values():
                        domain = control["domain"]
                        if domain not in controls_by_domain:
                            controls_by_domain[domain] = []
                        controls_by_domain[domain].append(control)
                    
                    for domain, domain_controls in controls_by_domain.items():
                        report_content += f"### {domain} Domain\n\n"
                        for control in domain_controls:
                            report_content += f"**{control['control_id']}: {control['control_name']}**\n\n"
                            report_content += f"{control['description']}\n\n"
                            report_content += f"- Implementation Effort: {control['implementation_effort']}\n"
                            report_content += f"- Cost: {control['cost']}\n"
                            report_content += f"- Effectiveness: {control['effectiveness']:.1f}%\n\n"
                
                file_extension = "md"
                mime_type = "text/markdown"
            
            # Provide download button
            filename = f"{st.session_state.threat_model_name.replace(' ', '_')}_threat_model.{file_extension}"
            
            st.download_button(
                label=f"📥 Download {report_format} Report",
                data=report_content,
                file_name=filename,
                mime=mime_type,
                type="primary"
            )
            
            st.success(f"Report generated successfully! Click the button above to download your {report_format} report.")
            
            # Show preview
            with st.expander("Preview Report Content"):
                if report_format == "JSON":
                    st.json(report_data)
                else:
                    st.text(report_content[:2000] + "..." if len(report_content) > 2000 else report_content)

if __name__ == "__main__":
    main()
