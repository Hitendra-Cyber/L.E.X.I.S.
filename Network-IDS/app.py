import streamlit as st
import pandas as pd
import plotly.express as px
import pickle
import numpy as np
import sqlite3
import time
import os  # Added to handle paths dynamically

# Set up page styling
st.set_page_config(page_title="Network Intrusion Detection System", layout="wide")
st.title("🛡️ Network Traffic Intrusion Detection Dashboard")
st.markdown("Monitor network logs, analyze traffic anomalies via SQL, and predict cyber threats using Machine Learning.")

# ----------------------------------------------------------------------------------
# DYNAMIC PATH BINDING FOR CLOUD HOSTING
# ----------------------------------------------------------------------------------
# Automatically discover the exact directory where this specific app.py file lives
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

ids_model_path = os.path.join(BASE_DIR, "ids_model.pkl")
model_features_path = os.path.join(BASE_DIR, "model_features.pkl")
default_data_path = os.path.join(BASE_DIR, "network_logs_sample.csv")

# 1. Load models and feature lists safely
try:
    with open(ids_model_path, "rb") as f:
        model = pickle.load(f)
    with open(model_features_path, "rb") as f:
        model_features = pickle.load(f)
    st.sidebar.success("🤖 ML Model Loaded Successfully!")
except Exception as e:
    st.sidebar.error(f"❌ Error loading ML model files: {e}")
    st.stop()

# ----------------------------------------------------------------------------------
# FILE UPLOAD & GLOBAL THREAT SCANNING ENGINE
# ----------------------------------------------------------------------------------
st.sidebar.header("📁 Data Source Selection")
uploaded_file = st.sidebar.file_uploader("Upload custom network logs (CSV format):", type=["csv"])

@st.cache_data
def load_default_data():
    return pd.read_csv(default_data_path)  # Updated to use dynamic absolute file path

# Initialize global status variables
is_breach_detected = False
attack_types_found = []
has_user_uploaded_file = False  # Track if a file was uploaded manually

# Determine data stream and execute automatic scanning logic
if uploaded_file is not None:
    has_user_uploaded_file = True  # Set to True only when a file is dropped in
    try:
        df = pd.read_csv(uploaded_file)
        st.sidebar.success(f"🎯 Successfully loaded uploaded file: {uploaded_file.name}")
        
        # ------------------------------------------------------------------------------
        # STEP 1: THE PROCESSING STATE (The "Hold On" Moment)
        # ------------------------------------------------------------------------------
        with st.spinner(f"⚡ Scanning {len(df):,} network packets for anomalies and threat signatures..."):
            time.sleep(1.5)  
            
            # Prepare data to match your ML model features exactly
            scan_df = df.drop(columns=['Label']) if 'Label' in df.columns else df.copy()
            
            # Align features with training constraints
            input_features = pd.DataFrame(0, index=np.arange(len(scan_df)), columns=model_features)
            for col in model_features:
                if col in scan_df.columns:
                    input_features[col] = scan_df[col].values
            
            input_features.replace([np.inf, -np.inf], np.nan, inplace=True)
            input_features.fillna(0, inplace=True)
            
            # Run background predictions on the whole file
            predictions = model.predict(input_features)
            
            # Check if any rows are predicted as malicious threats
            unique_predictions = np.unique(predictions)
            attack_types_found = [p for p in unique_predictions if p != "BENIGN"]
            
            if len(attack_types_found) > 0:
                is_breach_detected = True
                
    except Exception as e:
        st.sidebar.error(f"❌ Error reading uploaded file: {e}")
        df = load_default_data()
else:
    df = load_default_data()
    st.sidebar.info("ℹ️ Using default 'network_logs_sample.csv' data.")

# ------------------------------------------------------------------------------
# STEP 2 & 3: THE VERDICT (Only displays if a file was uploaded!)
# ------------------------------------------------------------------------------
st.markdown("---")

if has_user_uploaded_file:
    if not is_breach_detected:
        # Condition A: Secure State
        st.success("🟢 STATUS: SECURE")
        st.subheader("Everything looks good!")
        st.markdown("We analyzed your network logs and found no signs of malicious activity. Your system appears safe.")
    else:
        # Condition B: Breach State
        st.error("🔴 STATUS: POSSIBLE BREACH DETECTED")
        st.subheader("Warning: Urgent Security Risk")
        st.markdown(f"**Warning: We detected highly suspicious activity in your logs matching known attack variants:** `{', '.join(attack_types_found)}`. **There is a potential security threat that requires immediate attention.**")
else:
    # Default Welcome state when no file is uploaded yet
    st.info("👋 Welcome! Please upload a custom network log CSV file in the sidebar to run a live security breach scan.")

st.markdown("---")

# Sidebar Navigation Menu
menu = st.sidebar.radio("Navigate Dashboard", ["Traffic Overview", "SQL Security Analytics", "Live Threat Predictor"])

# ----------------------------------------------------------------------------------
# SCREEN 1: TRAFFIC OVERVIEW 
# ----------------------------------------------------------------------------------
if menu == "Traffic Overview":
    st.header("📊 Traffic Overview & Statistics")
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Logs Analyzed", f"{len(df):,}")
    
    if 'Label' in df.columns:
        attack_count = len(df[df['Label'] != 'BENIGN'])
        col2.metric("Total Anomalies/Attacks Detected", f"{attack_count:,}", delta=f"{attack_count/len(df)*100:.1f}% of total", delta_color="inverse")
        col3.metric("Safe (Benign) Traffic Logs", f"{len(df[df['Label'] == 'BENIGN']):,}")
    else:
        col2.metric("Total Anomalies/Attacks", "N/A", help="Uploaded file has no ground-truth 'Label' column.")
        col3.metric("Safe (Benign) Traffic", "N/A")
    
    st.markdown("---")
    
    # Visual Proof Layout adjustment based on condition
    if has_user_uploaded_file and not is_breach_detected:
        st.subheader("📉 Network Traffic Behavior (Normal Status)")
        st.info("System health is operating smoothly. Below is the volume profile across your historical window:")
        fig = px.line(df.head(200), y='Flow_Duration' if 'Flow_Duration' in df.columns else df.columns[0], title="Steady Network Transmission Baseline")
        st.plotly_chart(fig, use_container_width=True)
    elif has_user_uploaded_file and is_breach_detected:
        st.subheader("🚨 Threat Map Profile (Breach Status)")
        st.warning("Immediate visual profile of the anomalies discovered by the Machine Learning Pipeline:")
        
        if 'Label' in df.columns:
            label_counts = df['Label'].value_counts().reset_index()
            label_counts.columns = ['Identified Vector / Attack Fingerprint', 'Incident Count']
            fig = px.bar(label_counts, x='Identified Vector / Attack Fingerprint', y='Incident Count', color='Identified Vector / Attack Fingerprint', text_auto=True, log_y=True)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("The file uploaded doesn't have explicit category columns. Here are the suspicious data streams pinpointed by the ML Engine:")
            st.dataframe(df.head(20), use_container_width=True)
    else:
        # Default view before upload
        st.subheader("📋 Dataset Preview")
        st.markdown("Currently displaying a preview of the default historical network log database:")
        st.dataframe(df.head(15), use_container_width=True)

# ----------------------------------------------------------------------------------
# SCREEN 2: SQL SECURITY ANALYTICS
# ----------------------------------------------------------------------------------
elif menu == "SQL Security Analytics":
    st.header("🗄️ SQL Threat Hunting Queries")
    st.markdown("Running database engine scans on the current active data stream to flag suspicious traffic properties.")
    
    if 'Protocol' in df.columns:
        sql_df = df.copy()
        sql_df.columns = [c.strip().replace(' ', '_').replace('/', '_').replace('-', '_') for c in sql_df.columns]
        conn = sqlite3.connect(':memory:')
        sql_df.to_sql('network_traffic', conn, index=False, if_exists='replace')
        
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Query 1: Protocol Activity Distribution")
            label_select = ", Label" if 'Label' in sql_df.columns else ""
            group_select = ", Label" if 'Label' in sql_df.columns else ""
            
            query_proto = f"SELECT Protocol {label_select}, COUNT(*) as Count FROM network_traffic GROUP BY Protocol {group_select} ORDER BY Count DESC LIMIT 10;"
            res_proto = pd.read_sql_query(query_proto, conn)
            st.dataframe(res_proto, use_container_width=True)
            
            fig_proto = px.pie(res_proto, values='Count', names='Protocol', title='Protocol Volume Footprint (6=TCP, 17=UDP)')
            st.plotly_chart(fig_proto, use_container_width=True)
            
        with col2:
            st.subheader("Query 2: Traffic Timing Outliers")
            duration_col = 'Flow_Duration' if 'Flow_Duration' in sql_df.columns else sql_df.columns[1]
            
            query_dur = f"SELECT {duration_col}, COUNT(*) as Connections FROM network_traffic WHERE {duration_col} > 1000000 GROUP BY {duration_col} ORDER BY Connections DESC LIMIT 10;"
            res_dur = pd.read_sql_query(query_dur, conn)
            st.dataframe(res_dur, use_container_width=True)
            
            fig_dur = px.histogram(res_dur, x=duration_col, y='Connections', title='Long Duration Network Flows (>1s)')
            st.plotly_chart(fig_dur, use_container_width=True)
        
        conn.close()
    else:
        st.error("❌ The uploaded dataset schema does not match. It must contain at least a 'Protocol' column to use SQL queries.")

# ----------------------------------------------------------------------------------
# SCREEN 3: LIVE THREAT PREDICTOR
# ----------------------------------------------------------------------------------
elif menu == "Live Threat Predictor":
    st.header("🤖 Live Random Forest Threat Detection")
    st.markdown("Pick any packet or log entry from your uploaded stream below to run an evaluation through your pipeline.")
    
    row_idx = st.number_input("Select a Network Log Row Index to Inspect:", min_value=0, max_value=len(df)-1, value=0)
    
    selected_row = df.iloc[[row_idx]]
    has_label = 'Label' in df.columns
    features_df = selected_row.drop(columns=['Label']) if has_label else selected_row.copy()
    
    st.subheader("🔬 Extracted Feature Vector for Model Input:")
    st.dataframe(features_df, use_container_width=True)
    
    input_features = pd.DataFrame(0, index=[0], columns=model_features)
    for col in model_features:
        if col in features_df.columns:
            input_features[col] = features_df[col].values[0]
            
    input_features.replace([np.inf, -np.inf], np.nan, inplace=True)
    input_features.fillna(0, inplace=True)
    
    prediction = model.predict(input_features)[0]
    
    st.markdown("---")
    st.subheader("🔮 Machine Learning Verdict:")
    
    col1, col2 = st.columns(2)
    with col1:
        if prediction == "BENIGN":
            st.success(f"🟢 MODEL VERDICT: **{prediction}** (Normal Network Activity)")
        else:
            st.error(f"🚨 MODEL VERDICT: **{prediction}** (Malicious Activity Blocked!)")
            
    with col2:
        if has_label:
            actual_label = selected_row['Label'].values[0]
            st.info(f"🏷️ File's Ground-Truth Label: **{actual_label}**")
        else:
            st.info("🏷️ File's Ground-Truth Label: **Not Provided in Uploaded CSV**")