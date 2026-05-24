🛡️ L.E.X.I.S.

Log-based Evaluation & Cyber Threat Intelligence System

A unified AI-powered Cyber Security Operations Center (SOC) workspace combining threat intelligence, intrusion detection, and phishing analysis into a single modular security ecosystem.

🚀 Overview

L.E.X.I.S. is a multi-project cybersecurity workspace designed to simulate how modern SOC environments detect, analyze, and respond to cyber threats in real time.

This repository integrates three independent AI/ML-powered security systems:



🔍 AI Threat Intelligence Dashboard

🌐 Network Intrusion Detection System (NIDS)

⚠️ Malicious URL & Phishing Detection Engine

Each module is fully deployable, modular, and production-oriented.

🗂️ Workspace Structure

L.E.X.I.S.

│

├── AI-Threat-Intelligence-System/

│   ├── app.py

│   ├── chatbot.py

│   ├── *.pkl

│   └── requirements.txt

│

├── Network-IDS/

│   ├── app.py

│   ├── step3_ml_model.py

│   ├── network_logs_sample.csv

│   └── requirements.txt

│

└── Beginner-Malicious-URL/

    ├── app.py

    └── requirements.txt

🧠 Project 1 — AI Threat Intelligence System

📌 Description

A centralized SOC dashboard powered by machine learning and real-time threat analytics. The platform combines malware classification, phishing URL analysis, and network monitoring into one intelligent interface.

🌐 Live Deployment

🔗 https://ai-threat-intelli-sys.streamlit.app/

⚙️ Tech Stack

ComponentTechnologyFrontendStreamlitML FrameworkScikit-LearnData ProcessingPandas, NumPyModel StorageJoblib / PickleAssistant EngineCustom AI Chatbot✨ Features

Unified multi-tab SOC dashboard

AI-powered cybersecurity assistant

Real-time simulated threat monitoring

Malware family prediction engine

URL threat intelligence scanning

Interactive analytics visualizations

✅ Advantages

Fast inference speeds

Modular architecture

Lightweight deployment

Unified security workflow

⚠️ Limitations

Depends heavily on serialized model weights

Requires retraining for evolving threats

Limited scalability without cloud synchronization

🌐 Project 2 — Network Intrusion Detection System (NIDS)

📌 Description

An ML-driven intrusion detection engine trained on the CICIDS2017 dataset to classify malicious network traffic patterns including DDoS attacks, port scans, brute-force attempts, and web exploits.

🌐 Live Deployment

🔗 https://netwrk-ids.streamlit.app/

⚙️ Tech Stack

ComponentTechnologyML ModelsRandom Forest, Gradient BoostingData HandlingPandasVisualizationStreamlitDatasetCICIDS2017✨ Features

Multi-class intrusion classification

Real-time network log simulation

Attack traffic categorization

Modular standalone architecture

Threat analytics dashboard

🚨 Detectable Threats

DDoS Attacks

Port Scans

Brute Force Attacks

Web Attacks

Botnet Activity

Suspicious Traffic Patterns

✅ Advantages

High classification accuracy

Lightweight deployment

Modular execution

Edge-device friendly

⚠️ Limitations

Training is computationally expensive

Requires feature extraction preprocessing

Performance depends on dataset quality

⚠️ Project 3 — Malicious URL & Phishing Detector

📌 Description

A phishing detection engine that evaluates URL structures using lexical analysis and heuristic-based feature extraction to identify malicious websites without visiting them.

🌐 Live Deployment

🔗 https://mal-url-proj.streamlit.app/

⚙️ Tech Stack

ComponentTechnologyFrontendStreamlitFeature ExtractionRegex + URL ParsingML AlgorithmsLogistic Regression, Decision TreesProcessingPython✨ Features

Instant URL threat scoring

Lexical phishing detection

HTTPS protocol validation

IP-based URL detection

Secure offline analysis

Lightweight prediction engine

✅ Advantages

No connection to suspicious domains required

Extremely fast analysis

Safe local execution

Minimal system requirements

⚠️ Limitations

Cannot detect DOM-based obfuscation

Limited against advanced JavaScript redirects

Purely structure-based analysis

🛠️ Installation & Local Setup

1️⃣ Clone Repository

git clone https://github.com/Hitendra-Cyber/L.E.X.I.S..git

cd L.E.X.I.S.

▶️ Run Project 1 — AI Threat Intelligence System

cd AI-Threat-Intelligence-System



pip install -r requirements.txt



streamlit run app.py

▶️ Run Project 2 — Network IDS

cd ../Network-IDS



pip install -r requirements.txt



streamlit run app.py

▶️ Run Project 3 — Malicious URL Scanner

cd ../Beginner-Malicious-URL



pip install -r requirements.txt



streamlit run app.py

📊 Core Learning Outcomes

This workspace demonstrates practical implementation of:



Machine Learning for Cybersecurity

Threat Intelligence Pipelines

Network Traffic Classification

Phishing Detection Systems

SOC Dashboard Engineering

Streamlit-based Security Applications

Modular AI System Design

🔮 Future Improvements

Real-time packet sniffing integration

SIEM connectivity

Cloud-native deployment

Threat feed API integration

Deep Learning malware analysis

Live SOC alerting system

Role-based authentication

👨‍💻 Author

Hitendra Singh Panwar

Cybersecurity • AI/ML • Threat Intelligence • SOC Engineering

📄 License

This project is licensed under the MIT License.

⭐ Support

If you found this project useful:



⭐ Star the repository

🍴 Fork the project

🛡️ Contribute to future improvements

📤 Git Push Commands

git add .

git commit -m "Docs: Revamp README with production-ready GitHub formatting"

git push origin main
