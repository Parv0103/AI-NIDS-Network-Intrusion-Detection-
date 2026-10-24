# AI-NIDS-Network-Intrusion-Detection-

This is a demonstration, not a working intrusion detection system. It runs on simulated traffic, detects attacks with keyword and regex patterns, and shows hardcoded model performance numbers. No machine learning model is trained or used for detection.

A Streamlit dashboard that shows what a network intrusion detection interface could look like: a live-updating alert feed, charts, heatmaps, a payload tester and CSV export.

What is real and what is a placeholder
Part	Status
Streamlit dashboard (start/stop, alert feed, charts, heatmaps, filters, CSV export)	Real, working UI code
Network traffic	Simulated. PacketSimulator generates random packets: random source IPs, random ports, random choice of destination, and a 40% chance that a packet carries one of a fixed list of example attack payloads (SQL injection, XSS, reverse shell, SYN flood text, and similar). No real packets are captured or read
"Detection"	Regular-expression and keyword matching on the payload text (class BERTDetector in demo.py). A matching pattern returns a fixed confidence value. A payload with no match gets a random confidence between 0.05 and 0.20
DistilBERT	The code tries to load distilbert-base-uncased (untrained, 2 labels) but never uses it for predictions. Despite its name, BERTDetector.predict() is pure pattern matching
Model performance table (Decision Tree, Random Forest, and the other algorithms shown)	Hardcoded placeholder values in the MLModelPerformance class. They are for display only. No model was trained or evaluated, and no dataset is used
Attack signature database	A hand-written list of descriptions and mitigations for display
"Real-time"	The interface refreshes continuously while the simulator runs. It does not process live network traffic

Do not cite any accuracy, precision or recall figure from this dashboard as a measured result.

Features
Start and stop a simulated traffic stream.
Alert feed with attack type, severity and confidence.
Charts and heatmaps: attack types, attacks by hour, severity by attack type, attack-to-attack sequence.
Payload tester: paste text and see whether a pattern matches.
Export alerts and filtered logs to CSV.
Run locally
bash
pip install streamlit pandas numpy plotly
streamlit run demo.py

requirements.txt also lists packages the demo does not use (OpenCV, PyTorch, ultralytics, seaborn, matplotlib) and is saved in UTF-16 encoding. The demo itself imports only Streamlit, pandas, NumPy and Plotly, plus an optional transformers import that is not needed.

Turning this into a real NIDS (roadmap, not implemented)
Capture or load real traffic (for example a CICIDS2017 or NSL-KDD CSV, or live capture with a packet library).
Extract flow features and train a classifier such as Random Forest or gradient boosting.
Evaluate on a held-out test set with precision, recall and F1 per attack class, and report those measured numbers in place of the hardcoded table.
Replace the regex matcher with the trained model, keeping signatures only as a rule-based baseline.
Tech stack

Python, Streamlit, pandas, NumPy, Plotly.
