# Phishing Detection Engine



Cybersecurity-focused phishing detection platform built with Python and Flask.



!\[Dashboard Preview](phishing-preview.png)



\---



\## 📌 About The Project



Phishing Detection Engine is a cybersecurity laboratory project designed to identify suspicious URLs using heuristic-based analysis techniques.



The platform evaluates multiple phishing indicators including:



\* Suspicious keywords

\* Risky top-level domains (TLDs)

\* Typosquatting attempts

\* Excessive hyphen usage

\* HTTP instead of HTTPS

\* Brand impersonation patterns



Each indicator contributes to a weighted risk score, generating classifications such as Safe, Suspicious, Dangerous, or Critical.







\---



\## 🚀 Features



\* Real-time URL analysis

\* Weighted phishing scoring system

\* Suspicious keyword detection

\* Typosquatting detection

\* Brand spoofing detection

\* TLD reputation analysis

\* HTTP security validation

\* Hyphen abuse detection

\* Risk classification engine

\* Detailed alert reporting

\* Modern Flask dashboard



\---



\## 🔬 Detection Rules



The engine currently evaluates:



| Indicator           | Description                                        |

| ------------------- | -------------------------------------------------- |

| Suspicious Keywords | Login, verify, update, banking, password, etc.     |

| Risky TLDs          | .xyz, .tk, .ml and other frequently abused domains |

| Typosquatting       | Brand imitation using lookalike characters         |

| Brand Spoofing      | Attempts to mimic well-known organizations         |

| HTTP Usage          | Lack of encrypted HTTPS connection                 |

| Excessive Hyphens   | Common phishing URL obfuscation technique          |



\---



\## 📈 Example Analysis



Example URL:



http://secure-login-account-update-verify-security.xyz



Detection Result:



\* Critical Risk Score

\* Suspicious Keywords Detected

\* Risky TLD Detected

\* HTTP Usage Detected

\* Excessive Hyphen Usage Detected



\---



\## 🛠️ Technology Stack



\* Python

\* Flask

\* HTML5

\* CSS3

\* JavaScript



\---



\## 📦 Installation



```bash

git clone https://github.com/nikolas-reges/phishing-detection-engine.git



cd phishing-detection-engine



pip install flask



python app.py

```



\---



\## 🎯 Learning Objectives



This project was built to practice:



\* Secure coding concepts

\* Cybersecurity detection logic

\* Threat analysis workflows

\* Flask web development

\* Python backend development

\* Security tool prototyping



\---



\## 👨‍💻 Author



Nikolas Reges



Cybersecurity student building practical security projects and portfolio applications.



