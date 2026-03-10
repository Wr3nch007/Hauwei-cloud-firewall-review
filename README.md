# Huawei Cloud Firewall Review Tool

Automated Firewall Rule Review Tool for analyzing firewall configuration files and generating a security action tracker.

## Features

- Upload firewall configuration Excel file
- Detect insecure firewall rules
- Severity classification
- Security recommendations
- Compliance references
- Downloadable action tracker

## Vulnerability Checks

- Any-to-Any rules
- Internet exposed services
- Sensitive service exposure (SSH, RDP, FTP, Telnet)
- Overly permissive ports
- Missing rule descriptions

## Technologies Used

- Python
- Flask
- Pandas
- HTML/CSS

## Installation

Install dependencies:
pip install -r requirements.txt

## Run the Application
python app.py

## Open Browser:
http://127.0.0.1:5000


## Usage

1. Upload firewall configuration Excel
2. Click **Analyze Firewall**
3. Review findings
4. Download **Action Tracker**

## Author

AK
