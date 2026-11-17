 # PhishGuard – Cybersecurity Threat Detection System

## Project Overview
PhishGuard is a Python-based cybersecurity application developed using Streamlit. It helps users identify common suspicious indicators in URLs and email messages.

The system analyzes user input, calculates a risk score, classifies the risk level, and stores scan history for future analysis.

## Features

- URL Scanner
- Email Phishing Detector
- Risk Score Calculation
- High, Medium and Low Risk Classification
- Security Analytics Dashboard
- Scan History Management
- Search and Filter Options
- Downloadable Scan Reports
- SQLite Database Integration

## Technologies Used

- Python
- Streamlit
- SQLite
- Pandas
- Plotly

## Project Structure

```text
PhishGuard/
├── app.py
├── database.py
├── url_scanner.py
├── email_detector.py
├── dashboard.py
├── requirements.txt
└── database/
	 └── scans.db
```

## Installation

1. Clone or download the project.
2. Open the project folder in VS Code.
3. Install the required libraries:

	```bash
	pip install -r requirements.txt
	```

4. Run the application:

	```bash
	streamlit run app.py
	```

## Working

1. The user enters a URL or email content.
2. The system checks for predefined suspicious indicators.
3. A risk score is calculated.
4. The application displays the risk level and analysis.
5. Scan details are stored in the SQLite database.
6. Users can view previous scans in the dashboard.

## Limitations

- The detection system uses predefined rules and keywords.
- It does not connect to live threat intelligence databases.
- Risk scores are indicators, not confirmed malware or phishing verdicts.

## Future Scope

- Integration with VirusTotal or other threat intelligence APIs.
- Machine learning-based phishing detection.
- Real-time threat monitoring.
- Advanced email header analysis.
- User authentication and access control.

## Developed By

Kirna Kumari  
B.Tech CSE (Internet of Things)
