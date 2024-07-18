import requests
import os
import json

GITHUB_TOKEN = os.getenv('HUB_TOKEN')  # Ensure to use HUB_TOKEN
REPO_OWNER = 'viek9306'  # Your GitHub username
REPO_NAME = 'vulnerable-code-repo'  # Your repository name
SEVERITY = 'high'

if not GITHUB_TOKEN:
    raise ValueError("HUB_TOKEN environment variable is not set")

headers = {
    'Authorization': f'token {GITHUB_TOKEN}',
    'Accept': 'application/vnd.github.v3+json'
}

url = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/code-scanning/alerts'

response = requests.get(url, headers=headers)

# Check for HTTP errors
if response.status_code != 200:
    print(f"Error fetching alerts: {response.status_code}")
    print(response.text)
    response.raise_for_status()

# Parse the JSON response
try:
    alerts = response.json()
except ValueError as e:
    print("Error parsing JSON response:", e)
    print(response.text)
    raise

# Save alerts to a file
with open('alerts.json', 'w') as f:
    json.dump(alerts, f, indent=2)

print("Fetched alerts:", alerts)

# Filter high severity alerts
high_alerts = [alert for alert in alerts if alert['rule']['severity'] == SEVERITY]

# Sample CWE data for demonstration purposes
cwe_data = {
    'CWE-79': 'High',
    'CWE-89': 'Medium',
    # Add more CWE data as needed
}

print("Vulnerabilities with severity High and 'Likelihood of exploitability' High:")
for alert in high_alerts:
    cwe_id = alert['rule']['tags'][0]
    likelihood = cwe_data.get(cwe_id, 'Unknown')
    if likelihood is None:
        likelihood = "Unknown"
    if likelihood == 'High':
        print(f"- {alert['rule']['description']} (CWE ID: {cwe_id}, Likelihood: {likelihood})")
