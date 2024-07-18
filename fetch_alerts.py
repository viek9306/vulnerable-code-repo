import requests
import os

GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
REPO_OWNER = 'your_username'
REPO_NAME = 'vulnerable-code-repo'
SEVERITY = 'high'

headers = {
    'Authorization': f'token {GITHUB_TOKEN}',
    'Accept': 'application/vnd.github.v3+json'
}

url = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/code-scanning/alerts'

response = requests.get(url, headers=headers)
alerts = response.json()

high_alerts = [alert for alert in alerts if alert['rule']['severity'] == SEVERITY]

# Sample CWE data for demonstration purposes
cwe_data = {
    'CWE-79': 'High',
    'CWE-89': 'Medium',
    # Add more CWE data as needed
}

print("Vulnerabilities with severity High and 'Likelihood of exploitability' High:")
for alert in high_alerts:
    cwe_id = alert['rule']['tags'][0]  # Example way to get CWE ID
    likelihood = cwe_data.get(cwe_id, 'Unknown')
    if likelihood == 'High':
        print(f"- {alert['rule']['description']} (CWE ID: {cwe_id}, Likelihood: {likelihood})")
