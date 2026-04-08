import requests
import json
import os
from dotenv import load_dotenv

# Module 1: Configuration Loader
# .env file se Slack URL load karta hai taaki security bani rahe[cite: 114].
load_dotenv()
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
print(SLACK_WEBHOOK_URL)

def send_slack_alert(file_name, file_hash, threat_score, status="Sent"):
    """
    Module 14: Alert Formatting Module.
    Formats the threat details into a Slack Block Kit JSON payload.
    """
    
    # Logic for Visual Indicators (As per Synopsis Page 12) 
    if threat_score > 0:
        # Red Circle for critical threats 
        color = "#FF0000" 
        header_text = "🔴 CRITICAL THREAT DETECTED"
        severity = "HIGH"
    else:
        # Green Circle for safe files 
        color = "#2EB67D" 
        header_text = "🟢 FILE SCANNED: SAFE"
        severity = "NONE"

    # Constructing the JSON Payload for Slack [cite: 166, 222]
    payload = {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": header_text
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*File Name:*\n{file_name}"},
                            {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"}
                        ]
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Threat Score:*\n{threat_score}/70"},
                            {"type": "mrkdwn", "text": f"*Status:*\n{status}"}
                        ]
                    },
                    {
                        "type": "context",
                        "elements": [
                            {"type": "mrkdwn", "text": f"*Digital Fingerprint (Hash):* `{file_hash}`"}
                        ]
                    }
                ]
            }
        ]
    }

    try:
        # Module 10: API Connection Manager logic [cite: 146, 148]
        # Sending real-time notification via Slack Webhooks [cite: 53, 54]
        response = requests.post(
            SLACK_WEBHOOK_URL, 
            data=json.dumps(payload),
            headers={'Content-Type': 'application/json'},
            timeout=10 # Handles network timeouts [cite: 149]
        )
        
        if response.status_code == 200:
            print(f"[+] Alert sent to Slack for {file_name}")
            return True
        else:
            print(f"[!] Slack API Error: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"[!] Error in Notification Module: {e}")
        return False

# Manual Testing (Sir ko dikhane ke liye useful hai)
if __name__ == "__main__":
    # Fake data for testing
    print("Testing Notification System...")
    send_slack_alert("malware_test.exe", "e1102a9099309995167571f541178657", 55)