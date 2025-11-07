import os
import json
import logging
from datetime import datetime
import requests
import hashlib
import hmac
import base64

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SentinelConnector:
    def __init__(self, config_path):
        """Initialize the Sentinel connector with configuration."""
        self.config = self._load_config(config_path)
        self.workspace_id = self.config['sentinel']['workspaceId']
        self.shared_key = self.config['sentinel']['primaryKey']
        self.log_type = 'WazuhSecurityAlerts'

    def _load_config(self, config_path):
        """Load configuration from JSON file."""
        try:
            with open(config_path) as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            raise

    def _build_signature(self, date, content_length, method, content_type, resource):
        """Build the signature for Sentinel API authentication."""
        x_headers = 'x-ms-date:' + date
        string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
        bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
        decoded_key = base64.b64decode(self.shared_key)
        encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest())
        return "SharedKey {}:{}".format(self.workspace_id, encoded_hash.decode())

    def send_alert(self, alert_data):
        """Send an alert to Azure Sentinel."""
        try:
            # Prepare the data
            if isinstance(alert_data, str):
                alert_data = json.loads(alert_data)
            
            # Add timestamp if not present
            if 'timestamp' not in alert_data:
                alert_data['timestamp'] = datetime.utcnow().isoformat()

            # Convert to JSON string
            body = json.dumps(alert_data)
            
            # Build the API request
            method = 'POST'
            content_type = 'application/json'
            resource = '/api/logs'
            rfc1123date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
            content_length = len(body)
            signature = self._build_signature(rfc1123date, content_length, method, content_type, resource)

            uri = 'https://' + self.workspace_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

            headers = {
                'content-type': content_type,
                'Authorization': signature,
                'Log-Type': self.log_type,
                'x-ms-date': rfc1123date
            }

            response = requests.post(uri, data=body, headers=headers)
            
            if response.status_code >= 200 and response.status_code <= 299:
                logger.info(f"Alert sent successfully. Status code: {response.status_code}")
                return True
            else:
                logger.error(f"Error sending alert. Status code: {response.status_code}")
                logger.error(f"Response: {response.text}")
                return False

        except Exception as e:
            logger.error(f"Error sending alert to Sentinel: {e}")
            raise

if __name__ == "__main__":
    # Example usage
    config_path = "../config.json"  # Adjust path as needed
    connector = SentinelConnector(config_path)
    
    # Example alert
    test_alert = {
        "rule_id": "100001",
        "level": 7,
        "description": "Test alert from Wazuh",
        "timestamp": datetime.utcnow().isoformat(),
        "agent_name": "test-agent",
        "event_data": {
            "type": "syscheck",
            "path": "/etc/passwd",
            "action": "modified"
        }
    }
    
    connector.send_alert(test_alert)