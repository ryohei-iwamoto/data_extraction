import requests
import json

def send_request(method, url, headers, payload):
    try:
        response = getattr(requests, method.lower(), requests.get)(url, headers=headers, data=payload)
        return response.text
    except Exception as e:
        return str(e)

def generate_code(method, url, headers, payload):
    return f'''
import requests

url = "{url}"
headers = {json.dumps(headers, indent=4)}
payload = {json.dumps(payload, indent=4)}

response = requests.{method.lower()}(url, headers=headers, params=payload)
print(response.text)
'''
