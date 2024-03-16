import requests

# URL серверной части
server_url = 'http://127.0.0.1:5000'

def create_security_rule(description, min_antivirus_version):
    data = {'description': description, 'min_antivirus_version': min_antivirus_version}
    response = requests.post(f'{server_url}/create_security_rule', json=data)
    if response.status_code == 200:
        print('Security rule created successfully')

def report_security_rule(device_id, rule_id, violation):
    data = {'device_id': device_id, 'rule_id': rule_id, 'violation': violation}
    response = requests.post(f'{server_url}/report_security_rule', json=data)
    if response.status_code == 200:
        print('Security rule reported successfully')

def get_security_rules():
    response = requests.get(f'{server_url}/security_rules')
    if response.status_code == 200:
        rules = response.json()
        print('Security rules:')
        for rule in rules:
            print(rule)

def check_antivirus_version(device_id, antivirus_version):
    data = {'device_id': device_id, 'antivirus_version': antivirus_version}
    response = requests.post(f'{server_url}/check_antivirus_version', json=data)
    if response.status_code == 200:
        result = response.json()
        print(result)

if __name__ == '__main__':
    # Пример использования функций
    create_security_rule('Antivirus Version Check', '2.0')
    report_security_rule(1, 1, True)
    get_security_rules()
    check_antivirus_version(1, '1.5')