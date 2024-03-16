import platform
import requests
from packaging import version



def read_antivirus_version():
    # Считывание версии антивируса из текстового файла
    with open(r'C:\Users\NonLo\Desktop\nini\antivirus_version.txt', 'r') as file:
        return file.read().strip()

def check_antivirus_version():
    # Отправка запроса к серверу для проверки версии антивируса
    response = requests.get('http://127.0.0.1:5000/security_rules')
    
    if response.status_code == 200:
        server_data = response.json()
        server_antivirus_version = server_data.get('antivirus_version')  # Получаем версию антивируса из ответа сервера
        if server_antivirus_version:
            print(f"Текущая версия антивируса на сервере: {server_antivirus_version}")

            # Тут вы можете добавить проверку сравнения с установленными правилами
            # например, сравнение server_antivirus_version с минимальной версией из правил

            # Пример:
            min_antivirus_version_rule = "X.Y"  # замените на реальное правило
            if version.parse(server_antivirus_version) >= version.parse(min_antivirus_version_rule):
                print("Версия антивируса соответствует установленному правилу.")
            else:
                print("Версия антивируса не соответствует установленному правилу.")
        else:
            print("В ответе от сервера отсутствует информация о версии антивируса.")
    else:
        print(f"Ошибка при запросе к серверу: {response.status_code}")
        
    current_antivirus_version = read_antivirus_version()
    print(f"Считанная версия антивируса: {current_antivirus_version}")


def check_security_rule(rule):
    # Проверка правила безопасности
    if rule['description'] == 'Устройство должно иметь антивирус версии X.Y или выше':
        min_antivirus_version = rule['min_antivirus_version']
        current_antivirus_version = read_antivirus_version()
        if check_antivirus_version(current_antivirus_version, min_antivirus_version):
            return True
        else:
            return False
    # Другие правила безопасности могут быть добавлены аналогично

def send_security_report(device_id, rule, status):
    # Отправка отчета о соблюдении/несоблюдении правила безопасности на сервер
    payload = {'device_id': device_id, 'rule_id': rule['id'], 'violation': not status}
    response = requests.post('http://127.0.0.1:5000/report_security_rule', json=payload)
    if response.status_code == 200:
        print(f"Отчет о соблюдении правила {rule['description']}: {status} успешно отправлен на сервер")
    else:
        print(f"Ошибка при отправке отчета на сервер: {response.status_code}")

if __name__ == "__main__":
    # Получение правил безопасности от сервера администратора
    response = requests.get('http://127.0.0.1:5000/security_rules')
    security_rules = response.json()



    # Проверка каждого правила безопасности
for rule in security_rules:
    if check_security_rule(rule):
            print(f"Устройство не соблюдает правило: {rule['description']}")
            
    else:
            print(f"Устройство соблюдает правило: {rule['description']}")

            # Отправка отчета на сервер администратора
            send_security_report(device_id=1, rule=rule, status=False)