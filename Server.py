from flask import Flask, jsonify, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

app = Flask(__name__)

# Конфигурация базы данных
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///security_rules.db'
app.config['SECRET_KEY'] = 'your_secret_key_here'
db = SQLAlchemy(app)


# Определение моделей
class SecurityRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(200), nullable=False)
    min_antivirus_version = db.Column(db.String(20), nullable=False)

class SecurityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, nullable=False)
    rule_id = db.Column(db.Integer, nullable=False)
    violation = db.Column(db.Boolean, nullable=False)

class RuleTriggeredDevices(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, nullable=False)
    rule_id = db.Column(db.Integer, nullable=False)
    violation = db.Column(db.Boolean, nullable=False)

# Создание объекта администратора
admin = Admin(app, name='Security System Admin Panel', template_mode='bootstrap3')
# Добавление моделей в администраторскую панель
admin.add_view(ModelView(SecurityRule, db.session))
admin.add_view(ModelView(SecurityLog, db.session))
admin.add_view(ModelView(RuleTriggeredDevices, db.session))

def read_antivirus_version():
    # Считывание версии антивируса из текстового файла
    with open(r'C:\Users\NonLo\Desktop\nini\antivirus_version.txt', 'r') as file:
        return file.read().strip()
    

@app.route('/antivirus_version', methods=['GET'])
def get_antivirus_version():
    # Получение текущей версии антивируса
    antivirus_version = read_antivirus_version()
    return jsonify({'antivirus_version': antivirus_version})


# Маршруты
@app.route('/dashboard_info', methods=['GET'])
def dashboard_info():
    triggered_rules = RuleTriggeredDevices.query.all()
    dashboard_data = [{'device_id': rule.device_id, 'rule_id': rule.rule_id, 'violation': rule.violation} for rule in triggered_rules]
    return jsonify(dashboard_data)

@app.route('/create_security_rule', methods=['POST'])
def create_security_rule():
    data = request.get_json()
    try:
        new_rule = SecurityRule(description=data['description'], min_antivirus_version=data['min_antivirus_version'])
        db.session.add(new_rule)
        db.session.commit()
        return jsonify({'message': 'Rule created successfully'})
    except Exception as e:
        db.session.rollback()
        abort(500, f'Error: {str(e)}')

@app.route('/report_security_rule', methods=['POST'])
def report_security_rule():
    data = request.get_json()
    try:
        new_log = SecurityLog(device_id=data['device_id'], rule_id=data['rule_id'], violation=data['violation'])
        db.session.add(new_log)
        db.session.commit()
        return jsonify({'message': 'Log added successfully', 'violation': data['violation']})
    except Exception as e:
        db.session.rollback()
        abort(500, f'Error: {str(e)}')

@app.route('/security_rules', methods=['GET'])
def get_security_rules():
    rules = SecurityRule.query.all()
    return jsonify([{'id': rule.id, 'description': rule.description, 'min_antivirus_version': rule.min_antivirus_version} for rule in rules])

@app.route('/check_antivirus_version', methods=['POST'])
def check_antivirus_version():
    data = request.get_json()
    device_id = data['device_id']
    antivirus_version = data['antivirus_version']
    rule = SecurityRule.query.filter_by(description='Antivirus Version Check').first()
    if rule and antivirus_version < rule.min_antivirus_version:
        new_log = SecurityLog(device_id=device_id, rule_id=rule.id, violation=True)
        db.session.add(new_log)
        db.session.commit()
        return jsonify({'status': 'Violation reported'})
    else:
        new_log = SecurityLog(device_id=device_id, rule_id=rule.id, violation=False)
        db.session.add(new_log)
        db.session.commit()
        return jsonify({'status': 'Rule complied with'})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

@app.route('/antivirus_rule_status', methods=['GET'])
def antivirus_rule_status():
    # Получаем все записи из таблицы с информацией о сработанных правилах антивируса
    triggered_antivirus_rules = RuleTriggeredDevices.query.filter_by(rule_id=1).all()

    # Создаем список для хранения информации об устройствах, где сработали правила
    triggered_devices = []

    # Создаем список для хранения информации об устройствах, где не сработали правила
    non_triggered_devices = []

    # Проходимся по записям и разделяем их по категориям
    for record in triggered_antivirus_rules:
        device_info = {'device_id': record.device_id, 'violation': record.violation}
        if record.violation:
            triggered_devices.append(device_info)
        else:
            non_triggered_devices.append(device_info)

    # Возвращаем информацию об устройствах в формате JSON
    return jsonify({'triggered_devices': triggered_devices, 'non_triggered_devices': non_triggered_devices})