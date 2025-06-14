import os
import time
import redis #Хранилище для токенов и брокер сообщений для Celery
import jwt #Для авторизации пользователей
import bcrypt #Для хеширования паролей
from datetime import datetime, timedelta
from flask import Flask, request, jsonify #Веб-фреймворк для создания REST API
from flask_sqlalchemy import SQLAlchemy #для работы с базой данных PostgreSQL и управления миграциями
from flask_migrate import Migrate
from celery import Celery #Система для асинхронной обработки задач

app = Flask(__name__)
# os.getenv позволяет брать значение из переменной окружения DATABASE_URL, а если
# она не задана, используется строка по умолчанию
# Формат: postgresql://<пользователь>:<пароль>@<хост>:<порт>/<имя_базы>
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://postgres:postgres@db:5432/premiumcars')
# Отключаем отслеживание модификаций объектов SQLAlchemy
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Задаём секретный ключ для подписи JWT-токенов
# Используется значение из переменной окружения JWT_SECRET_KEY или строка по умолчанию
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'super-secret-key')
app.config['TOKEN_TTL'] = timedelta(minutes=15)
app.config['REDIS_URL'] = os.getenv('REDIS_URL', 'redis://redis:6379/0')
# Задаём URL брокера сообщений для Celery
# Celery использует Redis для передачи задач между Flask-приложением и worker’ом
app.config['CELERY_BROKER_URL'] = os.getenv('CELERY_BROKER_URL', 'redis://redis:6379/0')
app.config['CELERY_RESULT_BACKEND'] = os.getenv('CELERY_RESULT_BACKEND', 'redis://redis:6379/0')


db = SQLAlchemy(app)
migrate = Migrate(app, db)
redis_client = redis.Redis.from_url(app.config['REDIS_URL'])
celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'])
celery.conf.update(app.config)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='Pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class RequestState(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('request.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Утилиты
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(hashed_password, password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

#Создаёт токен, содержащий имя пользователя и срок действия (15 минут), подписывает
# его секретным ключом
def generate_jwt(username):
    return jwt.encode({'username': username, 'exp': datetime.utcnow() + app.config['TOKEN_TTL']},
                      app.config['JWT_SECRET_KEY'], algorithm='HS256')
# Пытается декодировать токен, используя секретный ключ возвращает None, если токен недействителен или истёк
def parse_jwt(token):
    try:
        return jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None
# Сохраняет токен как ключ с значением "valid" и устанавливает TTL (15 минут)
def save_token(token):
    redis_client.setex(token, app.config['TOKEN_TTL'], 'valid')
# Возвращает True, если токен существует, иначе False
def token_exists(token):
    return redis_client.exists(token)
# Продлевает TTL токена до 15 минут, реализуя механизм "разогрева" кэша
def refresh_token_ttl(token):
    redis_client.expire(token, app.config['TOKEN_TTL'])

#При каждом запросе к защищённым endpoint’ам
# (/submit, /request/<id>/status, /request/<id>/state)
# middleware проверяет наличие токена в заголовке Authorization
#Если токен валиден (существует в Redis и не истёк),
# вызывается функция refresh_token_ttl для обновления TTL токена на 15 минут
def auth_required(f):
    # Внутренняя функция-обёртка, которая выполняет проверку токена перед вызовом эндпоинта
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'The token is missing'}), 401
        payload = parse_jwt(token)
        if not payload or not token_exists(token):
            return jsonify({'error': 'Invalid or expired token'}), 401
        refresh_token_ttl(token)
        # Добавляем имя пользователя из токена в объект request для использования в эндпоинте
        request.username = payload['username']
        return f(*args, **kwargs)

    # Устанавливаем имя обёртки, чтобы избежать конфликтов при регистрации маршрутов Flask
    wrapper.__name__ = f.__name__

    return wrapper


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Incorrect data'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'The username is already taken'}), 400
    hashed_password = hash_password(password)
    user = User(username=username, password=hashed_password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'Registration is successful'}), 200
@app.route('/')
def index():
    return "Welcome to the Premium Cars App!", 200
from flask import send_from_directory

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(app.static_folder, 'favicon.png')
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if not user or not check_password(user.password, password):
        return jsonify({'error': 'Invalid credentials'}), 401
    token = generate_jwt(username)
    save_token(token)
    return jsonify({'token': token}), 200

@app.route('/submit', methods=['POST'])
@auth_required
def submit_request():
    user = User.query.filter_by(username=request.username).first()
    request_obj = Request(user_id=user.id)
    db.session.add(request_obj)
    db.session.commit()
    process_request.delay(request_obj.id)
    return jsonify({'message': 'The application has been submitted', 'request_id': request_obj.id}), 200

@app.route('/request/<int:request_id>/status', methods=['GET'])
@auth_required
def get_request_status(request_id):
    user = User.query.filter_by(username=request.username).first()
    request_obj = Request.query.filter_by(id=request_id, user_id=user.id).first()
    if not request_obj:
        return jsonify({'error': 'The application was not found'}), 404
    return jsonify({'status': request_obj.status}), 200

# @app.route('/request/<int:request_id>/state', methods=['POST'])
# @auth_required
# def get_request_state_at_time(request_id):
#     user = User.query.filter_by(username=request.username).first()
#     request_obj = Request.query.filter_by(id=request_id, user_id=user.id).first()
#     if not request_obj:
#         return jsonify({'error': 'The application was not found'}), 404
#     data = request.get_json()
#     timestamp = data.get('timestamp')
#     if not timestamp:
#         return jsonify({'error': 'A timestamp is required'}), 400
#     try:
#         timestamp = datetime.fromisoformat(timestamp)
#     except ValueError:
#         return jsonify({'error': 'Invalid timestamp format'}), 400
#     state = RequestState.query.filter(
#         RequestState.request_id == request_id,
#         RequestState.timestamp <= timestamp
#     ).order_by(RequestState.timestamp.desc()).first()
#     if not state:
#         return jsonify({'error': 'The status was not found at the specified time'}), 404
#     return jsonify({'status': state.status, 'timestamp': state.timestamp.isoformat()}), 200

# Celery задача для обработки заявок
@celery.task
def process_request(request_id):
    request_obj = Request.query.get(request_id)
    if not request_obj:
        return
    request_obj.status = 'Processing'
    db.session.add(RequestState(request_id=request_id, status='Processing'))
    db.session.commit()
    time.sleep(5)
    request_obj.status = 'Completed'
    db.session.add(RequestState(request_id=request_id, status='Completed'))
    db.session.commit()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)