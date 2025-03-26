from flask import Flask, request, render_template, jsonify, g
import sqlite3
import psycopg2
import bcrypt
from psycopg2 import sql

app = Flask(__name__)

# Конфигурация баз данных
DATABASE_SQLITE = 'database.db'
POSTGRES_CONFIG = {
    'dbname': 'postgres',  #Дефолтный настройки postgres
    'user': 'postgres',
    'password': 'postgres',
    'host': 'localhost',
    'port': '5432',
    'client_encoding': 'UTF8'
}


# Подключение к SQLite
def get_db_sqlite():
    if 'db_sqlite' not in g:
        g.db_sqlite = sqlite3.connect(DATABASE_SQLITE)
        g.db_sqlite.row_factory = sqlite3.Row
    return g.db_sqlite

# Подключение к PostgreSQL
def get_db_postgres():
    if 'db_postgres' not in g:
        g.db_postgres = psycopg2.connect(**POSTGRES_CONFIG)
    return g.db_postgres

# Выбор базы данных
def get_db(db_type):
    if db_type == 'sqlite':
        return get_db_sqlite()
    elif db_type == 'postgres':
        return get_db_postgres()
    else:
        raise ValueError("Неподдерживаемый тип БД")

# Создание таблицы users в SQLite и PostgreSQL
def create_users_table():
    sql_query = '''
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        login TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    );
    '''
    for db_type in ['sqlite', 'postgres']:
        db = get_db(db_type)
        cursor = db.cursor()
        cursor.execute(sql_query)
        db.commit()

@app.teardown_appcontext
def close_db(error):
    if 'db_sqlite' in g:
        g.db_sqlite.close()
    if 'db_postgres' in g:
        g.db_postgres.close()

@app.route('/')
def home():
    return render_template('home.html')


@app.route('/authorization', methods=['GET', 'POST'])
def form_authorization():
    if request.method == 'POST':
        login = request.form.get('Login')
        password = request.form.get('Password')
        db_type = request.form.get('db', 'sqlite')  

        # Получаем соединение для обеих БД
        db_sqlite = get_db_sqlite()
        cursor_sqlite = db_sqlite.cursor()
        cursor_sqlite.execute("SELECT password FROM users WHERE login = ?", (login,))
        row_sqlite = cursor_sqlite.fetchone()

        db_postgres = get_db_postgres()
        cursor_postgres = db_postgres.cursor()
        cursor_postgres.execute("SELECT password FROM users WHERE login = %s", (login,))
        row_postgres = cursor_postgres.fetchone()

        # Если пароль совпадает в любой из баз
        if (row_sqlite and bcrypt.checkpw(password.encode('utf-8'), row_sqlite[0].encode('utf-8'))) or \
           (row_postgres and bcrypt.checkpw(password.encode('utf-8'), row_postgres[0].encode('utf-8'))):
            return render_template('successfulauth.html')
        else:
            return render_template('auth_bad.html')

    return render_template('authorization.html')


@app.route('/registration', methods=['GET', 'POST'])
def form_registration():
    if request.method == 'POST':
        login = request.form.get('Login')
        password = request.form.get('Password')

        # Хеширование пароля перед сохранением
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Проверка наличия логина в обеих базах
        db_sqlite = get_db_sqlite()
        cursor_sqlite = db_sqlite.cursor()
        cursor_sqlite.execute("SELECT * FROM users WHERE login = ?", (login,))
        existing_user_sqlite = cursor_sqlite.fetchone()

        db_postgres = get_db_postgres()
        cursor_postgres = db_postgres.cursor()
        cursor_postgres.execute("SELECT * FROM users WHERE login = %s", (login,))
        existing_user_postgres = cursor_postgres.fetchone()

        # Если пользователь с таким логином существует в любой базе
        if existing_user_sqlite or existing_user_postgres:
            return render_template('registration_error.html', message="Пользователь с таким логином уже существует.")

        # Вставка в SQLite
        cursor_sqlite.execute("INSERT INTO users (login, password) VALUES (?, ?)", (login, hashed_password.decode('utf-8')))
        db_sqlite.commit()

        # Вставка в PostgreSQL
        cursor_postgres.execute("INSERT INTO users (login, password) VALUES (%s, %s)", (login, hashed_password.decode('utf-8')))
        db_postgres.commit()

        return render_template('successfulregis.html')

    return render_template('registration.html')

# REST API

@app.route('/api/users', methods=['GET'])
def get_users():
    db_type = request.args.get('db', 'sqlite')  
    users = []

    # Для SQLite
    if db_type == 'sqlite' or db_type == 'both':
        db_sqlite = get_db_sqlite()
        cursor_sqlite = db_sqlite.cursor()
        cursor_sqlite.execute("SELECT login FROM users")
        users_sqlite = cursor_sqlite.fetchall()
        users.extend([user[0] for user in users_sqlite])

    # Для PostgreSQL
    if db_type == 'postgres' or db_type == 'both':
        db_postgres = get_db_postgres()
        cursor_postgres = db_postgres.cursor()
        cursor_postgres.execute("SELECT login FROM users")
        users_postgres = cursor_postgres.fetchall()
        users.extend([user[0] for user in users_postgres])

    return jsonify(users)

@app.route('/api/users/<login>', methods=['GET'])
def get_user(login):
    db_type = request.args.get('db', 'sqlite') 
    user = None

    # Для SQLite
    if db_type == 'sqlite' or db_type == 'both':
        db_sqlite = get_db_sqlite()
        cursor_sqlite = db_sqlite.cursor()
        cursor_sqlite.execute("SELECT login FROM users WHERE login = ?", (login,))
        user_sqlite = cursor_sqlite.fetchone()
        if user_sqlite:
            user = {'login': user_sqlite[0]}

    # Для PostgreSQL
    if db_type == 'postgres' or db_type == 'both':
        db_postgres = get_db_postgres()
        cursor_postgres = db_postgres.cursor()
        cursor_postgres.execute("SELECT login FROM users WHERE login = %s", (login,))
        user_postgres = cursor_postgres.fetchone()
        if user_postgres:
            user = {'login': user_postgres[0]}

    if user:
        return jsonify(user)
    return jsonify({'error': 'Пользователь не найден'}), 404


@app.route('/api/users', methods=['POST'])
def create_user():
    data = request.get_json()
    login = data.get('login')
    password = data.get('password')
    db_type = data.get('db', 'sqlite')

    if not login or not password:
        return jsonify({'error': 'Пользователь с таким логином уже существует'}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Добавляем в обе базы данных
    try:
        # Подключение к SQLite
        db_sqlite = get_db('sqlite')
        cursor_sqlite = db_sqlite.cursor()
        cursor_sqlite.execute("INSERT INTO users (login, password) VALUES (?, ?)", (login, hashed_password.decode('utf-8')))
        db_sqlite.commit()

        # Подключение к PostgreSQL
        db_postgres = get_db('postgres')
        cursor_postgres = db_postgres.cursor()
        cursor_postgres.execute("INSERT INTO users (login, password) VALUES (%s, %s)", (login, hashed_password.decode('utf-8')))
        db_postgres.commit()

        return jsonify({'message': 'Пользователь создан'}), 201

    except Exception as e:
        # Если произошла ошибка, откатываем изменения в обеих БД
        if db_sqlite:
            db_sqlite.rollback()
        if db_postgres:
            db_postgres.rollback()
        
        return jsonify({'error': str(e)}), 500


@app.route('/api/users/<login>', methods=['DELETE'])
def delete_user(login):
    db_type = request.args.get('db', 'sqlite')  # Выбор БД через параметр

    # Для SQLite
    if db_type == 'sqlite' or db_type == 'both':
        db_sqlite = get_db_sqlite()
        cursor_sqlite = db_sqlite.cursor()
        cursor_sqlite.execute("DELETE FROM users WHERE login = ?", (login,))
        db_sqlite.commit()

    # Для PostgreSQL
    if db_type == 'postgres' or db_type == 'both':
        db_postgres = get_db_postgres()
        cursor_postgres = db_postgres.cursor()
        cursor_postgres.execute("DELETE FROM users WHERE login = %s", (login,))
        db_postgres.commit()

    return jsonify({'message': 'Пользователь удалён'}), 200


if __name__ == '__main__':
    with app.app_context():
        create_users_table() 
    app.run(debug=False)
