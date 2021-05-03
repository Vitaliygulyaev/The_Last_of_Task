from flask import Flask, request, jsonify, session
import jwt
from functools import wraps
import sqlite3
import os
import hashlib


app = Flask(__name__)
secret_key = app.secret_key = os.urandom(16)
# Декоратор, который проверяет лишь тот факт, что токен в базе валидный. Тобишь создан реальным пользователем(Возможно будет использоватся в дальнейшем для просмотра страницы с собственными короткими ссылками)
def check_token(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({"message": "Missing token"}), 403
        try:
            data = jwt.decode(token, secret_key, "HS256")
        except:
            return jsonify({"message": "Invalid token"}), 403
        return func(*args, **kwargs)
    return wrapped

# Переделал аутентификацию. Теперь регистрация и авторизация лишь в одном методе /login
@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        username = request.args.get('username')
        passwd = request.args.get('password')
        headers = {
            "typ": "JWT",
            "alg": "HS256"
        }
        payloads = {
            "username": username
        }
        try:
            conn = sqlite3.connect('proj.db')
            db = conn.cursor()
            data = db.execute("SELECT password, salt FROM users WHERE username = ?", (username,)).fetchall()
            hash_passwd = hashlib.pbkdf2_hmac('sha256', passwd.encode('UTF-8'), data[0][1], 100000)  
            print(hash_passwd)     
            if data[0][0] is not None and data[0][0] == hash_passwd:
                session['username'] = True
                token = jwt.encode(payload=payloads, key= secret_key, algorithm="HS256", headers=headers)
                print(token)
            else:
                return jsonify({"message": "Неверное имя пользователя или пароль"})
        except:
            return jsonify({"message": f"Пользователя с именем {username} не существует"})
        finally:
            conn.close()
        return jsonify({'message': token})
    if request.method == 'POST':
        username = request.args.get('username')
        passwd = request.args.get('password')
        salt = os.urandom(32)
        hash_passwd = hashlib.pbkdf2_hmac('sha256', passwd.encode('UTF-8'), salt, 100000)
        headers = {
            "typ": "JWT",
            "alg": "HS256"
        }
        payloads = {
            "username": username
        }
        token = jwt.encode(payload=payloads, key=secret_key, algorithm="HS256", headers=headers)
        try:
            con = sqlite3.connect('proj.db')
            db = con.cursor()
            db.execute("INSERT INTO users(username, password, salt) VALUES(?, ?, ?)", (username, hash_passwd, salt))
            con.commit()
        except:
            return "Пользователь с таким именем уже зарегистрирован. Попробуйте использовать другое имя."
        finally:
            con.close()
        return jsonify({"token": token})


# Авторизация пользователя. По факту возвращает лишь то, что видно только авторизироваанному пользователю. Понадобится для просмотра коротких ссылок.
@app.route("/auth")
@check_token
def auth():
    return jsonify({"message": "Страница, которая видна лишь с валидным токеном JWT(Грубо говоря, это твой личный кабинет пользователя)"})


if __name__=="__main__":
    app.run(debug=True)