from flask import Flask, request, g, jsonify
import jwt
from functools import wraps
import sqlite3
import os
import hashlib


app = Flask(__name__)

# Декоратор, который проверяет лишь тот факт, что токен в базе валидный. Тобишь создан реальным пользователем(Возможно будет использоватся в дальнейшем для просмотра страницы с собственными короткими ссылками)
def check_token(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({"message": "Missing token"}), 403
        try:
            conn = sqlite3.connect("proj.db")
            db = conn.cursor()
            hash_passwd = db.execute("SELECT password FROM users WHERE (SELECT user_id FROM userstokens WHERE token=?)", (token,)).fetchone()
            print(hash_passwd)
            data = jwt.decode(token, hash_passwd[0], "HS256")
            print(data)
        except:
            return jsonify({"message": "Invalid token"}), 403
        finally:
            conn.close()
        return func(*args, **kwargs)
    return wrapped

# Регистрация нового пользователя (Логинизация если можно так выразиться). Добавляет нового польз в БД и создает для него Токен JWT.
@app.route("/login", methods=["POST"])
def login():
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
    token = jwt.encode(payload=payloads, key=hash_passwd, algorithm="HS256", headers=headers)
    print(token)
    try:
        con = sqlite3.connect('proj.db')
        db = con.cursor()
        db.execute("INSERT INTO users(username, password, salt) VALUES(?, ?, ?)", (username, hash_passwd, salt))
        con.commit()
        user_id = db.execute(f"SELECT user_id FROM users WHERE username=?", (username,)).fetchone()
        print(user_id[0])
        db.execute("INSERT INTO userstokens(user_id, token) VALUES(?, ?)", (user_id[0], token))
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