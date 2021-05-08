from flask import Flask, request, jsonify, session
import jwt
from functools import wraps
import sqlite3
import os
import hashlib
import random


app = Flask(__name__)
secret_key = app.secret_key = os.urandom(16)
# Декоратор, который проверяет лишь тот факт, что токен валидный. Тобишь создан реальным пользователем(Возможно будет использоватся в дальнейшем для просмотра страницы с собственными короткими ссылками)
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
            if data[0][0] is not None and data[0][0] == hash_passwd:
                session[f'{username}'] = True
                token = jwt.encode(payload=payloads, key= secret_key, algorithm="HS256", headers=headers)
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


# Авторизация пользователя. По факту возвращает лишь то, что видно только авторизированному пользователю. Понадобится для просмотра коротких ссылок.
@app.route("/auth", methods=['GET', 'POST'])
@check_token
def auth():
    if request.method == 'POST':
        short_link = ''
        domen_name = 'http://127.0.0.1:5000/'
        long_link = request.args.get('long_link')
        readble_link = request.args.get('readble_link')
        token = request.args.get('token')
        marker = True
        while marker == True:
            try:
                conn = sqlite3.connect('proj.db')
                db = conn.cursor()
                short_link = make_short_link()
                link = db.execute('SELECT short_link FROM private_link WHERE short_link = ?', (short_link,)).fetchone()
                if link is None:
                    marker = False
            except:
                return jsonify({'message': 'Что-то пошло не так 1 !'})
            finally:
                conn.close()
        try:
            conn = sqlite3.connect('proj.db')
            db = conn.cursor()
            username = jwt.decode(token, secret_key, 'HS256')
            user_id = db.execute('SELECT user_id FROM users WHERE username = ?', (username['username'],)).fetchone()[0]
            print(user_id)
            double_long_link = db.execute('SELECT long_link FROM private_link WHERE long_link = ? AND user_id = ?', (long_link, user_id)).fetchone()
            print(double_long_link)
            if double_long_link is not None:
                message = jsonify({"message": "Данная ссылка уже была сокращена вами ранее. Вы можете редактировать ее в личном кабинете"})
            else:
                db.execute('INSERT INTO private_link(long_link, short_link, user_id, readble_link) VALUES(?, ?, ?, ?)', (long_link, domen_name+short_link, user_id, readble_link))
                conn.commit()
                message = jsonify({long_link: domen_name+short_link})
        except:
            return jsonify({"message": "Что-то пошло не так 2 !"})
        finally:
            conn.commit()
        return message, 201

    




def make_short_link():
    arr_link = []
    alphavit = ('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
    count = random.randint(8, 12)
    [arr_link.append(random.choice(alphavit)) for i in range(count)]
    short_link = ''.join(arr_link)
    return short_link
       
    
    # ТУТ БУДУТ ДЕЙСТВИЯ ДЛЯ СОКРАЩАТЕЛЯ ССЫЛОК
    # return jsonify({"message": "Страница, которая видна лишь с валидным токеном JWT(Грубо говоря, это твой личный кабинет пользователя)"})


if __name__=="__main__":
    app.run(debug=True)