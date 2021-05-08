from flask import Flask, request, jsonify, session, redirect, url_for
import jwt
from functools import wraps
import sqlite3
import os
import hashlib
import random


app = Flask(__name__)
secret_key = app.secret_key = os.urandom(16)
domen_name = 'http://127.0.0.1:5000/'
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
@app.route("/auth", methods=['GET', 'POST', 'DELETE', 'PATCH'])
@check_token
def auth():
    if request.method == 'POST':
        short_link = ''
        
        long_link = request.args.get('long_link')
        readble_link = request.args.get('readble_link')
        token = request.args.get('token')
        link_status = request.args.get('link_status')
        marker = True
        while marker == True:
            try:
                conn = sqlite3.connect('proj.db')
                db = conn.cursor()
                short_link = make_short_link()
                link = db.execute('SELECT short_link FROM link WHERE short_link = ?', (short_link,)).fetchone()
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
            double_long_link = db.execute('SELECT long_link FROM link WHERE long_link = ? AND user_id = ? AND link_status = ?', (long_link, user_id, link_status)).fetchone()
            print(double_long_link)
            if double_long_link is not None:
                message = jsonify({"message": "Данная ссылка уже была сокращена вами ранее. Вы можете редактировать ее в личном кабинете"})
            else:
                db.execute('INSERT INTO link(long_link, short_link, user_id, link_status) VALUES(?, ?, ?, ?, ?)', (long_link, domen_name+short_link, user_id, link_status))
                conn.commit()
                link_id = db.execute('SELECT link_id FROM link WHERE long_link = ? AND user_id = ? AND link_status = ?', (long_link, user_id, link_status)).fetchone()[0]
                db.execute('INSERT INTO readble_link(link_id, link_name) VALUES(?, ?);', (link_id, domen_name+readble_link))
                conn.commit()
                message = jsonify({long_link: domen_name+short_link})
        except:
            return jsonify({"message": "Что-то пошло не так 2 !"})
        finally:
            conn.commit()
        return message, 201
    if request.method == 'GET':
        token = request.args.get('token')
        username = jwt.decode(token, secret_key, "HS256")
        try:
            conn = sqlite3.connect('proj.db')
            db = conn.cursor()
            user_id = db.execute('SELECT user_id FROM users WHERE username = ?', (username['username'],)).fetchone()[0]
            data = db.execute("""
                        SELECT link.user_id, link.long_link, link.short_link, readble_link.link_name, link.link_status, link.count_redirect 
                        FROM link 
                        LEFT JOIN readble_link 
                        ON link.link_id = readble_link.link_id
                        WHERE link.user_id = ?
                        GROUP BY short_link
                        """, (user_id,)).fetchall()
            conn.close()
        except:
            return jsonify({"message": "Что-то пошло не так"})
        return jsonify(data)

    if request.method == "DELETE":
        token = request.args.get('token')
        username = jwt.decode(token, secret_key, "HS256")
        del_link = request.args.get('del_link')
        try:
            conn = sqlite3.connect('proj.db')
            db = conn.cursor()
            del_link_id = db.execute('SELECT link_id FROM readble_link WHERE link_name = ?', (del_link,)).fetchone()
            user_id = db.execute('SELECT user_id FROM users WHERE username = ?', (username['username'],)).fetchone()
            print(del_link_id)
            if del_link_id is None:
                link_user_id = db.execute('SELECT user_id FROM link WHERE short_link = ?', (del_link,)).fetchone()
                if link_user_id[0] == user_id[0]:
                    db.execute('DELETE FROM link WHERE short_link = ? AND user_id = ?', (del_link, user_id[0]))
                    conn.commit()
                else:
                    return jsonify({"message": "Вы не являетесь владельцем этой короткой ссылки"})
            else:
                link_user_id = db.execute('SELECT user_id FROM link WHERE link_id = ?', (del_link_id[0],)).fetchone()
                if link_user_id == user_id:
                    db.execute('DELETE FROM link WHERE link_id = ? AND user_id = ?', (del_link_id[0], user_id[0]))
                    db.execute('DELETE FROM readble_link WHERE link_name = ?', (del_link,))
                    conn.commit()
                else:
                    return jsonify({"message": "Вы не являетесь владельцем этой короткой ссылки"})
            conn.close()
        except:
            return jsonify({"message": "Что-то пошло не так"})
        return jsonify({f"{del_link}": "Ссылка удалена"})

    if request.method == 'PATCH':
        token = request.args.get('token')
        username = jwt.decode(token, secret_key, "HS256")
        short_link = request.args.get('short_name')
        link_name = request.args.get('link_name')
        new_link_name = request.args.get('new_link_name')
        print(short_link)
        print(link_name)
        print(new_link_name)
        try:
            conn = sqlite3.connect('proj.db')
            db = conn.cursor()
            user_id = db.execute('SELECT user_id FROM users WHERE username = ?', (username['username'],)).fetchone()
            if link_name is not None and short_link == '':
                link_id = db.execute("""WITH Fun as (SELECT link.user_id, readble_link.link_id, readble_link.link_name FROM link JOIN readble_link ON link.link_id = readble_link.link_id GROUP BY link.user_id) SELECT link_id FROM Fun WHERE user_id = ? AND link_name = ?""", (user_id[0], link_name)).fetchone()
                if link_id is not None: 
                    if new_link_name == '':
                        db.execute('DELETE FROM readble_link WHERE link_id = ?', (link_id[0],))
                        conn.commit()
                    else:
                        db.execute('UPDATE readble_link SET link_name = ? WHERE link_id = ?', (domen_name+new_link_name, link_id[0]))
                        conn.commit()
                        message = [link_name, "Ссылка обновлена"]
                else:
                    return jsonify({"message": "Эта короткая ссылка вам не принадлежит 1"})
            elif short_link is not None and new_link_name == '' and link_name == '':
                link_id = db.execute('SELECT link_id FROM link WHERE user_id = ? AND short_link = ?', (user_id[0], short_link)).fetchone()
                print(link_id)
                if link_id is not None:
                    new_short_link = make_short_link()
                    db.execute('UPDATE link SET short_link = ? WHERE link_id = ?', (domen_name+new_short_link, link_id[0]))
                    conn.commit()
                    message = [short_link, "Ссылка обновлена"]
                else:
                    return jsonify({"message": "Эта короткая ссылка вам не принадлежит 2"})
            elif short_link is not None and new_link_name is not None:
                link_id = db.execute('SELECT link_id FROM link WHERE user_id = ? AND short_link = ?', (user_id[0], short_link)).fetchone()
                print(link_id)
                if link_id is not None:
                    db.execute('INSERT INTO readble_link(link_id, link_name) VALUES(?, ?)', (link_id[0], domen_name+new_link_name))
                    conn.commit()
                    message = [short_link, "Добавлено читаемое имя для ссылки"]
                else:
                    return jsonify({"message": "Эта короткая ссылка вам не принадлежит 3"})
            conn.close()
        except:
            return jsonify({"message": "Некорректный запрос"})
        return jsonify(message)
        

@app.route('/<short_link>', methods=['GET'])
def link(short_link):
    domen_name = 'http://127.0.0.1:5000/'
    try:
        conn = sqlite3.connect('proj.db')
        db = conn.cursor()
        long_link = db.execute('SELECT long_link FROM link WHERE short_link = ?', (domen_name+short_link,)).fetchone()[0]
    except:
        return jsonify({"message": "Какая то ошибка"})
    return redirect(long_link, code=302)

    
#http://www.llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogochuchaf.eu/
#https://python-scripts.com/sqlite/

def make_short_link():
    arr_link = []
    alphavit = ('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
    count = random.randint(8, 12)
    [arr_link.append(random.choice(alphavit)) for i in range(count)]
    short_link = ''.join(arr_link)
    return short_link
       
    
  


if __name__=="__main__":
    app.run(debug=True)