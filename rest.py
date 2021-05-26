from flask import Flask, request, jsonify, session, redirect, make_response
import jwt
from functools import wraps
import sqlite3
import os
from random import randint, choice
import bcrypt
from hashlib import md5
from datetime import timedelta

app = Flask(__name__)
secret_key = app.secret_key = os.urandom(16)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=200)
DATABASE = 'proj.db'

def check_token(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        token = session.get('token')
        if not token:
            return jsonify({"message": "Missing token"}), 403
        try:
            data = jwt.decode(token, secret_key, "HS256")
        except:
            return jsonify({"message": "Invalid token"}), 403
        return func(*args, **kwargs)
    return wrapped

@app.route("/login", methods=['GET'])
def login():
    if request.method == 'GET':
        data = request.get_json()
        username = data['username']
        passwd = data['password']
        if username != '' and passwd != '':
            headers = {"typ": "JWT", "alg": "HS256"}
            payloads = {"username": username}
            try:
                conn = sqlite3.connect(DATABASE)
                db = conn.cursor()
                password = db.execute("SELECT password FROM users WHERE username = ?", (username,)).fetchall()[0]
                hash_passwd = bcrypt.checkpw(passwd.encode(), password[0]) 
                if passwd is not None and hash_passwd is True:
                    token = jwt.encode(payload=payloads, key=secret_key, algorithm="HS256", headers=headers)
                    session["username"] = username
                    session["token"] = token
                    res = make_response(jsonify({"token": token}))
                    res.set_cookie(key='token', value=token)
                else:
                    return jsonify({"message": "Неверное имя пользователя или пароль"}), 403
            except:
                return jsonify({"message": f"Пользователя с именем {username} не существует"}), 403
            finally:
                conn.close()
        else:
            return jsonify({"message": "Введите имя пользователя и пароль"}), 403
    return res, 200

@app.route("/logout", methods=["GET"])
def logout():
    name = session['username']
    session.pop("username", None)
    session.pop("token", None)
    return jsonify({"message": f"{name} - закрыта"})

@app.route("/register", methods=['POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        username = data['username']
        passwd = data['password']
        if username != '' and passwd != '':
            hash_passwd = bcrypt.hashpw(passwd.encode(), bcrypt.gensalt())
            headers = {
                "typ": "JWT",
                "alg": "HS256"
            }
            payloads = {
                "username": username
            }
            token = jwt.encode(payload=payloads, key=secret_key, algorithm="HS256", headers=headers)
            res = make_response(jsonify({"token": token}))
            res.set_cookie(key='token', value=token)
            try:
                con = sqlite3.connect(DATABASE)
                db = con.cursor()
                db.execute("INSERT INTO users(username, password) VALUES(?, ?)", (username, hash_passwd))
                con.commit()
            except:
                return "Пользователь с таким именем уже зарегистрирован. Попробуйте использовать другое имя.",  403
            finally:
                con.close()
        else:
            return jsonify({"message": "Введите имя пользователя и пароль"}), 403
        return res

@app.route("/make_link", methods=['POST'])
@check_token
def make_link():
    if request.method == 'POST':
        data = request.get_json()
        long_link = data['long_link']
        short_link = data['short_link']
        token = session.get('token')
        link_status = data['link_status']
        if short_link == "":
            short_link = make_short_link()
        try:
            conn = sqlite3.connect(DATABASE)
            db = conn.cursor()
            username = jwt.decode(token, secret_key, 'HS256')
            user_id = db.execute('SELECT user_id FROM users WHERE username = ?', (username['username'],)).fetchone()[0]
            double_long_link = db.execute('SELECT long_link FROM link WHERE long_link = ? AND user_id = ? AND link_status = ?', (long_link, user_id, link_status)).fetchone()
            if double_long_link is not None:
                return jsonify({"message": "Данная ссылка уже была сокращена вами ранее. Вы можете редактировать ее в личном кабинете"})
            else:
                db.execute('INSERT INTO link(long_link, short_link, user_id, link_status) VALUES(?, ?, ?, ?)', (long_link, short_link, user_id, link_status))
                conn.commit()
                conn.close()
                return jsonify({"long_link": long_link, "short_link": short_link, "link_status": link_status})
        except:
            return jsonify({"message": "Что-то пошло не так 2 !"})
 
@app.route("/show_links", methods=['GET'])
@check_token
def show_links():
    if request.method == 'GET':
        dat = []
        token = session.get('token')
        username = jwt.decode(token, secret_key, "HS256")
        try:
            conn = sqlite3.connect(DATABASE)
            db = conn.cursor()
            user_id = db.execute('SELECT user_id FROM users WHERE username = ?', (username['username'],)).fetchone()[0]
            req = db.execute("SELECT  link_id, long_link, short_link, link_status, count_redirect FROM link WHERE user_id = ?", (user_id,)).fetchall()
            for row in req:
                data = {}
                data['link_id'] = row[0]
                data['long_link'] = row[1]
                data['short_link'] = row[2]
                data['link_status'] = row[3]
                data['count_redirect'] = row[4]
                dat.append(data)
            conn.close()
        except:
            return jsonify({"message": "Что-то пошло не так"})
        return jsonify(dat)

@app.route('/<short_link>', methods=['GET', 'DELETE', 'PATCH'])
def link(short_link):
    if request.method == "GET":
        try:
            token = session.get('token')
            conn = sqlite3.connect(DATABASE)
            db = conn.cursor()
            if not token:
                link_status = db.execute('SELECT link_status FROM link WHERE short_link = ?', (short_link,)).fetchone()[0]
                if link_status == 0:
                    link = db.execute('SELECT long_link, link_id FROM link WHERE short_link = ?', (short_link,)).fetchone()
                    count = red_count(link[1])
                    print(count) 
                    db.execute('UPDATE link SET count_redirect = ? WHERE link_id = ?', (count, link[1]))
                    conn.commit()
                    conn.close()
                    return redirect(link[0], code=302)
                else:
                    return jsonify({"message": "Данная ссылка имеет ограниченный доступ, авторизуйтесь или зарегистрируйтесь"})
            try:
                username = jwt.decode(token, secret_key, "HS256")
                link_status = db.execute('SELECT link_status FROM link WHERE short_link = ?', (short_link,)).fetchone()[0]
                if link_status == 0 or link_status == 1:
                        link = db.execute('SELECT long_link, link_id FROM link WHERE short_link = ?', (short_link,)).fetchone()
                        count = red_count(link[1])
                        db.execute('UPDATE link SET count_redirect = ? WHERE link_id = ?', (count, link[1]))
                        conn.commit()
                        conn.close()
                        return redirect(link[0], code=302)
                elif link_status == 3:
                        user_id = db.execute('SELECT user_id FROM users WHERE username = ?', (username['username'],)).fetchone()[0]
                        link_user_id = db.execute('SELECT user_id FROM link WHERE short_link = ?', (short_link,)).fetchone()[0]
                        if link_user_id == user_id:
                            link = db.execute('SELECT long_link, link_id FROM link WHERE short_link = ? AND user_id = ?', (short_link, user_id)).fetchone()
                            count = red_count(link[1])
                            db.execute('UPDATE link SET count_redirect = ? WHERE link_id = ?', (count, link[1]))
                            conn.commit()
                            conn.close()
                            return redirect(link[0], code=302)
                        else:
                            return jsonify({"message": "Данная ссылка имеет ограниченный доступ"})
            except:
                return jsonify({"message": "Invalid token. Please login"})
            
        except:
            return jsonify({"message": "Что-то пошло не так 2!"})
    if request.method == "DELETE":
        token = session.get('token')
        if token is None:
            return jsonify({"message": "Missing token"})
        try:
            data = jwt.decode(token, secret_key, "HS256")
        except:
            return jsonify({"message": "Invalid token"}), 403
        username = jwt.decode(token, secret_key, "HS256")
        try:
            conn = sqlite3.connect(DATABASE)
            db = conn.cursor()
            user_id = db.execute('SELECT user_id FROM users WHERE username = ?', (username['username'],)).fetchone()[0]
            link_user_id = db.execute('SELECT user_id FROM link WHERE short_link = ?', (short_link,)).fetchone()[0]
            if link_user_id == user_id:
                db.execute('DELETE FROM link WHERE short_link = ? AND user_id = ?', (short_link, user_id))
                conn.commit()
            else:
                return jsonify({"message": "Вы не являетесь владельцем этой короткой ссылки"})
            conn.close()
        except:
            return jsonify({"message": "Пройдите авторизацию"})
        return jsonify({f"{short_link}": "Ссылка удалена"})
    if request.method == "PATCH":
        token = session.get('token')
        if token is None:
            return jsonify({"message": "Missing token"}), 403
        try:
            data = jwt.decode(token, secret_key, "HS256")
        except:
            return jsonify({"message": "Invalid token"}), 403
        username = jwt.decode(token, secret_key, "HS256")
        data = request.get_json()
        link_status = data['link_status']
        new_short_link = data['new_short_link']
        try:
            conn = sqlite3.connect(DATABASE)
            db = conn.cursor()
            user_id = db.execute('SELECT user_id FROM users WHERE username = ?', (username['username'],)).fetchone()[0]
            link_user_id = db.execute('SELECT user_id FROM link WHERE short_link = ?', (short_link,)).fetchone()[0]
            if link_user_id == user_id:
                if new_short_link == "":
                    new_short_link = make_short_link()
                    db.execute('UPDATE link SET short_link = ? WHERE short_link = ?', (new_short_link, short_link))
                elif 8 < len(new_short_link) < 12:# БЫЛО БЫ НЕПЛОХО ВАЛИДАТОР НАПИСАТЬ чтобы не было коротких ссылок типа @@@@@@@@@@@@@
                    db.execute('UPDATE link SET short_link = ? WHERE short_link = ?', (new_short_link, short_link))
                if link_status == 0 or link_status == 1 or link_status == 2 and link_status != "":
                    db.execute('UPDATE link SET link_status = ? WHERE short_link = ?', (link_status, short_link))
                conn.commit()
                return jsonify({"Ссылка "+f"{short_link}": "Успешно обновлена"}), 201
            else:
                return jsonify({"message": "Вы не являетесь владельцем этой короткой ссылки"})
        except:
            return jsonify({"message": "Пройдите авторизацию"})

def make_short_link():
    marker = True
    while marker == True:
        try:
            conn = sqlite3.connect(DATABASE)
            db = conn.cursor()
            arr_link = []
            alphavit = ('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
            count = randint(8, 12)
            [arr_link.append(choice(alphavit)) for i in range(100)]
            num = ''.join(arr_link)
            short_link = md5(num.encode('utf-8')).hexdigest()[:count]
            print(short_link)
            link = db.execute('SELECT short_link FROM link WHERE short_link = ?', (short_link,)).fetchone()
            if link is None:
                marker = False
        except:
            return jsonify({'message': 'Что-то пошло не так 1 !'})
        finally:
            conn.close()
    
    return short_link

def red_count(link_id):
    conn = sqlite3.connect(DATABASE)
    db = conn.cursor()
    count = db.execute('SELECT count_redirect FROM link WHERE link_id = ?', (link_id,)).fetchone()[0]
    print(count)
    if count is None:
        count = 1
        conn.close()
        return count
    else:
        count = count + 1
        conn.close()
        return count

if __name__=="__main__":
    app.run(debug=True)