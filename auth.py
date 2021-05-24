from flask import Flask, request, jsonify, session, redirect, render_template, make_response
import jwt
from functools import wraps
import sqlite3
import os
import hashlib
import random


app = Flask(__name__)
secret_key = app.secret_key = os.urandom(16)
domen_name = 'http://127.0.0.1:5000/'


def check_token(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        token = request.cookies.get('token')
        print(token)
        if not token:
            return jsonify({"message": "Missing token"}), 403
        try:
            data = jwt.decode(token, secret_key, "HS256")
        except:
            return jsonify({"message": "Invalid token"}), 403
        return func(*args, **kwargs)
    return wrapped

@app.route('/', methods=['GET'])
def path():
    return render_template('login.html')

    

@app.route("/login", methods=['POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')## менять на строчку reauest.form.get...
        passwd = request.form.get('password')
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
            print(data)
            hash_passwd = hashlib.pbkdf2_hmac('sha256', passwd.encode('UTF-8'), data[0][1], 100000)  
            if data[0][0] is not None and data[0][0] == hash_passwd:
                token = jwt.encode(payload=payloads, key=secret_key, algorithm="HS256", headers=headers)
                res = make_response(redirect(domen_name+'auth'))
                res.set_cookie(key='token', value=token)
            else:
                return jsonify({"message": "Неверное имя пользователя или пароль"})
        except:
            return jsonify({"message": f"Пользователя с именем {username} не существует"})
        finally:
            conn.close()
    else:
        return jsonify({"message": "Введите имя пользователя и пароль"})
    return res

@app.route("/register", methods=['POST'])
def register():
    if request.method == 'POST':
        username = request.args.get('username')
        passwd = request.args.get('password')
        print(username)
        print(passwd)
        if username != '' and passwd != '':
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
            res = make_response(jsonify({"token": token}))
            res.set_cookie(key='token', value=token)
            try:
                con = sqlite3.connect('proj.db')
                db = con.cursor()
                db.execute("INSERT INTO users(username, password, salt) VALUES(?, ?, ?)", (username, hash_passwd, salt))
                con.commit()
            except:
                return "Пользователь с таким именем уже зарегистрирован. Попробуйте использовать другое имя."
            finally:
                con.close()
        else:
            return jsonify({"message": "Введите имя пользователя и пароль"})
        return res


@app.route("/auth", methods=['GET', 'POST'])
@check_token
def auth():
    if request.method == 'POST':
        long_link = request.form.get('long_link')
        short_link = request.form.get('short_link')
        token = request.cookies.get('token')
        link_status = request.form.get('link_status')
        if short_link == "":
            short_link = make_short_link()
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
                db.execute('INSERT INTO link(long_link, short_link, user_id, link_status) VALUES(?, ?, ?, ?)', (long_link, short_link, user_id, link_status))
                conn.commit()
                message = redirect(domen_name+'auth')#jsonify({long_link: domen_name+short_link})
        except:
            return jsonify({"message": "Что-то пошло не так 2 !"})
        finally:
            conn.close()
        return message, 201

    if request.method == 'GET':
        token = request.cookies.get('token')
        username = jwt.decode(token, secret_key, "HS256")
        try:
            conn = sqlite3.connect('proj.db')
            db = conn.cursor()
            user_id = db.execute('SELECT user_id FROM users WHERE username = ?', (username['username'],)).fetchone()[0]
            data = db.execute("SELECT long_link, short_link, link_status, count_redirect, link_id FROM link WHERE user_id = ?", (user_id,)).fetchall()
            print(data)
            conn.close()
        except:
            return jsonify({"message": "Что-то пошло не так"})
        return render_template('userplace.html', data=data)#jsonify(data)

@app.route("/removelink", methods=['POST'])
@check_token
def remove_link():
    if request.method == "POST":
        token = request.cookies.get('token')
        username = jwt.decode(token, secret_key, "HS256")
        link_id = request.form.get('del_link_id')# Со страницы хтмл взять тот линк, что будет удален
        try:
            conn = sqlite3.connect('proj.db')
            db = conn.cursor()
            user_id = db.execute('SELECT user_id FROM users WHERE username = ?', (username['username'],)).fetchone()[0]
            link_user_id = db.execute('SELECT user_id FROM link WHERE link_id = ?', (link_id,)).fetchone()[0]
            if link_user_id == user_id:
                db.execute('DELETE FROM link WHERE link_id = ? AND user_id = ?', (link_id, user_id))
                conn.commit()
            else:
                return jsonify({"message": "Вы не являетесь владельцем этой короткой ссылки"})
            conn.close()
        except:
            return jsonify({"message": "Что-то пошло не так"})
        return redirect(domen_name+'auth', code=302)#jsonify({f"{link_id}": "Ссылка удалена"})

@app.route("/updatelink", methods=['POST'])
@check_token
def update_link():
    if request.method == 'POST':
        token = request.cookies.get('token')
        username = jwt.decode(token, secret_key, "HS256")
        link_id = request.form.get('link_id')
        long_link = request.form.get('long_link')
        short_link = request.form.get('short_link')
        generate_link = request.form.get('generate_link')
        print(generate_link)
        print(type(generate_link))
        link_status = request.form.get('link_status')## адаптировать под шаблон
        print(link_id)
        print(long_link)
        print(short_link)
        print(link_status)
        try:
            conn = sqlite3.connect('proj.db')
            db = conn.cursor()
            user_id = db.execute('SELECT user_id FROM users WHERE username = ?', (username['username'],)).fetchone()[0]
            link_user_id = db.execute('SELECT user_id FROM link WHERE link_id = ?', (link_id,)).fetchone()[0]
            if link_user_id == user_id:
                if short_link == "" and generate_link == None:
                    db.execute('UPDATE link SET long_link = ?, link_status = ? WHERE link_id = ? AND user_id = ?', (long_link, link_status, link_id, user_id))
                elif short_link != "" and generate_link != None:
                    db.execute('UPDATE link SET long_link = ?, short_link = ?, link_status = ? WHERE link_id = ? AND user_id = ?', (long_link, short_link, link_status, link_id, user_id))
                elif short_link != "" and generate_link == None:
                    db.execute('UPDATE link SET long_link = ?, short_link = ?, link_status = ? WHERE link_id = ? AND user_id = ?', (long_link, short_link, link_status, link_id, user_id))
                elif short_link == "" and generate_link != None:
                    short_link = make_short_link()
                    db.execute('UPDATE link SET long_link = ?, short_link = ?, link_status = ? WHERE link_id = ? AND user_id = ?', (long_link, short_link, link_status, link_id, user_id))
                conn.commit()
                return redirect(domen_name+'auth')#jsonify(long_link, short_link, link_status, link_id, user_id)## адаптировать под шаблон
            else:
                return jsonify({"message": "Вы не являетесь владельцем этой короткой ссылки"})
        except:
            return jsonify({"message": "Что-то пошло не так"})

# Для обновления уже существующей ссылки. По факту переход на страничку для редактирования
@app.route('/show_link', methods=['POST'])
@check_token
def show_link():
    token = request.cookies.get('token')
    link_id = request.form.get('patch_link_id')
    print(link_id)
    username = jwt.decode(token, secret_key, 'HS256')
    try:
        conn = sqlite3.connect('proj.db')
        db = conn.cursor()
        user_id = db.execute('SELECT user_id FROM users WHERE username = ?', (username['username'],)).fetchone()[0]
        print(user_id)
        link_user_id = db.execute('SELECT user_id FROM link WHERE link_id = ?', (link_id,)).fetchone()[0]
        print(link_user_id)
        if link_user_id == user_id:
            data = db.execute('SELECT long_link, short_link, link_status, link_id FROM link WHERE link_id = ?', (link_id,)).fetchone()
            print(data)
            return render_template('make_link.html', data=data)# адаптировать под шаблон
    except:
        return jsonify({"message": "Error"})# адаптировать под шаблон



@app.route('/<short_link>', methods=['GET'])
def link(short_link):
    try:
        token = request.cookies.get('token')
        conn = sqlite3.connect('proj.db')
        db = conn.cursor()
        if not token:
            link_status = db.execute('SELECT link_status FROM link WHERE short_link = ?', (short_link,)).fetchone()[0]
            if link_status == 'public':
                link = db.execute('SELECT long_link, link_id FROM link WHERE short_link = ?', (short_link,)).fetchone()
                print(link[0])
                print(link[1])
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
            if link_status == 'public' or link_status == 'general':
                    link = db.execute('SELECT long_link, link_id FROM link WHERE short_link = ?', (short_link,)).fetchone()
                    count = red_count(link[1])
                    db.execute('UPDATE link SET count_redirect = ? WHERE link_id = ?', (count, link[1]))
                    conn.commit()
                    conn.close()
                    return redirect(link[0], code=302)
            elif link_status == 'private':
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
    

def make_short_link():
    marker = True
    while marker == True:
        try:
            conn = sqlite3.connect('proj.db')
            db = conn.cursor()
            arr_link = []
            alphavit = ('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
            count = random.randint(8, 12)
            [arr_link.append(random.choice(alphavit)) for i in range(count)]
            short_link = ''.join(arr_link)
            link = db.execute('SELECT short_link FROM link WHERE short_link = ?', (short_link,)).fetchone()
            if link is None:
                marker = False
        except:
            return jsonify({'message': 'Что-то пошло не так 1 !'})
        finally:
            conn.close()
    
    return short_link

def red_count(link_id):
    conn = sqlite3.connect('proj.db')
    db = conn.cursor()
    count = db.execute('SELECT count_redirect FROM link WHERE link_id = ?', (link_id,)).fetchone()[0]
    print(count)
    if count is None:
        count = 1
        #conn.close()
        return count
    else:
        count = count + 1
        #conn.close()
        return count

if __name__=="__main__":
    app.run(debug=True)