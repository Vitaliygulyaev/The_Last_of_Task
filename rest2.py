from flask import Flask, request, jsonify, session, redirect, make_response
from flask_sqlalchemy import SQLAlchemy
import jwt
from functools import wraps
import os
from random import randint, choice
import bcrypt
from hashlib import md5
from datetime import timedelta

app = Flask(__name__)
secret_key = app.secret_key = os.urandom(16)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=3)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lib.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text, nullable=False, unique=True)
    password = db.Column(db.BLOB, nullable=False)

    def __repr__(self):
        return f'<Users {self.id}>'

class longlink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    long_link = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f'<longlink {self.id}>'

class Link(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    longlink_id = db.Column(db.Integer, db.ForeignKey('longlink.id'), nullable=False)
    users_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    short_link = db.Column(db.Text, nullable=False, unique=True)
    count_redirect = db.Column(db.Integer, nullable=True)
    link_status = db.Column(db.Integer, nullable=True)

    def __repr__(self):
        return f'<Link {self.id}>'

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
                pswd = Users.query.filter_by(username=username).first()
                password = pswd.password
                hash_passwd = bcrypt.checkpw(passwd.encode(), password)
                if passwd is not None and hash_passwd is True:
                    token = jwt.encode(payload=payloads, key=secret_key, algorithm="HS256", headers=headers)
                    session["username"] = username
                    session["token"] = token
                    res = make_response(jsonify({"token": token}))
                else:
                    return jsonify({"message": "Неверное имя пользователя или пароль"}), 403
            except:
                return jsonify({"message": f"Пользователя с именем {username} не существует"}), 403
        else:
            return jsonify({"message": "Введите имя пользователя и пароль"}), 403
    return res, 200

@app.route("/logout", methods=["GET"])
def logout():
    name = session['username']
    session.pop("username", None)
    session.pop("token", None)
    return jsonify({"message": f"{name} - закрыта"}), 200

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
            session["username"] = username
            session["token"] = token
            try:
                users = Users(username=username, password=hash_passwd)
                db.session.add(users)
                db.session.commit()
            except:
                return "Пользователь с таким именем уже зарегистрирован. Попробуйте использовать другое имя.",  403
        else:
            return jsonify({"message": "Введите имя пользователя и пароль"}), 403
        return res, 200


@app.route("/make_link", methods=['POST'])
@check_token
def make_link():
    if request.method == 'POST':
        data = request.get_json()
        long_link = data['long_link']
        short_link = data['short_link']
        token = session.get('token')
        link_status = data['link_status']
        print(link_status)
        print(type(link_status))
        if short_link == "":
            short_link = make_short_link()
        else:
            if 8 > len(short_link) or 12 < len(short_link):
                return jsonify({"message": "Длина ссылки должна быть от 8 - 12 символов"})
        print(short_link)
        if '012'.count(str(link_status)) == 0:
            return jsonify({"message": """Введите следующий статус ссылки: 0 - Публичная (доступна всем), 1 - Общего доступа (доступна лишь авторизованным пользователям, 2 - Приватная (доступна лишь создателю)"""})
        try:
            username = jwt.decode(token, secret_key, 'HS256')
            usr = Users.query.filter_by(username=username['username']).first()
            user_id = usr.id
            lnglnk = longlink.query.filter_by(long_link=long_link).first()
            if lnglnk is None:
                lnglnk = longlink(long_link=long_link)
                db.session.add(lnglnk)
                db.session.commit()
            longlink_id = lnglnk.id
            lnk = Link.query.filter_by(longlink_id=longlink_id, users_id=user_id).first()
            if lnk is not None:
                return jsonify({"message": "Данная ссылка уже была сокращена вами ранее. Вы можете редактировать ее в личном кабинете"})
            else:
                lnglnk = longlink.query.filter_by(long_link=long_link).first()
                longlnk = lnglnk.long_link
                if long_link != longlnk:
                    lnglnk = longlink(long_link=long_link)
                    db.session.add(lnglnk)
                    db.session.commit()
                lnglnk = longlink.query.filter_by(long_link=long_link).first()
                lnglnkid = lnglnk.id
                link = Link(short_link=short_link, users_id=user_id, link_status=link_status, longlink_id=lnglnkid)
                db.session.add(link)
                db.session.commit()
                return jsonify({"long_link": long_link, "short_link": short_link, "link_status": link_status})
        except:
            return jsonify({"message": "Увы, но что-то пошло не так"}), 500
 
@app.route("/show_links", methods=['GET'])
@check_token
def show_links():
    if request.method == 'GET':
        dat = []
        token = session.get('token')
        username = jwt.decode(token, secret_key, "HS256")
        usr = Users.query.filter_by(username=username['username']).first()
        user_id = usr.id
        try:
            lnk = Link.query.filter_by(users_id=user_id).all()
            if len(lnk) is not 0:
                for row in lnk:
                    data = {}
                    data['link_id'] = row.id
                    long_linkid = row.longlink_id
                    lnkid = longlink.query.filter_by(id=long_linkid).first()
                    data['long_link'] = lnkid.long_link
                    data['short_link'] = row.short_link
                    data['link_status'] = row.link_status
                    data['count_redirect'] = row.count_redirect
                dat.append(data)
            else:
                return jsonify({"message": "Здесь пока нет ваших ссылок, создайте ее..."})
        except:
            return jsonify({"message": "Увы, но что-то пошло не так"}), 500
        return jsonify(dat)

@app.route('/<short_link>', methods=['GET', 'DELETE', 'PATCH'])
def link(short_link):
    if request.method == "GET":
        try:
            token = session.get('token')
            if not token:
                lnk = Link.query.filter_by(short_link=short_link).first()
                link_status = lnk.link_status
                if link_status == 0:
                    lnk = Link.query.filter_by(short_link=short_link).first()
                    longlink_id = lnk.longlink_id
                    lnglnk = longlink.query.filter_by(id=longlink_id).first()
                    long_link = lnglnk.long_link
                    count = red_count(lnk.id)
                    Link.query.filter_by(id=lnk.id).update({'count_redirect': count})
                    db.session.commit()
                    return redirect(long_link, code=302)
                elif link_status == 1:
                    return jsonify({"message": "Данная ссылка имеет ограниченный доступ, авторизуйтесь или зарегистрируйтесь"}), 401
                elif link_status == 2:
                    return jsonify({"message": "Данная ссылка приватна!"}), 403
            try:
                username = jwt.decode(token, secret_key, "HS256")
                usr = Users.query.filter_by(username=username['username']).first()
                user_id = usr.id
                lnk = Link.query.filter_by(short_link=short_link).first()
                link_status = lnk.link_status
                if link_status == 0 or link_status == 1:
                    link_id = lnk.id
                    longlink_id = lnk.longlink_id
                    lnglnk = longlink.query.filter_by(id=longlink_id).first()
                    long_link = lnglnk.long_link
                    count = red_count(link_id)
                    Link.query.filter_by(id=link_id).update({'count_redirect': count})
                    db.session.commit()
                    return redirect(long_link, code=302)
                elif link_status == 2:
                    lnk = Link.query.filter_by(short_link=short_link, users_id=user_id).first()
                    if lnk is not None:
                        link_user_id = lnk.users_id
                        link_id = lnk.id
                        longlink_id = lnk.longlink_id
                        lnglnk = longlink.query.filter_by(id=longlink_id).first()
                        long_link = lnglnk.long_link
                        count = red_count(link_id)
                        Link.query.filter_by(id=link_id).update({'count_redirect': count})
                        db.session.commit()
                        return redirect(long_link, code=302)
                    else:
                        return jsonify({"message": "Данная ссылка приватна"}), 403
            except:
                return jsonify({"message": "Неверный токен, авторизуйтесь"}), 401
        except:
            return jsonify({"message": "Увы, но что-то пошло не так"}), 500

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
            usr = Users.query.filter_by(username=username['username']).first()
            user_id = usr.id
            lnk = Link.query.filter_by(short_link=short_link).first()
            link_user_id = lnk.users_id
            if link_user_id == user_id:
                delete = Link.query.filter_by(short_link=short_link, users_id=user_id).first()
                db.session.delete(delete)
                db.session.commit()
            else:
                return jsonify({"message": "Вы не являетесь владельцем этой короткой ссылки"}), 403
        except:
            return jsonify({"message": "Авторизуйтесь"}), 401
        return jsonify({f"{short_link}": "Ссылка удалена"}), 200

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
            usr = Users.query.filter_by(username=username['username']).first()
            user_id = usr.id
            lnk = Link.query.filter_by(short_link=short_link).first()
            link_user_id = lnk.users_id
            if link_user_id == user_id:
                if new_short_link == "":
                    new_short_link = make_short_link()
                    Link.query.filter_by(short_link=short_link, users_id=user_id).update({'short_link': new_short_link})
                    db.session.commit()
                elif 8 < len(new_short_link) and len(new_short_link) < 12:
                    Link.query.filter_by(short_link=short_link, users_id=user_id).update({'short_link': new_short_link})
                    db.session.commit()
                if link_status == 0 or link_status == 1 or link_status == 2 and link_status != "":
                    Link.query.filter_by(short_link=short_link, users_id=user_id).update({'link_status': link_status})
                    db.session.commit()
                return jsonify({"Ссылка "+f"{short_link}": "Успешно обновлена"}), 201
            else:
                return jsonify({"message": "Вы не являетесь владельцем этой короткой ссылки"}), 403
        except:
            return jsonify({"message": "Авторизуйтесь"}), 401


def make_short_link():
    marker = True
    while marker == True:
        try:
            arr_link = []
            alphavit = ('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
            count = randint(8, 12)
            [arr_link.append(choice(alphavit)) for i in range(100)]
            num = ''.join(arr_link)
            short_link = md5(num.encode('utf-8')).hexdigest()[:count]
            print(short_link)
            lnk = Link.query.filter_by(short_link=short_link).first()
            print(lnk)
            if lnk is None:
                marker = False
        except:
            return jsonify({'message': 'Увы, но что-то пошло не так!'}), 500
    return short_link

def red_count(link_id):
    cnt = Link.query.filter_by(id=link_id).first()
    count = cnt.count_redirect
    print(count)
    if count is None:
        count = 1
        return count
    else:
        count = count + 1
        return count
if __name__=="__main__":
    app.run(debug=True)