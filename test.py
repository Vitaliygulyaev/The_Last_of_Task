import sqlite3
# short_link = []
# alphavit = ('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
# count = random.randint(8, 12)
# [short_link.append(random.choice(alphavit)) for i in range(count)]
# print(''.join(short_link))
# conn = sqlite3.connect('proj.db')
# db = conn.cursor()
# data = db.execute("SELECT password, salt FROM users WHERE username = ?", ('vitaliy',)).fetchall()
# conn.close()
# print(data)
# if data[0][0] is not None:
#     print(True)
                
conn = sqlite3.connect('proj.db')
db = conn.cursor()
user_id = db.execute('SELECT user_id FROM users WHERE username = ?', ('vitaliy',)).fetchone()[0]
data = db.execute("""
            SELECT link.user_id, link.long_link, link.short_link, readble_link.link_name, link.link_status, link.count_redirect 
            FROM link 
            LEFT JOIN readble_link 
            ON link.link_id = readble_link.link_id
            WHERE link.user_id = ?
            GROUP BY short_link
            """, (user_id,)).fetchall()
print(data)
print(type(data))
conn.close()