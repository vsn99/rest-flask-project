import mysql.connector


conn = mysql.connector.connect(
        host="database.clau0466sb6g.us-east-1.rds.amazonaws.com",
        user="admin",
        password="12345678",
        database="database1"
)
cursor = conn.cursor()

cursor.execute("select * from USER;")
print(cursor.fetchall())