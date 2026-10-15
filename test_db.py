import os
import pymysql
from dotenv import load_dotenv

load_dotenv()

try:
    connection = pymysql.connect(
        host=os.getenv("DB_HOST"),
        port=int(os.getenv("DB_PORT", 4000)),
        user=os.getenv("DB_USERNAME"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        ssl={"ca": os.getenv("DB_CA_PATH")},
        connect_timeout=15
    )

    with connection.cursor() as cursor:
        cursor.execute("SELECT VERSION(), DATABASE()")
        result = cursor.fetchone()
        print("Connection successful!")
        print("TiDB version:", result[0])
        print("Connected database:", result[1])

    connection.close()

except Exception as e:
    print("Connection failed.")
    print(type(e).__name__ + ":", e)