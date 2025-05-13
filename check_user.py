import pyodbc
import hashlib

# Veritabanı bağlantısı
conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=E\\SQLEXPRESS;DATABASE=ReviseMe;Trusted_Connection=yes;')
cursor = conn.cursor()

# Kullanıcıları listele
cursor.execute("SELECT UserId, UserName, PasswordHash, Name, Surname FROM Users")
users = cursor.fetchall()

print("\nVeritabanındaki Kullanıcılar:")
print("-" * 50)
for user in users:
    print(f"ID: {user.UserId}")
    print(f"Kullanıcı Adı: {user.UserName}")
    print(f"Şifre Hash: {user.PasswordHash}")
    print(f"Ad: {user.Name}")
    print(f"Soyad: {user.Surname}")
    print("-" * 50)

# Test şifresi oluştur
test_password = "123456"  # Buraya giriş yapmaya çalıştığınız şifreyi yazın
test_hash = hashlib.sha256(test_password.encode()).hexdigest()
print(f"\nTest şifresi için hash: {test_hash}")

conn.close() 