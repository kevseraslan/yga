import pyodbc

# Veritabanı bağlantısı
conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=E\\SQLEXPRESS;DATABASE=ReviseMe;Trusted_Connection=yes;')
cursor = conn.cursor()

# Questions tablosunun yapısını kontrol et
cursor.execute("""
    SELECT COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_NAME = 'Questions'
    ORDER BY ORDINAL_POSITION
""")

columns = cursor.fetchall()

print("\nQuestions Tablosunun Yapısı:")
print("-" * 50)
for column in columns:
    print(f"Sütun: {column.COLUMN_NAME}")
    print(f"Veri Tipi: {column.DATA_TYPE}")
    if column.CHARACTER_MAXIMUM_LENGTH:
        print(f"Maksimum Uzunluk: {column.CHARACTER_MAXIMUM_LENGTH}")
    print("-" * 30)

conn.close() 