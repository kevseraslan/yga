from app import db, app
from sqlalchemy import text

def update_database():
    with app.app_context():
        # Explanation ve ImagePath sütunlarını ekle
        try:
            db.session.execute(text('ALTER TABLE Questions ADD COLUMN Explanation TEXT'))
            db.session.execute(text('ALTER TABLE Questions ADD COLUMN ImagePath VARCHAR(255)'))
            db.session.commit()
            print("Veritabanı başarıyla güncellendi.")
        except Exception as e:
            print(f"Hata oluştu: {str(e)}")
            db.session.rollback()

if __name__ == '__main__':
    update_database() 