# ReviseMe - Soru Tekrar ve Öğrenme Platformu

ReviseMe, öğrencilerin soruları tekrar etmelerine ve öğrenmelerine yardımcı olan bir web uygulamasıdır.

## Özellikler

- Kullanıcı girişi ve şifre yönetimi
- Soru ekleme ve düzenleme
- Soru tekrar sistemi
- Not alma özelliği
- Favori sorular
- Kategori ve zorluk seviyesine göre sınıflandırma
- Gelişim takibi ve raporlama
- Bildirim sistemi
- Motive edici mesajlar

## Gereksinimler

- Python 3.8 veya üzeri
- MSSQL Server
- ODBC Driver 17 for SQL Server

## Kurulum

1. Projeyi klonlayın:
```bash
git clone https://github.com/yourusername/revise-me.git
cd revise-me
```

2. Sanal ortam oluşturun ve aktifleştirin:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

3. Gerekli paketleri yükleyin:
```bash
pip install -r requirements.txt
```

4. Veritabanı bağlantı bilgilerini ayarlayın:
- `config.py` dosyasındaki `SQLALCHEMY_DATABASE_URI` değişkenini kendi veritabanı bilgilerinizle güncelleyin.

5. Uygulamayı çalıştırın:
```bash
python app.py
```

## Kullanım

1. Tarayıcınızda `http://localhost:5000` adresine gidin
2. Yeni bir hesap oluşturun veya mevcut hesabınızla giriş yapın
3. Sorularınızı ekleyin ve yönetmeye başlayın

## Veritabanı Yapısı

Uygulama aşağıdaki tabloları kullanır:

- Users: Kullanıcı bilgileri
- Questions: Sorular
- Categories: Kategoriler
- Notes: Notlar
- Favorites: Favori sorular
- Notifications: Bildirimler
- RepeatSettings: Tekrar ayarları
- Reports: Raporlar
- StudyPlans: Çalışma planları

## Katkıda Bulunma

1. Bu depoyu fork edin
2. Yeni bir branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add some amazing feature'`)
4. Branch'inizi push edin (`git push origin feature/amazing-feature`)
5. Bir Pull Request oluşturun

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için `LICENSE` dosyasına bakın. 