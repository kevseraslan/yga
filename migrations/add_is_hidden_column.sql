-- IsHidden sütununu ekle
ALTER TABLE Questions
ADD IsHidden BIT DEFAULT 0;

-- Mevcut kayıtları güncelle
UPDATE Questions
SET IsHidden = 0; 