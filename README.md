# Güvenlik Yardımcısı

Herkesin kullanımına uygun, sisteminizi derinlemesine analiz eden ve güvenlik risklerini görsel olarak sunan modern bir masaüstü uygulamasıdır. Rootkit, şüpheli başlangıç ögeleri, sürücüler, ağ bağlantıları ve hassas veri risklerini tespit eder; bulguları kullanıcı dostu bir arayüzde kategorize ve renklendirerek gösterir.

## 🚀 Temel Özellikler

### 🔍 Gelişmiş Sistem Tarayıcı
- **Çapraz Görüş (Cross-View) Analizi**: WMI, psutil ve OpenProcess karşılaştırmalı rootkit ve gizli işlem tespiti
- **Dinamik Risk Puanlama**: Ağırlıklandırılmış risk hesaplama motoru ile her bulgu için özel puanlama
- **Korelasyon Motoru**: Farklı bulguları (aynı PID'ye ait bellek ve ağ anomalisi) birleştirerek "İlişkili Tehdit" olarak sunma
- **İmza Tabanlı Tespit**: signatures.json dosyası ile bilinen rootkit belirtilerinin doğrudan teşhisi
- **Gelişmiş Beyaz Liste**: Tarama motoru seviyesinde çalışan akıllı filtreleme sistemi
- **Bellek Analizi**: PEB Unlinking ve kod bütünlüğü kontrolü ile gelişmiş bellek taraması
- **ADS Tespiti**: Alternate Data Streams ile gizli dosya akışlarının tespiti

### 🛡️ Güvenlik Yapılandırması Paneli
- **Güvenlik Duvarı Durumu**: Domain, Private ve Public profil durumları
- **BitLocker Şifreleme**: Tüm sürücülerin şifreleme durumu
- **Yerel Yöneticiler**: Sistem yönetici hesaplarının listesi

### 🔒 Hassas Veri Tarayıcı
- **Çoklu Format Desteği**: PDF, DOCX, XLSX, TXT, CSV dosyalarında arama
- **Gelişmiş PII Tespiti**: TCKN, kredi kartı, IBAN, e-posta, telefon numarası
- **Luhn Algoritması**: Kredi kartı numaralarının geçerlilik kontrolü
- **Maskeleme Sistemi**: Bulunan hassas verilerin güvenli görüntülenmesi
- **Satır Numarası Takibi**: Bulguların tam konumunu gösteren detaylı raporlama

### 🌐 URL Güvenlik Kontrolü
- **Çoklu API Entegrasyonu**: VirusTotal, URLhaus, urlscan.io
- **WHOIS Analizi**: Alan adı yaşı ve kayıt bilgileri
- **Risk Değerlendirmesi**: Çok faktörlü risk hesaplama algoritması
- **Detaylı Raporlama**: Tıklanabilir linkler ve kapsamlı analiz sonuçları

### ⚙️ Güçlendirilmiş Güvenlik
- **Salt Tabanlı Şifreleme**: Her kurulum için rastgele üretilen salt değeri
- **PBKDF2 Anahtar Türetme**: 100.000 iterasyon ile güçlü şifreleme
- **Güvenli API Saklama**: Fernet şifreleme ile API anahtarlarının korunması
- **Yönetici Hakları Kontrolü**: Otomatik yönetici izni kontrolü ve yeniden başlatma

### 🎨 Modern Kullanıcı Arayüzü
- **Sağ Tık Menüsü**: Dosya konumunu açma, işlem sonlandırma, beyaz listeye ekleme
- **Hiyerarşik Görünüm**: Risk seviyelerine göre kategorize edilmiş bulgular
- **Gerçek Zamanlı Log**: Tarama sürecinin canlı takibi
- **İlerleme Çubuğu**: Tarama durumunun görsel gösterimi
- **Dark Mode**: Modern koyu tema desteği

## 📦 Kurulum

### Gereksinimler
- Python 3.8+
- Windows 10/11 (64-bit)
- Yönetici hakları (tam tarama için)
- En az 4GB RAM

### Adımlar
1. **Bağımlılıkları yükleyin:**
   ```bash
   pip install -r requirements.txt
   ```

2. **API anahtarlarınızı yapılandırın:**
   - VirusTotal: https://www.virustotal.com/gui/join-us
   - URLhaus: https://urlhaus.abuse.ch/api/
   - urlscan.io: https://urlscan.io/user/signup/

3. **Uygulamayı başlatın:**
   ```bash
   python main.py
   ```

4. **Yönetici olarak çalıştırın:**
   - Tam sistem taraması için yönetici hakları gerekir
   - Uygulama otomatik olarak yönetici izni isteyecektir

## 🎯 Kullanım

### Sistem Taraması
1. **Sistem Tarayıcı** modülünü seçin
2. **Sistem Taramasını Başlat** butonuna tıklayın
3. Tarama sonuçlarını sol panelde kategorize şekilde inceleyin
4. Sağ panelde güvenlik yapılandırması özetini görün
5. Şüpheli bulgulara sağ tıklayarak işlem yapın

### Bulgu Yönetimi
- **Sağ Tık Menüsü**: Bulgulara sağ tıklayarak:
  - 📁 Dosya konumunu açın
  - ❌ İşlemi sonlandırın (PID varsa)
  - 👍 Beyaz listeye ekleyin
- **Beyaz Liste Yöneticisi**: Ayarlar menüsünden beyaz listeyi yönetin
- **Detaylı İnceleme**: Bulgulara çift tıklayarak detayları görün

### Hassas Veri Taraması
1. **PII Tarayıcı** modülünü seçin
2. Dosya veya klasör seçin
3. Taranacak veri tiplerini belirleyin
4. Taramayı başlatın ve sonuçları inceleyin
5. Bulgu detaylarını çift tıklayarak görün

### URL Kontrolü
1. **URL Kontrol** modülünü seçin
2. Kontrol edilecek URL'yi girin
3. **Denetle** butonuna tıklayın
4. Detaylı güvenlik raporunu inceleyin
5. Tıklanabilir linklerle manuel kontrol yapın

## 🔧 Teknik Özellikler

### Risk Puanlama Sistemi
- **Dinamik Ağırlıklandırma**: Her bulgu tipi için özel risk ağırlıkları
- **Korelasyon Analizi**: İlişkili bulguların birleştirilmesi
- **Eşik Değerleri**: 
  - 🛑 KRİTİK: Onaylanmış ve ilişkili tehditler
  - 🔴 YÜKSEK: 6.0+ puan
  - ⚠️ ORTA: 3.0-5.9 puan
  - ℹ️ BİLGİ: 0-2.9 puan

### Beyaz Liste Sistemi
- **Süreç İsimleri**: Güvenilir süreçlerin filtrelenmesi
- **Dosya Yolları**: Güvenilir konumların belirlenmesi
- **Otomatik Filtreleme**: Tarama sırasında gerçek zamanlı uygulama
- **Kullanıcı Yönetimi**: Kolay ekleme/çıkarma arayüzü

### Şifreleme Altyapısı
- **PBKDF2**: 100.000 iterasyon ile anahtar türetme
- **Fernet**: AES-128-CBC şifreleme
- **Salt Üretimi**: Her kurulum için rastgele 16-byte salt
- **Güvenli Saklama**: API anahtarlarının şifrelenmiş depolanması

### Bellek Analizi
- **PEB Unlinking**: Gizli modül tespiti
- **Kod Bütünlüğü**: Hash tabanlı modül doğrulama
- **Bellek Enjeksiyonu**: Şüpheli bellek bölgelerinin tespiti
- **Kritik Süreç Taraması**: Sistem süreçlerinin detaylı analizi

## 🛠️ Sorun Giderme

### Yaygın Sorunlar
- **Yönetici Hakları**: Tam tarama için yönetici olarak çalıştırın
- **API Limitleri**: Ücretsiz API'lerin günlük limitlerini kontrol edin
- **Antivirüs Engellemesi**: Güvenilir uygulamalar listesine ekleyin
- **Bellek Yetersizliği**: En az 4GB RAM olduğundan emin olun

### Log Dosyaları
- `app_error.log`: Uygulama hataları
- `system_scanner.log`: Tarama detayları
- `config/config.ini`: Yapılandırma dosyası
- `whitelist.json`: Beyaz liste verileri

### Performans Optimizasyonu
- **Beyaz Liste Kullanımı**: Güvenilir öğeleri beyaz listeye ekleyin
- **Tarama Derinliği**: Kritik sistem işlemlerini atlayın
- **Bellek Yönetimi**: Büyük dosyaları chunk'lar halinde işleyin
- **Çoklu İş Parçacığı**: Paralel tarama ile hızlandırma

## 📄 Lisans
MIT Lisansı ile sunulmaktadır. Detaylar için `LICENSE` dosyasına bakın.

## 🤝 Destek
- **Dokümantasyon**: `KULLANIM_KILAVUZU.txt` ve `Guvenlik_Yardimcisi_Bilgi.txt`
- **Geliştirici**: Yiğit Yücel
- **Sürüm**: 2.0 (Final)
- **Son Güncelleme**: 2025

## 🔒 Güvenlik Uyarıları

### Yüksek Risk Durumunda (🛑 KRİTİK)
- Hemen sistem taramasını durdurun
- Şüpheli işlemleri sonlandırın
- Ağ bağlantısını kesin
- Profesyonel güvenlik uzmanına danışın

### Orta Risk Durumunda (🔴 YÜKSEK)
- Şüpheli işlemleri detaylı inceleyin
- Başlangıç öğelerini gözden geçirin
- Ağ bağlantılarını kontrol edin
- Güvenlik duvarı kurallarını gözden geçirin

### Düşük Risk Durumunda (⚠️ ORTA/ℹ️ BİLGİ)
- Bulguları düzenli olarak takip edin
- Güvenlik yazılımını güncel tutun
- Sistem güncellemelerini kontrol edin
- Haftalık sistem taraması yapın

---

**⚠️ Uyarı**: Bu araç güvenlik analizi için tasarlanmıştır. Bulguları dikkatle değerlendirin ve gerekirse profesyonel güvenlik uzmanlarına danışın. Yanlış pozitif sonuçlar olabilir, her bulgu kritik değildir.