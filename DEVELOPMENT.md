# Güvenlik Yardımcısı - Geliştirici Dokümantasyonu

## 📋 Proje Genel Bakış

Güvenlik Yardımcısı, herkesin kullanımına uygun olarak geliştirilmiş kapsamlı bir güvenlik tarama ve analiz aracıdır. Modern Python teknolojileri kullanılarak geliştirilmiş, modüler yapıya sahip bir masaüstü uygulamasıdır.

**Sürüm:** 2.0 (Final)  
**Geliştirici:** Yiğit Yücel  
**Son Güncelleme:** 2025  
**Lisans:** MIT

## 🏗️ Teknik Mimari

### Ana Bileşenler

#### 1. **main.py** (121KB, 2688 satır)
- **Ana GUI Uygulaması**: CustomTkinter tabanlı modern arayüz
- **Modüler Yapı**: Farklı tarama modüllerini entegre eden ana kontrolör
- **Şifreleme Yönetimi**: PBKDF2 ve Fernet tabanlı güvenlik altyapısı
- **API Anahtarı Yönetimi**: Güvenli API anahtarı saklama ve şifreleme
- **Beyaz Liste Arayüzü**: Kullanıcı dostu beyaz liste yönetimi
- **Sağ Tık Menüsü**: Bağlam işlemleri ve etkileşimli özellikler
- **Gerçek Zamanlı Log**: Canlı tarama takibi ve durum bildirimleri

#### 2. **system_scanner.py** (48KB, 1013 satır)
- **Gelişmiş Tarama Motoru**: Çapraz görüş (cross-view) analizi
- **Dinamik Risk Puanlama**: Ağırlıklandırılmış risk hesaplama sistemi
- **Korelasyon Motoru**: İlişkili tehdit tespiti ve gruplandırma
- **Bellek Analizi**: PEB Unlinking ve kod bütünlüğü kontrolü
- **ADS Tespiti**: Alternate Data Streams ile gizli dosya akışları
- **İmza Tabanlı Tespit**: signatures.json ile bilinen rootkit belirtileri
- **Beyaz Liste Filtreleme**: Tarama motoru seviyesinde akıllı filtreleme

#### 3. **pii_scanner.py** (12KB, 313 satır)
- **Hassas Veri Tarama**: Çoklu format desteği (PDF, DOCX, XLSX, TXT, CSV)
- **Gelişmiş Regex**: Optimize edilmiş pattern'lar ile PII tespiti
- **Luhn Algoritması**: Kredi kartı numaralarının geçerlilik kontrolü
- **Maskeleme Sistemi**: Bulunan hassas verilerin güvenli görüntülenmesi
- **Satır Numarası Takibi**: Bulguların tam konumunu gösteren detaylı raporlama

#### 4. **url_checker.py** (8.2KB, 223 satır)
- **URL Güvenlik Kontrolü**: Çoklu API entegrasyonu
- **WHOIS Analizi**: Alan adı yaşı ve kayıt bilgileri
- **Risk Değerlendirme**: Çok faktörlü risk hesaplama algoritması
- **Detaylı Raporlama**: Tıklanabilir linkler ve kapsamlı analiz sonuçları

#### 5. **api_utils.py** (6.8KB, 170 satır)
- **API Entegrasyonları**: VirusTotal, URLhaus, urlscan.io
- **HTTP İstekleri**: Güvenli ve hata toleranslı API çağrıları
- **Rate Limiting**: API limit kontrolü ve yeniden deneme mekanizması
- **Hata Yönetimi**: Kapsamlı hata yakalama ve loglama

### Yardımcı Modüller

#### **whitelist_utils.py** (1.2KB, 36 satır)
- **Beyaz Liste Yönetimi**: JSON tabanlı veri saklama
- **Ekleme/Çıkarma İşlemleri**: Güvenli veri manipülasyonu
- **Veri Doğrulama**: Format kontrolü ve duplikasyon önleme

#### **regex_patterns.py** (267B, 5 satır)
- **PII Pattern'ları**: TCKN, kredi kartı, IBAN, e-posta, telefon
- **Optimize Edilmiş Regex**: Performans odaklı pattern'lar

#### **signatures.json** (1.5KB, 42 satır)
- **Rootkit İmzaları**: Bilinen zararlı yazılım belirtileri
- **Hash Tabanlı Tespit**: Dosya ve süreç imzaları
- **Güncellenebilir Veritabanı**: Dinamik imza yükleme

## 🔒 Güvenlik Altyapısı

### Şifreleme Sistemi

#### PBKDF2 Anahtar Türetme
```python
def derive_key(password: str, salt: bytes) -> bytes:
    return base64.urlsafe_b64encode(
        hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)
    )
```

**Özellikler:**
- **100.000 İterasyon**: Güçlü anahtar türetme
- **SHA-256 Hash**: Güvenli hash algoritması
- **32-byte Anahtar**: AES-128-CBC için optimize
- **Salt Tabanlı Güvenlik**: Her kurulum için benzersiz

#### Fernet Şifreleme
```python
def encrypt(text: str, password: str, salt: bytes) -> str:
    key = derive_key(password, salt)
    f = Fernet(key)
    return f.encrypt(text.encode()).decode()
```

**Özellikler:**
- **AES-128-CBC**: Güçlü simetrik şifreleme
- **Base64 Encoding**: Güvenli veri transferi
- **Otomatik Anahtar Rotasyonu**: Güvenlik artırımı

### Salt Üretimi
```python
salt_bytes = os.urandom(16)
salt_b64 = base64.urlsafe_b64encode(salt_bytes).decode('utf-8')
```

**Özellikler:**
- **Rastgele 16-byte**: Kriptografik güvenlik
- **Her Kurulum İçin Benzersiz**: Çoklu kurulum desteği
- **Base64 Encoding**: Güvenli saklama

## 🎯 Risk Puanlama Sistemi

### Dinamik Ağırlıklandırma

```python
RISK_WEIGHTS = {
    'hidden_processes': 9.0,
    'patched_modules': 7.0,
    'unlinked_modules': 8.0,
    'memory_injections': 5.0,
    'unsigned_drivers': 3.0,
    'network_anomalies': 2.0,
    'unsigned_processes': 4.0,
    'temp_processes': 2.5
}
```

### Risk Seviyeleri

| Seviye | Puan Aralığı | Açıklama |
|--------|-------------|----------|
| 🛑 KRİTİK | Özel | Onaylanmış ve ilişkili tehditler |
| 🔴 YÜKSEK | 6.0+ | Yüksek riskli bulgular |
| ⚠️ ORTA | 3.0-5.9 | Orta riskli bulgular |
| ℹ️ BİLGİ | 0-2.9 | Düşük riskli bilgiler |

### Korelasyon Motoru

```python
def correlate_findings(findings):
    """İlişkili bulguları tespit eder ve gruplandırır."""
    correlated = {}
    for finding in findings:
        pid = finding.get('pid')
        if pid in correlated:
            correlated[pid]['linked_findings'].append(finding)
        else:
            correlated[pid] = {
                'threat_name': f"İlişkili Tehdit (PID: {pid})",
                'linked_findings': [finding]
            }
    return correlated
```

## 🧠 Bellek Analizi

### PEB Unlinking Tespiti

```python
def check_peb_unlinking(process):
    """PEB modül listesinde gizli modülleri tespit eder."""
    try:
        # WMI ile modül listesi
        wmi_modules = get_wmi_modules(process.pid)
        
        # PEB ile modül listesi
        peb_modules = get_peb_modules(process.pid)
        
        # Karşılaştırma
        hidden_modules = set(wmi_modules) - set(peb_modules)
        
        return list(hidden_modules)
    except Exception as e:
        logging.error(f"PEB Unlinking kontrolü başarısız: {e}")
        return []
```

### Kod Bütünlüğü Kontrolü

```python
def verify_module_integrity(module_path):
    """Modül dosyasının bütünlüğünü kontrol eder."""
    try:
        with open(module_path, 'rb') as f:
            content = f.read()
        
        # Hash hesaplama
        file_hash = hashlib.sha256(content).hexdigest()
        
        # İmza veritabanı kontrolü
        if file_hash in known_signatures:
            return False, "Bilinen zararlı imza"
        
        return True, "Bütünlük kontrolü geçti"
    except Exception as e:
        return False, f"Bütünlük kontrolü başarısız: {e}"
```

## 🌐 API Entegrasyonları

### VirusTotal Entegrasyonu

```python
def check_virustotal(url, api_key):
    """VirusTotal API ile URL kontrolü."""
    headers = {
        'x-apikey': api_key,
        'Content-Type': 'application/json'
    }
    
    # URL ID'si al
    url_id = get_url_id(url)
    
    # Analiz sonucu al
    response = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers=headers
    )
    
    return parse_vt_response(response.json())
```

### URLhaus Entegrasyonu

```python
def check_urlhaus(url):
    """URLhaus API ile zararlı URL kontrolü."""
    data = {
        'url': url
    }
    
    response = requests.post(
        'https://urlhaus.abuse.ch/api/',
        data=data,
        timeout=10
    )
    
    return parse_uh_response(response.json())
```

## 📊 PII Tarama Motoru

### Regex Pattern'ları

```python
PII_PATTERNS = {
    'tckn': r'\b[1-9][0-9]{10}\b',
    'credit_card': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
    'iban': r'\bTR[0-9]{2}[0-9]{4}[0-9]{4}[0-9]{4}[0-9]{4}[0-9]{2}\b',
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'phone': r'\b(?:\+90|0)?[5][0-9]{9}\b'
}
```

### Luhn Algoritması

```python
def luhn_check(card_number):
    """Kredi kartı numarasının geçerliliğini Luhn algoritması ile kontrol eder."""
    def digits_of(n):
        return [int(d) for d in str(n)]
    
    digits = digits_of(card_number)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = sum(odd_digits)
    for d in even_digits:
        checksum += sum(digits_of(d*2))
    return checksum % 10 == 0
```

## 🎨 Kullanıcı Arayüzü

### CustomTkinter Tabanlı GUI

```python
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Tema ayarları
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Renk paleti
        self.COLORS = {
            "bg_dark": "#0f172a",
            "bg_medium": "#1e293b",
            "bg_light": "#1a202c",
            "text_primary": "#e2e8f0",
            "text_secondary": "#94a3b8",
            "accent": "#3b82f6",
            "accent_hover": "#2563eb",
            "error": "#f44336",
            "warning": "#F59E42"
        }
```

### Sağ Tık Menüsü

```python
def show_context_menu(event):
    """TreeView üzerinde sağ tıklandığında bağlam menüsünü gösterir."""
    selected_id = self.system_tree.focus()
    if not selected_id:
        return
    
    item = self.system_tree.item(selected_id)
    values = item.get("values")
    
    context_menu = tk.Menu(self.system_tree, tearoff=0)
    
    # Dosya konumunu aç
    if process_path and os.path.exists(process_path):
        context_menu.add_command(
            label="📁 Dosya Konumunu Aç",
            command=lambda: self.open_file_location(process_path)
        )
    
    # İşlemi sonlandır
    if pid:
        context_menu.add_command(
            label="❌ İşlemi Sonlandır",
            command=lambda: self.terminate_process(pid, process_name)
        )
    
    # Beyaz listeye ekle
    context_menu.add_command(
        label="👍 Beyaz Listeye Ekle",
        command=lambda: self.add_to_whitelist(process_name, process_path)
    )
```

## 🔧 Performans Optimizasyonu

### Çoklu İş Parçacığı

```python
def run_scan():
    """Tarama işlemini ayrı thread'de çalıştırır."""
    def scan_worker():
        try:
            # Tarama işlemleri
            results = perform_full_scan()
            
            # UI güncelleme
            self.after(0, self.update_ui, results)
        except Exception as e:
            self.after(0, self.show_error, str(e))
    
    threading.Thread(target=scan_worker, daemon=True).start()
```

### Bellek Yönetimi

```python
def process_large_file(file_path, chunk_size=8192):
    """Büyük dosyaları chunk'lar halinde işler."""
    with open(file_path, 'r', encoding='utf-8') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            
            # Chunk işleme
            process_chunk(chunk)
            
            # Bellek temizleme
            gc.collect()
```

## 🐛 Hata Yönetimi

### Merkezi Loglama

```python
def setup_logging():
    """Merkezi loglama sistemini yapılandırır."""
    log_directory = os.path.join(app_dir, '..', 'Log Kayıtları')
    os.makedirs(log_directory, exist_ok=True)
    
    # Sistem tarayıcı logu
    system_log_path = os.path.join(log_directory, 'system_scanner.log')
    system_handler = logging.FileHandler(system_log_path, encoding='utf-8')
    
    # Uygulama hata logu
    app_error_log_path = os.path.join(log_directory, 'app_error.log')
    error_handler = logging.FileHandler(app_error_log_path, encoding='utf-8')
    
    # Format ayarları
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - [%(module)s] - %(message)s'
    )
    
    system_handler.setFormatter(formatter)
    error_handler.setFormatter(formatter)
```

### Kullanıcı Bildirimleri

```python
def show_custom_messagebox(parent, title, message, icon="error"):
    """Modern ve estetik mesaj kutusu gösterir."""
    dialog = ctk.CTkToplevel(parent)
    dialog.title(title)
    dialog.resizable(False, False)
    dialog.transient(parent)
    dialog.grab_set()
    
    # İkon ve renk ayarları
    icon_map = {
        "info": ("\u2139", "#3b82f6"),
        "warning": ("\u26A0", "#FF3131"),
        "error": ("\u26A0", "#FF3131"),
    }
    
    icon_text, icon_color = icon_map.get(icon, ("\u2139", "#3b82f6"))
    
    # UI bileşenleri
    ctk.CTkLabel(dialog, text=icon_text, font=("Segoe UI Emoji", 54, "bold"))
    ctk.CTkLabel(dialog, text=title, font=("Inter", 18, "bold"))
    ctk.CTkLabel(dialog, text=message, wraplength=540)
```

## 📦 Kurulum ve Dağıtım

### Bağımlılık Yönetimi

```txt
# requirements.txt
customtkinter>=5.2.0
psutil>=5.9.0
requests>=2.31.0
python-whois>=0.8.0
python-docx>=0.8.11
openpyxl>=3.1.2
PyPDF2>=3.0.1
cryptography>=41.0.0
Pillow>=10.0.0
```

### PyInstaller Konfigürasyonu

```spec
# main.spec
a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('config', 'config'),
        ('signatures.json', '.'),
        ('whitelist.json', '.'),
        ('admin_manifest.xml', '.')
    ],
    hiddenimports=[
        'customtkinter',
        'psutil',
        'requests',
        'python-whois',
        'docx',
        'openpyxl',
        'PyPDF2',
        'cryptography'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)
```

## 🧪 Test Stratejisi

### Unit Testler

```python
# test_regex_patterns.py
import unittest
from regex_patterns import PII_PATTERNS
import re

class TestRegexPatterns(unittest.TestCase):
    def test_tckn_pattern(self):
        """TCKN regex pattern'ının doğru çalıştığını test eder."""
        pattern = PII_PATTERNS['tckn']
        
        # Geçerli TCKN'ler
        valid_tckns = ['12345678901', '98765432109']
        for tckn in valid_tckns:
            self.assertIsNotNone(re.match(pattern, tckn))
        
        # Geçersiz TCKN'ler
        invalid_tckns = ['1234567890', '123456789012', 'abcdefghijk']
        for tckn in invalid_tckns:
            self.assertIsNone(re.match(pattern, tckn))

if __name__ == '__main__':
    unittest.main()
```

### Entegrasyon Testleri

```python
# test_url_checker.py
import unittest
from unittest.mock import patch, Mock
from url_checker import check_urlhaus, check_virustotal

class TestURLChecker(unittest.TestCase):
    @patch('requests.post')
    def test_urlhaus_check(self, mock_post):
        """URLhaus API kontrolünün doğru çalıştığını test eder."""
        # Mock response
        mock_response = Mock()
        mock_response.json.return_value = {
            'query_status': 'ok',
            'url_status': 'online',
            'threat': 'malware'
        }
        mock_post.return_value = mock_response
        
        # Test
        result, message = check_urlhaus('http://test.com')
        self.assertEqual(result['threat'], 'malware')
```

## 🔄 Geliştirme Süreci

### Kod Standartları

1. **PEP 8 Uyumluluğu**: Python kod standartlarına uygunluk
2. **Docstring Kullanımı**: Tüm fonksiyonlar için docstring
3. **Tip Belirteçleri**: Type hints kullanımı
4. **Hata Yönetimi**: Kapsamlı exception handling
5. **Loglama**: Detaylı log kayıtları

### Git Workflow

```bash
# Feature branch oluşturma
git checkout -b feature/new-feature

# Değişiklikleri commit etme
git add .
git commit -m "feat: add new security scanning feature"

# Pull request oluşturma
git push origin feature/new-feature
```

### Code Review Süreci

1. **Otomatik Testler**: CI/CD pipeline'da test çalıştırma
2. **Kod Kalitesi**: Linting ve formatting kontrolü
3. **Güvenlik Kontrolü**: Dependency vulnerability scanning
4. **Manuel Review**: Kod gözden geçirme
5. **Test Coverage**: Test coverage raporu

## 📈 Performans Metrikleri

### Tarama Performansı

- **Sistem Taraması**: ~30-60 saniye (ortalama sistem)
- **PII Taraması**: ~5-15 saniye (1MB dosya)
- **URL Kontrolü**: ~3-8 saniye (API bağımlı)
- **Bellek Kullanımı**: ~100-200MB (aktif tarama sırasında)

### Optimizasyon Hedefleri

1. **Paralel İşleme**: Çoklu CPU çekirdeği kullanımı
2. **Bellek Optimizasyonu**: Chunk-based processing
3. **Cache Sistemi**: Sık kullanılan verilerin önbelleklenmesi
4. **Lazy Loading**: On-demand veri yükleme

## 🔮 Gelecek Planları

### Kısa Vadeli (3-6 ay)

1. **Dosya İzleme Modülü**: Real-time dosya değişiklik takibi
2. **Ağ Trafiği Analizi**: Paket yakalama ve analiz
3. **Gelişmiş Raporlama**: PDF/HTML rapor oluşturma
4. **Plugin Sistemi**: Üçüncü parti eklenti desteği

### Orta Vadeli (6-12 ay)

1. **Machine Learning**: AI tabanlı tehdit tespiti
2. **Cloud Entegrasyonu**: Bulut tabanlı veri analizi
3. **Multi-Platform**: Linux ve macOS desteği
4. **Enterprise Features**: Kurumsal özellikler

### Uzun Vadeli (1+ yıl)

1. **Distributed Scanning**: Dağıtık tarama sistemi
2. **Threat Intelligence**: Tehdit istihbarat entegrasyonu
3. **Automated Response**: Otomatik tehdit yanıtı
4. **Compliance Reporting**: Uyumluluk raporlama

## 🤝 Katkıda Bulunma

### Geliştirici Gereksinimleri

- Python 3.8+
- Git
- Virtual environment
- IDE (PyCharm, VS Code, vb.)

### Katkı Süreci

1. **Fork**: Projeyi fork edin
2. **Branch**: Feature branch oluşturun
3. **Develop**: Özelliği geliştirin
4. **Test**: Testleri çalıştırın
5. **Submit**: Pull request gönderin

### İletişim

- **Geliştirici**: Yiğit Yücel
- **E-posta**: [Geliştirici e-posta adresi]
- **GitHub**: [Proje repository linki]
- **Dokümantasyon**: [Dokümantasyon linki]

---

Bu geliştirici dokümantasyonu, Güvenlik Yardımcısı projesinin teknik detaylarını ve geliştirme süreçlerini kapsar. Güncel bilgiler için resmi dokümantasyonu takip edin. 