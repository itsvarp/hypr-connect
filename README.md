# Hypr Connect Agent (Rust)

Windows ve Linux'ta aynı kaynak kodundan çalışan yerel ağ ajanıdır. Varsayılan olarak
`Documents/Hypr Connect Files` klasörünü `8765` portunda Android uygulamasına açar.

## Çalıştırma

```bash
cd hypr-connect-agent
MRP_TOKEN='uzun-ve-rastgele-bir-anahtar' cargo run --release
```

Ajan başladığında terminalde bir eşleştirme QR kodu gösterir. Android uygulamasındaki
**QR İLE BAĞLAN** düğmesi bu koddan adresi ve erişim anahtarını alıp otomatik bağlanır.
Yeni eşleştirmelerde ajan HTTPS kullanır. Android uygulaması QR içindeki SHA-256
sertifika parmak izini sabitleyerek sahte bir yerel sunucuya bağlanmayı reddeder.
HTTP bağlantıları kabul edilmez; eski HTTP eşleştirmeleri yeni QR koduyla yenilenmelidir.
Birden fazla ağ kartı varsa QR'da kullanılacak IP'yi
açıkça belirtebilirsiniz:

```bash
MRP_ADVERTISE_ADDRESS='192.168.1.10' MRP_TOKEN='uzun-ve-rastgele-bir-anahtar' cargo run --release
```

İsterseniz klasörü ve adresi değiştirebilirsiniz:

```bash
MRP_FILES_DIR='/başka/klasör' MRP_BIND='0.0.0.0:8765' cargo run --release
```

Linux kullanıcı-servisi örneği `hypr-connect-agent.service` dosyasındadır. Binary'yi
`/usr/local/bin/hypr-connect-agent`, birimi `~/.config/systemd/user/hypr-connect-agent.service` konumuna
kopyalayın; `~/.config/hypr-connect-agent.env` içine `MRP_TOKEN=...` yazıp
`systemctl --user enable --now hypr-connect-agent` komutunu çalıştırın. Güç komutları için
kullanıcıya yalnızca gereken güç komutları için yetki verilmelidir. Ekran kilidi
Omarchy'de `omarchy-system-lock`, diğer systemd tabanlı Linux sistemlerinde
`loginctl lock-sessions` ile çalışır. Windows'ta çalışma istasyonu kilitlenir.
Windows'ta `cargo build --release` sonrasında yönetici PowerShell ile
`./install-windows.ps1` çalıştırın. `Hypr Connect Agent` zamanlanmış görevi,
kullanıcı oturum açtığında o oturumda başlar; böylece pano, medya ve ekran görüntüsü
işlemleri masaüstüne erişebilir. Oturum açılmadan önce ajan bağlantısı kurulmaz.
Yerel alt ağdan TCP 8765 erişimi açılır ve gerçek S5 kapanışı için Hızlı Başlatma
kapatılır. Ajan hata durumunda otomatik yeniden başlatılır.

Erişim anahtarı `mrp-agent.env`, TLS kimliği ise sabit ortak klasörün
`.hypr-connect-private` alt klasöründe korunur. Bu dosyaları silmeyin.
QR kodu paylaşılan klasörün `.hypr-connect-private/agent.log` dosyasında bulunur.
Bu klasör yalnızca kullanıcı ve yöneticiler tarafından okunabilir. Ethernet MAC adresi eşleştirmeye eklenir.
Telefon aynı yerel ağa bağlıyken UYANDIR düğmesi bilgisayar kapalı olsa da
UDP 7 ve 9 üzerinden magic packet gönderir; S5 açılışı BIOS ve donanım desteğine bağlıdır.
Modem yeniden başlayınca DHCP IP adresi değişebilir; uygulama kayıtlı anahtar ve
sertifika sabitlemesi ile yeni IP'yi yerel ağda arar. Fabrika sıfırlamasında Wi-Fi
veya alt ağ ayarları değişirse telefonu yeni ağa bağlamak gerekir.

## Özellikler

- Kategorilenebilir, klasör destekli dosya listesi; yükleme, indirme, silme,
  taşıma/yeniden adlandırma ve kesilen aktarımı devam ettirme
- Ortak metin panosu
- CPU, bellek, disk, sıcaklık, pil ve ağ bilgileri
- Medya oynatma ve ses kontrolleri
- PNG ekran görüntüsü
- Güç, hazırda bekletme ve ekran kilidi kontrolleri
- HTTPS ve QR üzerinden sertifika parmak izi sabitleme
- TLS WebSocket üzerinden canlı sistem durumu ile gecikmesi azaltılmış medya ve kontrol komutları

> Ajan yalnızca güvenilen yerel ağ veya Tailscale üzerinde kullanılmalıdır.
> Erişim anahtarını ve QR eşleştirme kodunu paylaşmayın.
