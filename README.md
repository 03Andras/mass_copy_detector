# Mass Copy Detector by NA - Dokumentácia

[https://github.com/03Andras/mass_copy_detector](https://github.com/03Andras/mass_copy_detector)

## Popis
Systém na monitorovanie veľkých dátových prenosov na sieťových diskoch.

## Inštalácia krok za krokom

### 1. Inštalácia webového servera

#### Požiadavky
- Webový server s PHP 7.4+ (Apache, Nginx, IIS)
- Prístupové práva na zápis do priečinka

#### Postup inštalácie
1. **Stiahnite si projekt** z GitHub repozitára:
   ```
   https://github.com/03Andras/mass_copy_detector
   ```

2. **Nahrajte súbory na váš webový server**
   - Skopírujte súbory `index.php` do priečinka na webovom serveri (napr. `/var/www/html/masscopy/` alebo `C:\inetpub\wwwroot\masscopy\`)

3. **Nastavte oprávnenia**
   - Na Linuxe: `chmod 755 /var/www/html/masscopy/`
   - Na Linuxe: `chmod 777 /var/www/html/masscopy/data/` (priečinok sa vytvorí automaticky)
   - Na Windows: Uistite sa, že webový server má práva na zápis do priečinka

4. **Upravte konfiguráciu v `index.php`**
   ```php
   define('PASSWORD', 'vase_bezpecne_heslo');  // ZMEŇTE HESLO!
   define('DATA_DIR', 'data');                 
   define('API_TOKEN', 'vase_bezpecne_token'); // ZMEŇTE TOKEN!
   ```

5. **Otvorte webové rozhranie**
   - V prehliadači otvorte: `https://vas-server.com/masscopy/`
   - Prihláste sa s heslom, ktoré ste nastavili

### 2. Inštalácia na klientskych počítačoch (Windows)

#### Požiadavky
- Windows 7/8/10/11 alebo Windows Server 2012+
- PowerShell 5.1+
- Administratívne práva (iba pre prvé spustenie)

#### Postup inštalácie

1. **Stiahnite skript `masscopy.ps1`** z projektu na klientsky počítač

2. **Upravte parametre v skripte** (voliteľné)
   - Otvorte `masscopy.ps1` v textovom editore
   - Upravte riadok 27 - URL vášho API servera:
     ```powershell
     [string]$ApiUrl = 'https://vas-server.com/masscopy/',
     ```
   - Upravte riadok 28 - API token (musí sa zhodovať s tokennom v `index.php`):
     ```powershell
     [string]$ApiToken = 'vase_bezpecne_token',
     ```

3. **Prvé spustenie AKO ADMINISTRÁTOR**
   - Kliknite pravým tlačidlom na PowerShell a vyberte "Spustiť ako správca"
   - Spustite príkaz:
     ```powershell
     powershell -NoProfile -ExecutionPolicy Bypass -File "C:\cesta\k\masscopy.ps1"
     ```

4. **Automatická samoinstalacia**
   Pri prvom spustení ako administrátor sa skript:
   - ✅ Skopíruje sám do `C:\masscopy\masscopy.ps1`
   - ✅ Vytvorí naplánovanú úlohu (Task Scheduler) s názvom "MassCopyDetector"
   - ✅ Nastaví spustenie každých 5 minút
   - ✅ Nastaví spustenie ako SYSTEM account s najvyššími právami

5. **Overenie inštalácie**
   - Otvorte Task Scheduler (`taskschd.msc`)
   - Vyhľadajte úlohu "MassCopyDetector"
   - Skontrolujte, či je úloha aktívna (Ready/Running)
   - Skontrolujte, či existuje súbor `C:\masscopy\masscopy.ps1`

6. **Overenie funkčnosti**
   - Počkajte 5-10 minút
   - Otvorte webové rozhranie na `https://vas-server.com/masscopy/`
   - Mali by ste vidieť záznamy z klientského počítača
   - V záznamoch sa zobrazí:
     - Názov počítača
     - Umiestnenie skriptu (`C:\masscopy\masscopy.ps1`)
     - Stav Task Schedulera (Ready/Running)

### 3. Monitoring a správa

#### Webové rozhranie
- **URL**: `https://vas-server.com/masscopy/`
- **Funkcie**:
  - 📊 Prehľad všetkých meraní
  - ⚠️ Filter na alerty (prekročené prahy)
  - 📈 Časová os aktivít
  - 💻 Zoznam monitorovaných počítačov
  - 📁 Detaily o prenášaných súboroch
  - ⚙️ Stav inštalácie Task Schedulera na každom počítači

#### Riešenie problémov
- **Skript sa nespúšťa automaticky**:
  - Otvorte Task Scheduler a skontrolujte úlohu "MassCopyDetector"
  - Skontrolujte históriu úloh (Enable History v Task Scheduleri)
  
- **Nevidia sa dáta na webovom rozhraní**:
  - Skontrolujte, či je API URL správne nastavená v skripte
  - Skontrolujte, či sa zhoduje API token medzi skriptom a `index.php`
  - Skontrolujte firewall a sieťové pripojenie

- **Skript hlási chyby**:
  - Skontrolujte, či má používateľ/SYSTEM prístup k sieťovým diskom
  - Skontrolujte audit politiky (skript ich nastavuje automaticky)

## Štruktúra projektu

### Súbory
- `index.php` - Webové rozhranie pre zobrazovanie dát a API endpoint
- `masscopy.ps1` - PowerShell skript pre monitorovanie sieťových diskov
- `data/` - Priečinok pre JSON súbory (vytvorí sa automaticky)

### Konfigurácia

#### index.php
Na začiatku súboru nájdete sekciu konfigurácie:
```php
define('PASSWORD', 'Heslo');           // Heslo pre prihlásenie
define('DATA_DIR', 'data');               // Priečinok pre JSON súbory
define('API_TOKEN', 'Heslo');          // Token pre API autentifikáciu
```

#### masscopy.ps1
Parametre scriptu:
```powershell
-Minuty         # Časové okno v minútach (predvolené: 5)
-PrahMB         # Prah v MB (predvolené: 100)
-ApiUrl         # URL API (napr: https://CONFIGURE-YOUR-SERVER-URL/masscopy/)
-ApiToken       # Bezpečnostný token (predvolené: Heslo)
```

## Funkcie

### index.php
- **Autentifikácia**: Prihlásenie pomocou hesla
- **API endpoint**: Prijíma JSON dáta z PowerShell skriptu
- **Úložisko**: JSON súbory rozdelené podľa dní (YYYYMMDD.json)
- **Kontrola oprávnení**: Automatická kontrola práv na zápis
- **Vizualizácia**: Prehľadné zobrazenie dát s filtrom na alerty
- **Monitoring inštalácie**: Zobrazenie umiestnenia skriptov a stavu Task Schedulera

### masscopy.ps1
- **Samoinstalácia**: Automatická kópia do C:\masscopy
- **Task Scheduler**: Automatické nastavenie na spustenie každých 5 minút
- **Reporting**: Odosielanie stavu inštalácie a Task Schedulera na server
- **Audit 4663**: Primárna metóda sledovania súborov
- **Fallback LastAccess**: Záložná metóda pri nedostupnom audit logu
- **Sieťové disky**: Automatické vyhľadávanie všetkých sieťových diskov
- **API komunikácia**: Odosielanie dát na PHP endpoint

## Formát JSON súborov

Súbory sú uložené v priečinku `data/` vo formáte `YYYYMMDD.json`:
- `20251217.json` - dáta za 17. december 2025
- `20251218.json` - dáta za 18. december 2025
- atď.

## Bezpečnosť
- API token pre autentifikáciu požiadaviek
- Automatická kontrola oprávnení na zápis
- Session-based autentifikácia vo webovom rozhraní
- **DÔLEŽITÉ**: Zmeňte predvolené heslo a API token po inštalácii!
