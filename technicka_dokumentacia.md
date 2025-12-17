# Technická dokumentácia - Mass Copy Detector by NA

## Obsah
1. [Prehľad systému](#prehľad-systému)
2. [Architektúra](#architektúra)
3. [PowerShell skript (masscopy.ps1)](#powershell-skript-masscopyps1)
4. [PHP API endpoint (index.php)](#php-api-endpoint-indexphp)
5. [Tok dát](#tok-dát)
6. [Konfigurácia](#konfigurácia)
7. [Bezpečnosť](#bezpečnosť)
8. [Dátový formát](#dátový-formát)
9. [Riešenie problémov](#riešenie-problémov)
10. [Výkon a optimalizácia](#výkon-a-optimalizácia)
11. [Rozšírenia a customizácia](#rozšírenia-a-customizácia)

---

## Prehľad systému

Mass Copy Detector je distribuovaný monitorovací systém určený na detekciu veľkých dátových prenosov na sieťových diskoch v podnikovom prostredí.

### Hlavné komponenty:
- **PowerShell skript** (`masscopy.ps1`) - klientska časť bežiaca na Windows počítačoch
- **PHP API server** (`index.php`) - serverová časť zbierajúca a vizualizujúca dáta
- **JSON úložisko** - súbory s nameranými dátami organizované podľa dní

### Princíp fungovania:
1. PowerShell skript sa spúšťa pravidelne (každých 5 minút) na klientskych počítačoch
2. Skript monitoruje aktivitu na sieťových diskoch pomocou Windows Audit logov alebo LastAccess časov
3. Zhromaždené dáta sa odošlú cez HTTPS POST request na PHP API
4. PHP API uloží dáta do JSON súboru a sprístupní ich cez webové rozhranie
5. Administrátori môžu cez webové rozhranie sledovať aktivity a alerty

---

## Architektúra

```
┌─────────────────────────────────────────────────────────────┐
│                    Windows Client PC                        │
│  ┌────────────────────────────────────────────────────┐    │
│  │  C:\masscopy\masscopy.ps1                          │    │
│  │  - Spúšťané Task Schedulerom každých 5 min         │    │
│  │  - Beží ako SYSTEM alebo user                      │    │
│  │  - Číta Audit logy / LastAccess časy               │    │
│  └────────────────────────────────────────────────────┘    │
│                          │                                   │
│                          │ HTTPS POST                        │
│                          │ JSON payload                      │
│                          ▼                                   │
└──────────────────────────┼───────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Web Server (PHP)                         │
│  ┌────────────────────────────────────────────────────┐    │
│  │  index.php                                         │    │
│  │  - API endpoint (/masscopy/)                       │    │
│  │  - Autentifikácia cez API token                    │    │
│  │  - Ukladanie do data/*.json                        │    │
│  │  - Webové UI pre zobrazenie                        │    │
│  └────────────────────────────────────────────────────┘    │
│  ┌────────────────────────────────────────────────────┐    │
│  │  data/                                             │    │
│  │  - 20251217.json                                   │    │
│  │  - 20251218.json                                   │    │
│  │  - ...                                             │    │
│  └────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## PowerShell skript (masscopy.ps1)

### Parametre a konfigurácia

Skript prijíma nasledujúce parametre:

```powershell
param(
    [int]$Minuty        = 5,      # Časové okno monitorovania v minútach
    [int]$PrahMB        = 100,    # Prah v MB pre spustenie alertu
    [string]$ApiUrl     = 'https://CONFIGURE-YOUR-SERVER-URL/masscopy/',
    [string]$ApiToken   = 'Heslo', # API token pre autentifikáciu
    [switch]$PreskocAudit,        # Preskočiť nastavenie audit politík
    [switch]$Restartovany         # Interný parameter pre reštart
)
```

### Životný cyklus skriptu

#### 1. Kontrola administrátorských práv
```powershell
$jeAdmin = ([Security.Principal.WindowsPrincipal] 
    [Security.Principal.WindowsIdentity]::GetCurrent())
    .IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```
- Detekuje, či skript beží s admin právami
- Admin práva sú potrebné pre samoinstaláciu a nastavenie audit politík

#### 2. Samoinstalačná logika

Ak skript **beží ako admin** a **nie je v cieľovom umiestnení**:

##### a) Vytvorenie priečinka
```powershell
$cielovaCesta = 'C:\masscopy'
if (-not (Test-Path $cielovaCesta)) {
    New-Item -ItemType Directory -Path $cielovaCesta -Force
}
```

##### b) Skopírovanie skriptu
```powershell
$cielovyScript = Join-Path $cielovaCesta 'masscopy.ps1'
# Kontrola, či už existuje a či je iný (SHA256 hash)
if ($shouldCopy) {
    Copy-Item -Path $aktualnyScript -Destination $cielovyScript -Force
}
```

##### c) Vytvorenie Task Scheduler úlohy
```powershell
$taskName = 'MassCopyDetector'
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$cielovyScript`" ..."
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 5) `
    -RepetitionDuration ([TimeSpan]::MaxValue)
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" `
    -LogonType ServiceAccount -RunLevel Highest
```

**Dôležité nastavenia Task Schedulera:**
- Spúšťa sa každých **5 minút**
- Beží ako **SYSTEM** účet s najvyššími právami
- **ExecutionTimeLimit**: 4 minúty (aby sa stihol dokončiť pred ďalším spustením)
- **RestartCount**: 3 (automatický reštart pri zlyhaní)
- **StartWhenAvailable**: áno (spustí sa aj keď bol PC vypnutý v čase spustenia)

#### 3. Reštart pod používateľským kontextom

Ak skript beží ako admin, automaticky sa reštartuje pod kontextom **prihláseného používateľa**:

```powershell
if ($jeAdmin -and -not $Restartovany) {
    $pouzivatel = Get-PrihlasenyPouzivatel
    # Vytvorí dočasnú Task Scheduler úlohu
    # Spustí ju pod používateľom
    # Odstráni dočasnú úlohu
    exit
}
```

**Dôvod:** Používateľský kontext má lepší prístup k sieťovým diskom (mapped drives), ktoré sú často mapované len pre konkrétneho používateľa.

#### 4. Nastavenie audit politík

```powershell
function Enable-AuditSubcategories {
    $guids = @(
        '{0cce923f-69ae-11d9-bed3-505054503030}',  # File System
        '{0cce9225-69ae-11d9-bed3-505054503030}'   # Handle Manipulation
    )
    foreach ($g in $guids) {
        auditpol.exe /set /subcategory:"$g" /success:enable
    }
}
```

**Čo sa nastavuje:**
- **File System audit** - sleduje prístup k súborom
- **Handle Manipulation audit** - sleduje manipuláciu s file handles
- Potrebné pre fungovanie metódy **Audit 4663**

#### 5. Zisťovanie sieťových diskov

Skript používa **4 rôzne metódy** pre maximum kompatibility:

##### Metóda 1: COM WScript.Network
```powershell
$nw = New-Object -ComObject WScript.Network
$arr = @($nw.EnumNetworkDrives())
```
- Najspoľahlivejšia metóda
- Funguje pre všetky mapped drives

##### Metóda 2: CIM/WMI (Win32_LogicalDisk)
```powershell
Get-CimInstance Win32_LogicalDisk -Filter "DriveType=4"
```
- DriveType=4 = Network Drive
- Fallback pre prípad, že COM nefunguje

##### Metóda 3: Registry HKEY_USERS
```powershell
Get-ChildItem -Path Registry::HKEY_USERS |
    Where-Object { $_.Name -match 'S-1-5-21-' }
```
- Číta z registry všetkých používateľov
- Umožňuje nájsť disky aj keď nie sú aktívne pripojené

##### Metóda 4: PSDrive
```powershell
Get-PSDrive -PSProvider FileSystem |
    Where-Object { $_.DisplayRoot -and ($_.Name -match '^[A-Z]$') }
```
- PowerShell vlastná metóda
- Ďalší fallback

**Deduplikácia:**
```powershell
$zoznam = $zoznam | Group-Object DeviceID | 
    ForEach-Object { $_.Group | Select-Object -First 1 }
```

#### 6. Zber dát o súborových aktivitách

Skript používa dve metódy:

##### Primárna metóda: Audit 4663

```powershell
function Get-Audit4663PodlaDiska {
    $udalosti = Get-WinEvent -FilterHashtable @{
        LogName='Security'
        Id=4663
        StartTime=$casovyLimit
    }
    foreach ($e in $udalosti) {
        $xml = [xml]$e.ToXml()
        $nazovObj = $xml.Event.EventData.Data | 
            Where-Object { $_.Name -eq 'ObjectName' } | 
            Select-Object -ExpandProperty '#text'
        # ... ďalšie parsovanie
    }
}
```

**Čo zbiera:**
- **ObjectName**: Plná cesta k súboru
- **ObjectType**: Typ objektu (File)
- **AccessMask**: Typ prístupu (čítanie/zápis)
- **ProcessId**: ID procesu, ktorý pristupoval
- **ProcessName**: Názov procesu

**Výhody:**
- Presné informácie o prístupe
- Neovplyvňuje výkon súborového systému
- Obsahuje info o procese

**Nevýhody:**
- Vyžaduje audit politiku
- Funguje len ak je audit povolený

##### Záložná metóda: LastAccess/LastWrite

```powershell
function Get-FallbackPristupPodlaDiska {
    foreach ($d in $sietoveDisk) {
        Get-ChildItem -LiteralPath "$($d.DeviceID)\" -File -Recurse -Force |
            Where-Object { 
                ($_.LastAccessTime -ge $casovyLimit) -or 
                ($_.LastWriteTime -ge $casovyLimit) 
            }
    }
}
```

**Kedy sa používa:**
- Ak Audit 4663 nevrátil žiadne záznamy
- Automatický fallback

**Výhody:**
- Funguje vždy (nepotrebuje audit politiku)
- Jednoduché na implementáciu

**Nevýhody:**
- Pomalé (prechádza celý file system)
- Neobsahuje info o procese
- LastAccessTime môže byť vypnutý (výkon)

#### 7. Spracovanie a sumarizácia dát

```powershell
$suhrn = $riadky | Group-Object Drive | ForEach-Object {
    $suma = ($_.Group | Measure-Object -Property SizeMB -Sum).Sum
    $subory = $_.Group | Select-Object ObjectName, SizeMB | 
        Sort-Object SizeMB -Descending
    [PSCustomObject]@{
        Drive    = $_.Name
        Files    = $_.Count
        TotalMB  = [Math]::Round($suma, 2)
        FileList = $subory
    }
}
```

**Výstup:**
- Zoskupenie podľa disku
- Počet súborov
- Celková veľkosť v MB
- Detailný zoznam súborov

#### 8. Detekcia alertov

```powershell
$prekrocene = $suhrn | Where-Object { $_.TotalMB -ge $PrahMB } | 
    Select-Object -ExpandProperty Drive
```

Alert sa spustí, ak **celková veľkosť prenesených dát** na disku **prekročí prah** (predvolene 100 MB).

#### 9. Zber informácií o inštalácii

```powershell
# Stav Task Schedulera
$task = Get-ScheduledTask -TaskName 'MassCopyDetector'
$taskStatus = $task.State.ToString().ToLower()  # ready, running, disabled

# Umiestnenie skriptu
$installedPath = $PSCommandPath  # Aktuálna cesta k skriptu
```

#### 10. Zostavenie payload a odoslanie

```powershell
$payload = [ordered]@{
    machine           = $env:COMPUTERNAME
    user              = $env:USERNAME
    timestamp         = (Get-Date).ToString('o')  # ISO 8601
    timeWindowMinutes = $Minuty
    thresholdMB       = $PrahMB
    method            = $pouzitaMetoda  # 'audit_4663' alebo 'fallback_lastaccess'
    drives            = $suhrn
    exceeded          = @($prekrocene)
    alert             = ($prekrocene.Count -gt 0)
    installedPath     = $installedPath
    taskSchedulerStatus = $taskStatus
    runningAsAdmin    = $jeAdmin
}

$json = $payload | ConvertTo-Json -Depth 8
$headers = @{
    'Content-Type' = 'application/json'
    'X-Api-Token' = $ApiToken
}
Invoke-RestMethod -Method POST -Uri $ApiUrl -Headers $headers -Body $json -TimeoutSec 30
```

**Timeout:** 30 sekúnd (aby nečakal príliš dlho pri sieťovom výpadku)

---

## PHP API endpoint (index.php)

### Konfigurácia

```php
define('PASSWORD', 'Heslo');      // Heslo pre webové rozhranie
define('DATA_DIR', 'data');       // Priečinok pre JSON súbory
define('API_TOKEN', 'Heslo');     // Token pre API autentifikáciu
```

### Architektúra

PHP skript funguje v **dvoch režimoch**:

1. **API režim** - prijíma POST requesty od PowerShell skriptov
2. **UI režim** - zobrazuje webové rozhranie pre administrátorov

#### Režim detekcia

```php
// API režim
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['password'])) {
    // Spracovanie API requestu
}

// UI režim
if (!isset($_SESSION['logged_in']) || !$_SESSION['logged_in']) {
    // Prihlasovací formulár
}
```

### API endpoint

#### 1. Autentifikácia

```php
// Získanie tokenu z HTTP hlavičiek
$token = '';
if (function_exists('getallheaders')) {
    $headers = getallheaders();
    $token = $headers['X-Api-Token'] ?? '';
} elseif (function_exists('apache_request_headers')) {
    $headers = apache_request_headers();
    $token = $headers['X-Api-Token'] ?? '';
} else {
    // Fallback pre nginx/IIS
    $token = $_SERVER['HTTP_X_API_TOKEN'] ?? '';
}

if ($token !== API_TOKEN) {
    http_response_code(401);
    echo json_encode(['status' => 'error', 'message' => 'Neplatný token']);
    exit;
}
```

**Podporované metódy:**
- `getallheaders()` - Apache
- `apache_request_headers()` - Apache alternatíva
- `$_SERVER['HTTP_X_API_TOKEN']` - nginx/IIS

#### 2. Prijatie a validácia dát

```php
$json = file_get_contents('php://input');
$data = json_decode($json, true);

if ($data) {
    // Pridanie času prijatia
    $data['received_at'] = date('Y-m-d H:i:s');
}
```

#### 3. Uloženie dát

```php
// Názov súboru podľa dátumu
function getDataFile($date = null) {
    if ($date === null) {
        $date = date('Ymd');  // YYYYMMDD
    }
    return DATA_DIR . '/' . $date . '.json';
}

// Načítanie existujúcich dát
$dataFile = getDataFile();
$allData = [];
if (file_exists($dataFile)) {
    $content = file_get_contents($dataFile);
    $allData = json_decode($content, true) ?: [];
}

// Pridanie nového záznamu
$allData[] = $data;

// Uloženie
file_put_contents($dataFile, 
    json_encode($allData, 
        JSON_PRETTY_PRINT | 
        JSON_UNESCAPED_UNICODE | 
        JSON_UNESCAPED_SLASHES
    )
);
```

**Formát súboru:**
- `20251217.json` - všetky záznamy za 17. december 2025
- `20251218.json` - všetky záznamy za 18. december 2025

#### 4. Odpoveď

```php
http_response_code(200);
echo json_encode(['status' => 'ok', 'message' => 'Dáta uložené']);
```

### Webové rozhranie

#### 1. Autentifikácia

```php
session_start();

if (isset($_POST['password'])) {
    if ($_POST['password'] === PASSWORD) {
        $_SESSION['logged_in'] = true;
    }
    header('Location: index.php');
    exit;
}
```

**Session-based autentifikácia:**
- Heslo sa kontroluje len raz
- Session trvá podľa nastavenia PHP
- Odhlásenie zničí session

#### 2. Načítanie dát

```php
function getAllData() {
    $allData = [];
    $files = glob(DATA_DIR . '/*.json');
    if ($files) {
        foreach ($files as $file) {
            $content = @file_get_contents($file);
            if ($content !== false) {
                $data = json_decode($content, true);
                if ($data && is_array($data)) {
                    $allData = array_merge($allData, $data);
                }
            }
        }
    }
    return $allData;
}
```

**Proces:**
1. Nájde všetky JSON súbory v `data/`
2. Načíta každý súbor
3. Spojí všetky záznamy do jedného poľa

#### 3. Filtrovanie

```php
$filter = isset($_GET['filter']) ? $_GET['filter'] : 'all';

if ($filter === 'alert') {
    $filteredData = array_filter($allData, function($item) {
        return isset($item['alert']) && $item['alert'] === true;
    });
}
```

**Dostupné filtre:**
- `all` - všetky záznamy
- `alert` - len záznamy s alertom

#### 4. Časová os (Timeline)

```php
function getTimeline($data) {
    $timeline = [];
    foreach ($data as $record) {
        if (!empty($record['timestamp'])) {
            $dt = new DateTime($record['timestamp']);
            $hourKey = $dt->format('Y-m-d H:00');
            if (!isset($timeline[$hourKey])) {
                $timeline[$hourKey] = ['count' => 0, 'alerts' => 0];
            }
            $timeline[$hourKey]['count']++;
            if ($record['alert'] ?? false) {
                $timeline[$hourKey]['alerts']++;
            }
        }
    }
    ksort($timeline);
    return $timeline;
}
```

**Výstup:**
- Zoskupenie meraní podľa hodín
- Počet meraní v každej hodině
- Počet alertov v každej hodině

#### 5. Štatistiky

```php
<div class="stat-box">
    <h3>Celkovy pocet merani</h3>
    <div class="number"><?= count($allData) ?></div>
</div>
<div class="stat-box">
    <h3>Pocet alertov</h3>
    <div class="number">
        <?= count(array_filter($allData, fn($i) => $i['alert'] ?? false)) ?>
    </div>
</div>
```

#### 6. Zobrazenie záznamov

```php
foreach ($filteredData as $record) {
    // Základné info
    echo $record['machine'];      // Názov počítača
    echo $record['user'];         // Používateľ
    echo $record['timestamp'];    // Čas merania
    echo $record['method'];       // Metóda (audit_4663/fallback)
    
    // Info o inštalácii
    echo $record['installedPath'];       // Umiestnenie skriptu
    echo $record['taskSchedulerStatus']; // Stav Task Schedulera
    
    // Disky a súbory
    foreach ($record['drives'] as $drive) {
        echo $drive['Drive'];     // Písmeno disku
        echo $drive['Files'];     // Počet súborov
        echo $drive['TotalMB'];   // Celková veľkosť
        
        foreach ($drive['FileList'] as $file) {
            echo $file['ObjectName'];  // Cesta k súboru
            echo $file['SizeMB'];      // Veľkosť súboru
        }
    }
}
```

---

## Tok dát

### Kompletný flow

```
1. SPUSTENIE SKRIPTU (každých 5 min)
   ↓
2. KONTROLA ADMINISTRÁTORSKÝCH PRÁV
   ↓
   ├─ Ak admin a nie v C:\masscopy
   │  ├─ Skopírovanie do C:\masscopy
   │  ├─ Vytvorenie Task Scheduler úlohy
   │  └─ Reštart pod používateľským kontextom
   │
   └─ Ak nie admin alebo už v C:\masscopy
      ↓
3. NASTAVENIE AUDIT POLITÍK (ak admin)
   ↓
4. ZISTENIE SIEŤOVÝCH DISKOV
   ├─ COM WScript.Network
   ├─ CIM Win32_LogicalDisk
   ├─ Registry HKEY_USERS
   └─ PSDrive
   ↓
5. ZBER DÁT O SÚBOROVÝCH AKTIVITÁCH
   ├─ Pokus o Audit 4663 (primárne)
   │  └─ Parsovanie Security Event Log
   │
   └─ Fallback LastAccess (ak Audit zlyhá)
      └─ Prechádzanie súborového systému
   ↓
6. SPRACOVANIE DÁT
   ├─ Zoskupenie podľa diskov
   ├─ Sumarizácia veľkostí
   └─ Detekcia prekročenia prahu
   ↓
7. ZOSTAVENIE PAYLOAD
   ├─ Info o počítači a používateľovi
   ├─ Časové údaje
   ├─ Súhrnné dáta o diskoch
   ├─ Info o inštalácii
   └─ Alert flag
   ↓
8. ODOSLANIE NA API
   ├─ HTTPS POST request
   ├─ JSON payload
   └─ X-Api-Token hlavička
   ↓
   ↓ SIEŤ
   ↓
9. API PRIJATIE (index.php)
   ├─ Kontrola API tokenu
   ├─ Validácia JSON
   └─ Pridanie received_at
   ↓
10. ULOŽENIE DÁT
    ├─ Načítanie existujúceho JSON súboru (YYYYMMDD.json)
    ├─ Pridanie nového záznamu
    └─ Uloženie späť do súboru
    ↓
11. ODPOVEĎ KLIENTOVI
    └─ {"status": "ok", "message": "Dáta uložené"}
    ↓
12. ZOBRAZENIE VO WEBOVOM ROZHRANÍ
    ├─ Načítanie všetkých JSON súborov
    ├─ Filtrovanie (all/alert)
    ├─ Generovanie timeline
    ├─ Výpočet štatistík
    └─ Zobrazenie záznamov
```

### Časovanie

```
T+0:00   - Task Scheduler spustí skript
T+0:05   - Skript zistí sieťové disky
T+0:10   - Skript zhromaždí dáta o súboroch
T+0:15   - Skript odošle dáta na API
T+0:20   - API uloží dáta
T+0:21   - Skript skončí
T+5:00   - Task Scheduler spustí skript znova
```

**Poznámky:**
- ExecutionTimeLimit je 4 minúty
- Interval je 5 minút
- 1 minúta rezerva medzi spusteniami

---

## Konfigurácia

### PowerShell skript (masscopy.ps1)

#### Parametre pri spustení

```powershell
# Príklad: Monitorovať posledných 10 minút, prah 200 MB
powershell -File masscopy.ps1 -Minuty 10 -PrahMB 200 -ApiToken "MojToken123"
```

#### Predvolené hodnoty v skripte

```powershell
[int]$Minuty        = 5
[int]$PrahMB        = 100
[string]$ApiUrl     = 'https://CONFIGURE-YOUR-SERVER-URL/masscopy/'
[string]$ApiToken   = 'Heslo'
```

**Zmena predvolených hodnôt:**
1. Otvorte `masscopy.ps1` v editore
2. Upravte riadky 25-28
3. Uložte súbor
4. Pri ďalšom spustení sa použijú nové hodnoty

#### Task Scheduler parametre

Pri vytváraní Task Scheduler úlohy sa parametre zakódujú do argumentov:

```powershell
-Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden 
    -File `"$cielovyScript`" 
    -Minuty $Minuty 
    -PrahMB $PrahMB 
    -ApiUrl `"$ApiUrl`" 
    -ApiToken `"$ApiToken`""
```

**Zmena parametrov v Task Scheduleri:**
1. Otvorte Task Scheduler (`taskschd.msc`)
2. Nájdite úlohu "MassCopyDetector"
3. Upravte "Actions" → "Edit" → "Arguments"
4. Zmeňte hodnoty parametrov
5. Uložte

### PHP API (index.php)

#### Základná konfigurácia

```php
define('PASSWORD', 'Heslo');      // Heslo pre UI
define('DATA_DIR', 'data');       // Priečinok pre dáta
define('API_TOKEN', 'Heslo');     // Token pre API
```

**DÔLEŽITÉ:** Zmeňte predvolené heslo a token!

#### Oprávnenia

**Linux:**
```bash
chmod 755 /var/www/html/masscopy/
chmod 777 /var/www/html/masscopy/data/
```

**Windows IIS:**
- IIS_IUSRS musí mať práva na zápis do `data/`

#### Session konfigurácia

PHP používa predvolené session nastavenia. Pre úpravu pridajte do `index.php`:

```php
// Session timeout 8 hodín
ini_set('session.gc_maxlifetime', 28800);
session_set_cookie_params(28800);
session_start();
```

---

## Bezpečnosť

### Autentifikácia a autorizácia

#### 1. API Token

```php
// Server-side
define('API_TOKEN', 'VašSilnýToken123!@#');

// Client-side
$headers = @{ 'X-Api-Token' = 'VašSilnýToken123!@#' }
```

**Best practices:**
- Používajte silný, náhodný token (min. 32 znakov)
- Token by mal byť rovnaký na klientovi aj serveri
- Zmeňte token po inštalácii
- Nepoužívajte jednoduchý token ako "Heslo"

#### 2. Session-based UI autentifikácia

```php
session_start();
if (!isset($_SESSION['logged_in']) || !$_SESSION['logged_in']) {
    // Zobrazí prihlasovací formulár
}
```

**Bezpečnostné opatrenia:**
- Session ID sa prenáša v cookie
- Session expiruje podľa PHP nastavení
- Logout zničí session

#### 3. HTTPS

**Dôrazne odporúčané:**
- Všetka komunikácia by mala ísť cez HTTPS
- Chráni API token pred odchytením
- Chráni prihlasovacie heslo

**Nastavenie HTTPS:**
```powershell
$ApiUrl = 'https://server.company.com/masscopy/'  # NIE http://
```

### Oprávnenia súborového systému

#### Windows klient

**Task Scheduler SYSTEM účet:**
- Má prístup k všetkým sieťovým diskom
- Môže čítať Security Event Log
- Môže nastavovať audit politiky

**Používateľský kontext:**
- Má prístup len k vlastným mapped drives
- Nemôže čítať Security Event Log (fallback na LastAccess)

#### Linux/Unix server

**data/ priečinok:**
```bash
drwxrwxrwx  2 www-data www-data  4096 Dec 17 10:00 data/
```

**JSON súbory:**
```bash
-rw-rw-rw-  1 www-data www-data  4096 Dec 17 10:00 20251217.json
```

### Možné bezpečnostné riziká

#### 1. Citlivé údaje v JSON

**Riziko:** JSON súbory obsahujú plné cesty k súborom

**Mitigácia:**
- Chráňte `data/` priečinok (.htaccess / web.config)
- Zabráňte priamemu prístupu k JSON súborom

**.htaccess (Apache):**
```apache
Order Deny,Allow
Deny from all
```

**web.config (IIS):**
```xml
<configuration>
  <system.webServer>
    <security>
      <requestFiltering>
        <denyUrlSequences>
          <add sequence="/data/" />
        </denyUrlSequences>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
```

#### 2. Zneužitie API endpointu

**Riziko:** DoS útoky odosielaním veľkého množstva dát

**Mitigácia:**
- Rate limiting na webovom serveri
- Validácia veľkosti JSON payload
- Firewall pravidlá (povoliť len interné IP)

**Príklad PHP validácie:**
```php
$maxSize = 5 * 1024 * 1024;  // 5 MB
if (strlen($json) > $maxSize) {
    http_response_code(413);
    die('Payload príliš veľký');
}
```

#### 3. XSS útoky

**Riziko:** Injekcia škodlivého kódu cez názvy súborov

**Mitigácia:**
- PHP automaticky escapuje pomocou `htmlspecialchars()`

```php
echo htmlspecialchars($record['machine']);
echo htmlspecialchars($file['ObjectName']);
```

### Auditovanie a logovanie

#### Windows Event Log

Skript zapisuje do:
- **Security Log** (Event ID 4663) - prístupy k súborom
- **Application Log** - chyby PowerShell skriptu

#### PHP error log

```php
// Povoliť logovanie
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', '/var/log/php/masscopy.log');
```

---

## Dátový formát

### JSON payload (PowerShell → PHP)

```json
{
  "machine": "PC-OFFICE-01",
  "user": "jozef.novak",
  "timestamp": "2025-12-17T14:30:00.0000000+01:00",
  "timeWindowMinutes": 5,
  "thresholdMB": 100,
  "method": "audit_4663",
  "drives": [
    {
      "Drive": "Z:",
      "Files": 3,
      "TotalMB": 156.45,
      "FileList": [
        {
          "ObjectName": "Z:\\Projects\\Data\\large_file.xlsx",
          "SizeMB": 89.23
        },
        {
          "ObjectName": "Z:\\Projects\\Data\\backup.zip",
          "SizeMB": 45.12
        },
        {
          "ObjectName": "Z:\\Projects\\Data\\report.pdf",
          "SizeMB": 22.10
        }
      ]
    }
  ],
  "exceeded": ["Z:"],
  "alert": true,
  "installedPath": "C:\\masscopy\\masscopy.ps1",
  "taskSchedulerStatus": "ready",
  "runningAsAdmin": false
}
```

### Popis polí

| Pole | Typ | Popis |
|------|-----|-------|
| `machine` | string | Názov počítača (`$env:COMPUTERNAME`) |
| `user` | string | Prihlásený používateľ (`$env:USERNAME`) |
| `timestamp` | string | ISO 8601 timestamp merania |
| `timeWindowMinutes` | int | Sledované časové okno v minútach |
| `thresholdMB` | int | Prah pre alert v MB |
| `method` | string | `audit_4663` alebo `fallback_lastaccess` |
| `drives` | array | Zoznam sieťových diskov s aktivitou |
| `drives[].Drive` | string | Písmeno disku (napr. `Z:`) |
| `drives[].Files` | int | Počet súborov |
| `drives[].TotalMB` | float | Celková veľkosť v MB |
| `drives[].FileList` | array | Detailný zoznam súborov |
| `drives[].FileList[].ObjectName` | string | Plná cesta k súboru |
| `drives[].FileList[].SizeMB` | float | Veľkosť súboru v MB |
| `exceeded` | array | Zoznam diskov, ktoré prekročili prah |
| `alert` | bool | `true` ak bol prah prekročený |
| `installedPath` | string | Umiestnenie skriptu na klientovi |
| `taskSchedulerStatus` | string | Stav Task Scheduler úlohy |
| `runningAsAdmin` | bool | Či skript beží s admin právami |

### JSON súbor na serveri (data/YYYYMMDD.json)

```json
[
  {
    "machine": "PC-OFFICE-01",
    "user": "jozef.novak",
    "timestamp": "2025-12-17T14:30:00.0000000+01:00",
    "timeWindowMinutes": 5,
    "thresholdMB": 100,
    "method": "audit_4663",
    "drives": [...],
    "exceeded": ["Z:"],
    "alert": true,
    "installedPath": "C:\\masscopy\\masscopy.ps1",
    "taskSchedulerStatus": "ready",
    "runningAsAdmin": false,
    "received_at": "2025-12-17 14:30:05"
  },
  {
    "machine": "PC-OFFICE-02",
    ...
  }
]
```

**Formát:**
- Pole JSON objektov
- Každý objekt = jedno meranie
- Pridané pole `received_at` (čas prijatia serverom)

---

## Riešenie problémov

### Diagnostika na klientovi (Windows)

#### 1. Kontrola, či je skript nainštalovaný

```powershell
# Kontrola existencie súboru
Test-Path C:\masscopy\masscopy.ps1

# Kontrola Task Scheduler úlohy
Get-ScheduledTask -TaskName 'MassCopyDetector' | Format-List *
```

**Očakávaný výstup:**
```
TaskName            : MassCopyDetector
State               : Ready
Actions             : MSFT_ScheduledTaskExecAction
Triggers            : MSFT_ScheduledTaskTimeTrigger
```

#### 2. Manuálne spustenie skriptu

```powershell
# Spustenie s debug výstupom
cd C:\masscopy
powershell -NoProfile -ExecutionPolicy Bypass -File .\masscopy.ps1 -Verbose
```

**Hľadajte:**
- Chybové hlášky
- Zistené sieťové disky
- Metódu zberu dát (audit_4663 / fallback)
- HTTP response kód

#### 3. Kontrola audit politík

```powershell
# Zobrazenie aktuálnych audit politík
auditpol /get /category:*

# Konkrétne pre File System
auditpol /get /subcategory:"{0cce923f-69ae-11d9-bed3-505054503030}"
```

**Očakávaný výstup:**
```
Object Access
  File System                     Success
```

#### 4. Kontrola sieťových diskov

```powershell
# Zoznam mapped drives
net use

# WMI query
Get-WmiObject Win32_LogicalDisk -Filter "DriveType=4" | Select-Object DeviceID, ProviderName
```

#### 5. Kontrola Event Logu

```powershell
# Posledných 10 udalostí 4663
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663} -MaxEvents 10 |
    Format-List TimeCreated, Message
```

#### 6. Test API pripojenia

```powershell
# Test dostupnosti API
$apiUrl = 'https://server.company.com/masscopy/'
$headers = @{ 'X-Api-Token' = 'VášToken' }
$body = @{ test = 'test' } | ConvertTo-Json

try {
    Invoke-RestMethod -Method POST -Uri $apiUrl -Headers $headers -Body $body
} catch {
    Write-Host "Error: $_"
}
```

### Diagnostika na serveri (PHP)

#### 1. Kontrola oprávnení

```bash
# Linux
ls -la /var/www/html/masscopy/
ls -la /var/www/html/masscopy/data/

# Windows
icacls C:\inetpub\wwwroot\masscopy\data
```

**Očakávaný výstup (Linux):**
```
drwxr-xr-x  2 www-data www-data  4096 Dec 17 10:00 .
drwxrwxrwx  2 www-data www-data  4096 Dec 17 10:00 data
```

#### 2. Kontrola PHP logov

```bash
# Linux Apache
tail -f /var/log/apache2/error.log

# Linux nginx
tail -f /var/log/nginx/error.log

# Windows IIS
# Event Viewer → Windows Logs → Application
```

#### 3. Test API endpointu

```bash
# curl test
curl -X POST https://server.company.com/masscopy/ \
  -H "X-Api-Token: VášToken" \
  -H "Content-Type: application/json" \
  -d '{"test": "data"}'
```

**Očakávaný výstup:**
```json
{"status":"ok","message":"Dáta uložené"}
```

#### 4. Kontrola JSON súborov

```bash
# Zoznam súborov
ls -lh /var/www/html/masscopy/data/

# Obsah súboru
cat /var/www/html/masscopy/data/20251217.json | python -m json.tool
```

### Časté problémy a riešenia

#### Problém: Skript sa nespúšťa automaticky

**Príčina:** Task Scheduler úloha nie je správne nakonfigurovaná

**Riešenie:**
1. Otvorte Task Scheduler (`taskschd.msc`)
2. Nájdite úlohu "MassCopyDetector"
3. Skontrolujte "Triggers" - malo by byť "At log on" alebo "Daily" s opakovaním 5 min
4. Skontrolujte "Actions" - cesta k powershell.exe a argumenty
5. Skontrolujte "Conditions" - disable "Start only if on AC power"
6. Skontrolujte "History" - posledné spustenia a chyby

#### Problém: Nevidia sa žiadne dáta na webovom rozhraní

**Príčiny:**
- API URL nie je správne nastavená
- API token nesedí
- Firewall blokuje komunikáciu
- Sieťový disk nie je pripojený

**Riešenie:**
1. Spustite skript manuálne s `-Verbose`
2. Skontrolujte HTTP response
3. Skontrolujte firewall pravidlá
4. Overte API token v skripte aj PHP

#### Problém: Skript používa len fallback metódu

**Príčina:** Audit 4663 nie je povolený

**Riešenie:**
```powershell
# Povoliť audit ako administrátor
auditpol /set /subcategory:"{0cce923f-69ae-11d9-bed3-505054503030}" /success:enable
auditpol /set /subcategory:"{0cce9225-69ae-11d9-bed3-505054503030}" /success:enable

# Reštartovať skript
```

#### Problém: "Nie je možné zapisovať do priečinka pre dáta"

**Príčina:** Nesprávne oprávnenia na `data/` priečinok

**Riešenie Linux:**
```bash
chmod 777 /var/www/html/masscopy/data/
chown www-data:www-data /var/www/html/masscopy/data/
```

**Riešenie Windows:**
```cmd
icacls C:\inetpub\wwwroot\masscopy\data /grant "IIS_IUSRS:(OI)(CI)F"
```

#### Problém: Skript nevidí sieťové disky

**Príčina:** Task Scheduler beží ako SYSTEM, ktorý nemá mapped drives

**Riešenie:**
1. Zmeňte Task Scheduler na beh pod konkrétnym používateľom
2. Alebo použite UNC cesty namiesto mapped drives

#### Problém: Pomalé spracovanie s fallback metódou

**Príčina:** Fallback prechádza celý file system

**Riešenie:**
- Povoľte Audit 4663 (primárna metóda)
- Znížte časové okno (`-Minuty 2`)
- Zvýšte prah (`-PrahMB 500`)

### Debug režim

#### Pridanie debug výstupu do PowerShell skriptu

```powershell
# Na začiatok skriptu pridajte
$DebugPreference = 'Continue'

# V kóde pridajte debug výstupy
Write-Debug "Zistené disky: $($sietoveDisk.Count)"
Write-Debug "Metóda: $pouzitaMetoda"
Write-Debug "Počet súborov: $($riadky.Count)"
```

#### PHP debug režim

```php
// Na začiatok index.php pridajte
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Debug výpis
error_log("Received data: " . print_r($data, true));
```

---

## Výkon a optimalizácia

### PowerShell skript

#### Optimalizácia zberu dát

**Audit 4663 (rýchla):**
- Čas: ~5-10 sekúnd
- Závisí od počtu udalostí v Event Logu

**Fallback LastAccess (pomalá):**
- Čas: ~30-120 sekúnd
- Závisí od počtu súborov na disku

**Tip:** Povoľte Audit 4663 pre maximálny výkon

#### Optimalizácia sieťovej komunikácie

```powershell
# Timeout 30 sekúnd (predvolené)
Invoke-RestMethod -TimeoutSec 30

# Pre pomalé siete zvýšte
Invoke-RestMethod -TimeoutSec 60
```

### PHP API

#### Optimalizácia načítania dát

**Súčasný stav:** Načíta všetky JSON súbory

**Pre veľké objemy dát:**
```php
// Načítaj len posledných 7 dní
$files = glob(DATA_DIR . '/*.json');
rsort($files);
$files = array_slice($files, 0, 7);
```

#### Cache výsledkov

```php
// Cache timeline na 5 minút
$cacheFile = 'timeline_cache.json';
if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < 300) {
    $timeline = json_decode(file_get_contents($cacheFile), true);
} else {
    $timeline = getTimeline($allData);
    file_put_contents($cacheFile, json_encode($timeline));
}
```

### Údržba dát

#### Automatické čistenie starých JSON súborov

```bash
# Linux cron (ponechať len 30 dní)
0 2 * * * find /var/www/html/masscopy/data -name "*.json" -mtime +30 -delete
```

```powershell
# Windows Task Scheduler
Get-ChildItem "C:\inetpub\wwwroot\masscopy\data\*.json" |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } |
    Remove-Item
```

---

## Rozšírenia a customizácia

### Pridanie notifikácií

#### Email notifikácie (PowerShell)

```powershell
if ($prekrocene.Count -gt 0) {
    $subject = "ALERT: Mass Copy Detection on $env:COMPUTERNAME"
    $body = "Prekročený prah na diskoch: $($prekrocene -join ', ')"
    
    Send-MailMessage -To "admin@company.com" -From "masscopy@company.com" `
        -Subject $subject -Body $body -SmtpServer "smtp.company.com"
}
```

#### Slack notifikácie (PHP)

```php
if ($data['alert']) {
    $webhookUrl = 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL';
    $message = [
        'text' => "⚠️ Alert: {$data['machine']} prekročil prah!",
        'username' => 'Mass Copy Detector'
    ];
    
    $ch = curl_init($webhookUrl);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($message));
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    curl_exec($ch);
    curl_close($ch);
}
```

### Databázové úložisko

Namiesto JSON súborov použite MySQL/PostgreSQL:

```php
// Pripojenie k DB
$pdo = new PDO('mysql:host=localhost;dbname=masscopy', 'user', 'pass');

// Vloženie záznamu
$stmt = $pdo->prepare('INSERT INTO measurements 
    (machine, user, timestamp, method, data) 
    VALUES (?, ?, ?, ?, ?)');
$stmt->execute([
    $data['machine'],
    $data['user'],
    $data['timestamp'],
    $data['method'],
    json_encode($data)
]);
```

### REST API rozšírenia

```php
// GET /api/stats
if ($_SERVER['REQUEST_URI'] === '/api/stats') {
    $allData = getAllData();
    echo json_encode([
        'total_measurements' => count($allData),
        'total_alerts' => count(array_filter($allData, fn($i) => $i['alert'])),
        'machines' => array_unique(array_column($allData, 'machine'))
    ]);
    exit;
}
```

---

## Záver

Mass Copy Detector je komplexný systém pre monitorovanie dátových prenosov v podnikovom prostredí. Kombinuje Windows Audit systém, PowerShell automatizáciu a PHP webové technológie pre poskytnutie real-time prehľadu o aktivitách na sieťových diskoch.

### Kľúčové vlastnosti:

✅ **Automatická samoinstalacia** - skript sa sám nakonfiguruje  
✅ **Redundantné metódy zberu dát** - Audit 4663 + LastAccess fallback  
✅ **Distribuovaná architektúra** - centrálny server, viacero klientov  
✅ **Real-time monitoring** - meranie každých 5 minút  
✅ **Webové rozhranie** - prehľadná vizualizácia  
✅ **Alerting** - automatická detekcia prekročení prahov  
✅ **Nízka administračná náročnosť** - raz nastaviť, potom len sledovať  

### Podpora a ďalší vývoj:

GitHub: [https://github.com/03Andras/mass_copy_detector](https://github.com/03Andras/mass_copy_detector)

---

**Vytvoril:** NA  
**Verzia dokumentácie:** 1.0  
**Dátum:** December 2025
