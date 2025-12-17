<?php
// =============================================================================
// KONFIGURÁCIA - UPRAVTE PODĽA POTRIEB
// =============================================================================
define('PASSWORD', 'Heslo');           // Heslo pre prihlásenie
define('DATA_DIR', 'data');               // Priečinok pre JSON súbory
define('API_TOKEN', 'Heslo');          // Token pre API autentifikáciu

// =============================================================================
// INICIALIZÁCIA
// =============================================================================
session_start();

// Kontrola a vytvorenie priečinka pre dáta
if (!file_exists(DATA_DIR)) {
    if (!@mkdir(DATA_DIR, 0755, true)) {
        die('CHYBA: Nie je možné vytvoriť priečinok pre dáta. Skontrolujte oprávnenia.');
    }
}

// Kontrola oprávnení na zápis
if (!is_writable(DATA_DIR)) {
    die('CHYBA: Nie je možné zapisovať do priečinka pre dáta. Skontrolujte oprávnenia.');
}

// Funkcia pre získanie cesty k súboru pre daný deň
function getDataFile($date = null) {
    if ($date === null) {
        $date = date('Ymd');
    }
    return DATA_DIR . '/' . $date . '.json';
}

// Funkcia pre načítanie všetkých záznamov
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

// Funkcia pre formátovanie času
function formatTimestamp($timestamp) {
    if (empty($timestamp)) return 'Neznámy';
    try {
        $dt = new DateTime($timestamp);
        return $dt->format('d.m.Y H:i:s');
    } catch (Exception $e) {
        return htmlspecialchars($timestamp);
    }
}

// Funkcia pre získanie časovej osi (timeline)
function getTimeline($data) {
    $timeline = [];
    foreach ($data as $record) {
        if (!empty($record['timestamp'])) {
            try {
                $dt = new DateTime($record['timestamp']);
                $hourKey = $dt->format('Y-m-d H:00');
                if (!isset($timeline[$hourKey])) {
                    $timeline[$hourKey] = ['count' => 0, 'alerts' => 0];
                }
                $timeline[$hourKey]['count']++;
                if ($record['alert'] ?? false) {
                    $timeline[$hourKey]['alerts']++;
                }
            } catch (Exception $e) {
                // Preskočiť neplatné časové značky
            }
        }
    }
    ksort($timeline);
    return $timeline;
}

// Prihlasenie
if (isset($_POST['password'])) {
    if ($_POST['password'] === PASSWORD) {
        $_SESSION['logged_in'] = true;
    }
    header('Location: index.php');
    exit;
}

// Odhlasenie
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: index.php');
    exit;
}

// =============================================================================
// API ENDPOINT - PRIJÍMANIE DÁT
// =============================================================================
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['password'])) {
    // Kontrola API tokenu
    $token = '';
    if (function_exists('getallheaders')) {
        $headers = getallheaders();
        $token = $headers['X-Api-Token'] ?? '';
    } elseif (function_exists('apache_request_headers')) {
        $headers = apache_request_headers();
        $token = $headers['X-Api-Token'] ?? '';
    } else {
        $token = $_SERVER['HTTP_X_API_TOKEN'] ?? '';
    }
    
    if ($token !== API_TOKEN) {
        http_response_code(401);
        echo json_encode(['status' => 'error', 'message' => 'Neplatný token']);
        exit;
    }
    
    $json = file_get_contents('php://input');
    $data = json_decode($json, true);
    
    if ($data) {
        // Pridaj čas prijatia
        $data['received_at'] = date('Y-m-d H:i:s');
        
        // Načítaj existujúce dáta pre dnešný deň
        $dataFile = getDataFile();
        $allData = [];
        if (file_exists($dataFile)) {
            $content = file_get_contents($dataFile);
            $allData = json_decode($content, true) ?: [];
        }
        
        // Pridaj nový záznam
        $allData[] = $data;
        
        // Ulož
        $result = file_put_contents($dataFile, json_encode($allData, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        
        if ($result === false) {
            http_response_code(500);
            echo json_encode(['status' => 'error', 'message' => 'Chyba pri zápise dát']);
        } else {
            http_response_code(200);
            echo json_encode(['status' => 'ok', 'message' => 'Dáta uložené']);
        }
    } else {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Neplatné dáta']);
    }
    exit;
}

// Kontrola prihlasenia pre zobrazenie stranky
if (!isset($_SESSION['logged_in']) || !$_SESSION['logged_in']) {
    ?>
    <!DOCTYPE html>
    <html lang="sk">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Prihlasenie - Mass Copy Detector by NA</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
            }
            .login-box {
                background: white;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                width: 100%;
                max-width: 400px;
            }
            h1 { color: #333; margin-bottom: 30px; text-align: center; }
            input[type="password"] {
                width: 100%;
                padding: 12px;
                border: 2px solid #ddd;
                border-radius: 5px;
                font-size: 16px;
                margin-bottom: 20px;
            }
            input[type="password"]:focus {
                border-color: #667eea;
                outline: none;
            }
            button {
                width: 100%;
                padding: 12px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                border-radius: 5px;
                font-size: 16px;
                font-weight: bold;
                cursor: pointer;
                transition: transform 0.2s;
            }
            button:hover { transform: translateY(-2px); }
        </style>
    </head>
    <body>
        <div class="login-box">
            <h1>🔒 Mass Copy Detector by NA</h1>
            <form method="POST">
                <input type="password" name="password" placeholder="Zadajte heslo" required autofocus>
                <button type="submit">Prihlasit sa</button>
            </form>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// =============================================================================
// NAČÍTANIE A FILTROVANIE DÁT
// =============================================================================
$allData = getAllData();
$timeline = getTimeline($allData);

// Filtrovanie
$filter = isset($_GET['filter']) ? $_GET['filter'] : 'all';
$filteredData = $allData;

if ($filter === 'alert') {
    $filteredData = array_filter($allData, function($item) {
        return isset($item['alert']) && $item['alert'] === true;
    });
}

// Zoradenie - najnovsie hore
$filteredData = array_reverse($filteredData);

?>
<!DOCTYPE html>
<html lang="sk">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mass Copy Detector by NA</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f7fa;
            padding: 20px;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 { font-size: 24px; }
        .logout-btn {
            background: rgba(255,255,255,0.2);
            color: white;
            border: 2px solid white;
            padding: 8px 20px;
            border-radius: 5px;
            text-decoration: none;
            transition: all 0.3s;
        }
        .logout-btn:hover {
            background: white;
            color: #667eea;
        }
        .filters {
            background: white;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }
        .filter-btn {
            display: inline-block;
            padding: 10px 20px;
            margin-right: 10px;
            background: #f0f0f0;
            color: #333;
            text-decoration: none;
            border-radius: 5px;
            transition: all 0.3s;
        }
        .filter-btn.active, .filter-btn:hover {
            background: #667eea;
            color: white;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .stat-box {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            text-align: center;
        }
        .stat-box h3 { color: #666; font-size: 14px; margin-bottom: 10px; }
        .stat-box .number { font-size: 32px; font-weight: bold; color: #667eea; }
        .record {
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 15px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            border-left: 5px solid #667eea;
        }
        .record.alert { border-left-color: #e74c3c; }
        .record-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .record-title {
            font-size: 18px;
            font-weight: bold;
            color: #333;
        }
        .alert-badge {
            background: #e74c3c;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
        }
        .ok-badge {
            background: #27ae60;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
        }
        .record-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
            margin-bottom: 15px;
        }
        .info-item {
            padding: 10px;
            background: #f8f9fa;
            border-radius: 5px;
        }
        .info-label {
            font-size: 12px;
            color: #666;
            margin-bottom: 5px;
        }
        .info-value {
            font-size: 16px;
            font-weight: bold;
            color: #333;
        }
        .drives {
            margin-top: 15px;
        }
        .drive-item {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 10px;
            border-left: 3px solid #667eea;
        }
        .drive-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .drive-name {
            font-weight: bold;
            font-size: 18px;
            color: #667eea;
        }
        .drive-stats {
            display: flex;
            gap: 20px;
            font-size: 14px;
            color: #666;
        }
        .file-list {
            margin-top: 10px;
            padding-top: 10px;
            border-top: 1px solid #ddd;
        }
        .file-item {
            display: flex;
            justify-content: space-between;
            padding: 8px;
            background: white;
            margin-bottom: 5px;
            border-radius: 3px;
            font-size: 13px;
        }
        .file-path {
            color: #333;
            flex: 1;
            word-break: break-all;
        }
        .file-size {
            color: #667eea;
            font-weight: bold;
            margin-left: 15px;
            white-space: nowrap;
        }
        .no-data {
            text-align: center;
            padding: 60px 20px;
            color: #999;
            font-size: 18px;
        }
        .timeline {
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }
        .timeline h2 {
            font-size: 18px;
            color: #333;
            margin-bottom: 15px;
        }
        .timeline-bars {
            display: flex;
            gap: 5px;
            align-items: flex-end;
            height: 100px;
            padding: 10px 0;
        }
        .timeline-bar {
            flex: 1;
            background: #667eea;
            border-radius: 3px 3px 0 0;
            position: relative;
            cursor: pointer;
            transition: all 0.3s;
            min-height: 5px;
        }
        .timeline-bar:hover {
            background: #764ba2;
            transform: translateY(-2px);
        }
        .timeline-bar.has-alert {
            background: #e74c3c;
        }
        .timeline-bar.has-alert:hover {
            background: #c0392b;
        }
        .timeline-label {
            font-size: 11px;
            color: #666;
            text-align: center;
            margin-top: 5px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .timeline-tooltip {
            display: none;
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%);
            background: #333;
            color: white;
            padding: 8px 12px;
            border-radius: 5px;
            font-size: 12px;
            white-space: nowrap;
            margin-bottom: 5px;
            z-index: 10;
        }
        .timeline-bar:hover .timeline-tooltip {
            display: block;
        }
        .file-list-header {
            font-weight: bold;
            color: #667eea;
            margin-bottom: 10px;
            padding: 5px 0;
            border-bottom: 2px solid #667eea;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>📊 Mass Copy Detector by NA</h1>
        <a href="?logout" class="logout-btn">Odhlasit</a>
    </div>

    <div class="filters">
        <a href="?filter=all" class="filter-btn <?= $filter === 'all' ? 'active' : '' ?>">Vsetky</a>
        <a href="?filter=alert" class="filter-btn <?= $filter === 'alert' ? 'active' : '' ?>">Iba alerty</a>
    </div>

    <div class="stats">
        <div class="stat-box">
            <h3>Celkovy pocet merani</h3>
            <div class="number"><?= count($allData) ?></div>
        </div>
        <div class="stat-box">
            <h3>Pocet alertov</h3>
            <div class="number"><?= count(array_filter($allData, fn($i) => $i['alert'] ?? false)) ?></div>
        </div>
        <div class="stat-box">
            <h3>Zobrazene</h3>
            <div class="number"><?= count($filteredData) ?></div>
        </div>
    </div>

    <?php if (!empty($timeline)): ?>
    <div class="timeline">
        <h2>⏱️ Časová os meraní</h2>
        <div class="timeline-bars">
            <?php 
            $counts = array_column($timeline, 'count');
            $maxCount = !empty($counts) ? max($counts) : 1;
            foreach ($timeline as $hour => $data): 
                $height = $maxCount > 0 ? ($data['count'] / $maxCount) * 100 : 5;
                $hasAlert = $data['alerts'] > 0;
                $dt = new DateTime($hour);
            ?>
                <div class="timeline-bar <?= $hasAlert ? 'has-alert' : '' ?>" style="height: <?= $height ?>%;">
                    <div class="timeline-tooltip">
                        <?= $dt->format('d.m H:i') ?><br>
                        Meraní: <?= $data['count'] ?><br>
                        <?php if ($hasAlert): ?>
                            ⚠️ Alerty: <?= $data['alerts'] ?>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
        <div style="display: flex; justify-content: space-between; margin-top: 10px;">
            <div class="timeline-label">
                <?php 
                $firstHour = array_key_first($timeline);
                if ($firstHour) {
                    $dt = new DateTime($firstHour);
                    echo $dt->format('d.m.Y H:i');
                }
                ?>
            </div>
            <div class="timeline-label">
                <?php 
                $lastHour = array_key_last($timeline);
                if ($lastHour) {
                    $dt = new DateTime($lastHour);
                    echo $dt->format('d.m.Y H:i');
                }
                ?>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <?php if (empty($filteredData)): ?>
        <div class="no-data">
            📭 Zatial ziadne data
        </div>
    <?php else: ?>
        <?php foreach ($filteredData as $record): ?>
            <div class="record <?= ($record['alert'] ?? false) ? 'alert' : '' ?>">
                <div class="record-header">
                    <div class="record-title">
                        <?= htmlspecialchars($record['machine'] ?? 'Neznámy') ?> - <?= htmlspecialchars($record['user'] ?? 'Neznámy') ?>
                    </div>
                    <?php if ($record['alert'] ?? false): ?>
                        <span class="alert-badge">⚠️ ALERT</span>
                    <?php else: ?>
                        <span class="ok-badge">✓ OK</span>
                    <?php endif; ?>
                </div>

                <div class="record-info">
                    <div class="info-item">
                        <div class="info-label">Čas merania</div>
                        <div class="info-value"><?= formatTimestamp($record['timestamp'] ?? '') ?></div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Časové okno</div>
                        <div class="info-value"><?= isset($record['timeWindowMinutes']) ? htmlspecialchars($record['timeWindowMinutes']) . ' min' : 'Nenastavené' ?></div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Prah</div>
                        <div class="info-value"><?= isset($record['thresholdMB']) ? htmlspecialchars($record['thresholdMB']) . ' MB' : 'Nenastavené' ?></div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Metóda</div>
                        <div class="info-value"><?= htmlspecialchars($record['method'] ?? 'Neznáma') ?></div>
                    </div>
                    <?php if (isset($record['installedPath'])): ?>
                    <div class="info-item">
                        <div class="info-label">Umiestnenie skriptu</div>
                        <div class="info-value" style="font-size: 12px;"><?= htmlspecialchars($record['installedPath']) ?></div>
                    </div>
                    <?php endif; ?>
                    <?php if (isset($record['taskSchedulerStatus'])): ?>
                    <div class="info-item">
                        <div class="info-label">Task Scheduler</div>
                        <div class="info-value"><?= htmlspecialchars($record['taskSchedulerStatus']) ?></div>
                    </div>
                    <?php endif; ?>
                </div>

                <?php if (!empty($record['drives'])): ?>
                    <div class="drives">
                        <?php foreach ($record['drives'] as $drive): ?>
                            <div class="drive-item">
                                <div class="drive-header">
                                    <span class="drive-name"><?= htmlspecialchars($drive['Drive'] ?? 'Neznámy disk') ?></span>
                                    <div class="drive-stats">
                                        <span>📁 <?= isset($drive['Files']) ? htmlspecialchars($drive['Files']) : 0 ?> súborov</span>
                                        <span>💾 <?= isset($drive['TotalMB']) ? number_format($drive['TotalMB'], 2) : '0.00' ?> MB</span>
                                    </div>
                                </div>
                                
                                <?php if (!empty($drive['FileList']) && is_array($drive['FileList'])): ?>
                                    <div class="file-list">
                                        <div class="file-list-header">
                                            📋 Zoznam dotknutých súborov (<?= count($drive['FileList']) ?>)
                                        </div>
                                        <?php foreach ($drive['FileList'] as $file): ?>
                                            <?php if (!empty($file['ObjectName'])): ?>
                                                <div class="file-item">
                                                    <span class="file-path"><?= htmlspecialchars($file['ObjectName']) ?></span>
                                                    <span class="file-size"><?= number_format($file['SizeMB'] ?? 0, 2) ?> MB</span>
                                                </div>
                                            <?php endif; ?>
                                        <?php endforeach; ?>
                                    </div>
                                <?php else: ?>
                                    <div class="file-list">
                                        <div style="color: #999; font-style: italic; padding: 10px;">
                                            Žiadne súbory na zobrazenie
                                        </div>
                                    </div>
                                <?php endif; ?>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>
        <?php endforeach; ?>
    <?php endif; ?>

    <div style="text-align: center; margin-top: 40px; padding: 20px; color: #999; font-size: 14px;">
        <p>Mass Copy Detector by NA</p>
        <p><a href="https://github.com/03Andras/mass_copy_detector" target="_blank" style="color: #667eea; text-decoration: none;">https://github.com/03Andras/mass_copy_detector</a></p>
    </div>

</body>
</html>
