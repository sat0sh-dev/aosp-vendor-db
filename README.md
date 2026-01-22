# Data Broker (Db) Daemon - 利用ガイド

このドキュメントは、Data Broker (Db) デーモンのビルド、テスト、トラブルシューティングの完全な手順を提供します。

## 目次

1. [概要](#概要)
2. [ビルド方法](#ビルド方法)
3. [テスト方法](#テスト方法)
4. [PAL-Db連携テスト](#pal-db連携テスト)
5. [トラブルシューティング](#トラブルシューティング)

---

## 概要

Data Broker (Db) は、車両データの集約・配信を行うデータブローカーです。

### 主な機能

- **TCP server**: 127.0.0.1:50051でリスニング
- **簡易テキストプロトコル**: GET, SET, LIST, QUIT コマンド
- **HashMap storage**: 最新値を保持
- **マルチスレッド対応**: 接続ごとにスレッド生成

### 実装言語

- Rust (edition 2021)
- 依存: liblog_rust, libenv_logger

### 配置

- バイナリ: `/vendor/bin/db_daemon`
- init設定: `/vendor/etc/init/db_daemon.rc`
- SELinuxポリシー: `vendor/db/sepolicy/`

---

## ビルド方法

### モジュールのみビルド

```bash
# コンテナ内で実行
podman exec -it aosp-build-env bash -c "
    cd /work/src &&
    source build/envsetup.sh &&
    lunch aosp_car_dev-trunk_staging-eng &&
    m db_daemon
"
```

**ビルド時間**: 約2-3分

### フルビルド（vendor.img含む）

```bash
# コンテナ内で実行
podman exec -it aosp-build-env bash -c "
    cd /work/src &&
    source build/envsetup.sh &&
    lunch aosp_car_dev-trunk_staging-eng &&
    m
"
```

**ビルド時間**: 約30-40分（初回）、約3-5分（キャッシュあり）

### ビルド確認

```bash
ls -lh out/target/product/emulator_car64_x86_64/vendor/bin/db_daemon
```

---

## テスト方法

### 1. プロセス確認

```bash
# デバイスに接続
adb wait-for-device

# db_daemonプロセスの確認
adb shell "ps -AZ | grep db_daemon"
```

**期待される出力**:
```
u:r:db_daemon:s0     system    497    1    10805220   3196 inet_csk_accept 0 S db_daemon
```

- SELinuxコンテキスト: `u:r:db_daemon:s0`
- ユーザー: `system`
- 状態: `inet_csk_accept` (TCP接続待機中)

### 2. ログ確認

```bash
# 起動ログ確認
adb logcat -d | grep "db_daemon" | grep "starting"
```

**期待される出力**:
```
[INFO  db_daemon] db_daemon starting...
[INFO  db_daemon] Initialized with test data
[INFO  db_daemon] TCP server listening on 127.0.0.1:50051
[INFO  db_daemon] db_daemon started successfully
[INFO  db_daemon] Data store ready with 2 entries
[INFO  db_daemon] Waiting for client connections...
```

### 3. TCP server動作確認

#### 3.1 LIST - 全データ表示

```bash
adb shell "echo 'LIST' | nc 127.0.0.1 50051"
```

**期待される出力**:
```
OK: test_key=test_value, vehicle.speed=60
```

#### 3.2 GET - データ取得

```bash
adb shell "echo 'GET test_key' | nc 127.0.0.1 50051"
```

**期待される出力**:
```
OK: test_value
```

#### 3.3 SET - データ保存

```bash
adb shell "echo 'SET vehicle.rpm 3000' | nc 127.0.0.1 50051"
```

**期待される出力**:
```
OK: Set vehicle.rpm=3000
```

#### 3.4 データ保存の確認

```bash
adb shell "echo 'LIST' | nc 127.0.0.1 50051"
```

**期待される出力**:
```
OK: test_key=test_value, vehicle.speed=60, vehicle.rpm=3000
```

### 4. クライアント接続ログの確認

```bash
adb logcat -d | grep "db_daemon" | grep -E "New client|SET|GET"
```

**期待される出力**:
```
[INFO  db_daemon] New client connection from None
[INFO  db_daemon] SET vehicle.rpm=3000
```

---

## PAL-Db連携テスト

PALデーモンからDbへのデータ転送をテストします。

### 前提条件

- pal_daemon が起動している
- db_daemon が起動している

### テスト手順

#### 1. 両デーモンの起動確認

```bash
adb shell "ps -A | grep -E 'pal_daemon|db_daemon'"
```

**期待される出力**:
```
system    497    1    ... S db_daemon
system   2716    1    ... S pal_daemon
```

#### 2. UDPパケット送信（PAL経由）

```bash
# 温度データ送信
adb shell "echo 'temperature=25' | nc -u 239.255.0.1 12345"
```

#### 3. PALログ確認

```bash
adb logcat -d | grep "pal_daemon" | tail -10
```

**期待される出力**:
```
[INFO pal_daemon] Received UDP multicast packet
[INFO pal_daemon]   Data: temperature=25
[INFO pal_daemon] Forwarding to DB: udp.temperature = 25
[INFO pal_daemon] DB response: OK: Set udp.temperature=25
[INFO pal_daemon] Successfully forwarded to Data Broker
```

#### 4. Dbログ確認

```bash
adb logcat -d | grep "db_daemon" | tail -5
```

**期待される出力**:
```
[INFO  db_daemon] New client connection from None
[INFO  db_daemon] SET udp.temperature=25
```

#### 5. Dbに保存されたデータ確認

```bash
adb shell "echo 'LIST' | nc 127.0.0.1 50051"
```

**期待される出力**:
```
OK: udp.temperature=25, test_key=test_value, vehicle.speed=60
```

#### 6. 追加データでテスト

```bash
# RPMデータ送信
adb shell "echo 'rpm=3500' | nc -u 239.255.0.1 12345"

# 待機
sleep 2

# データ確認
adb shell "echo 'LIST' | nc 127.0.0.1 50051"
```

**期待される出力**:
```
OK: udp.temperature=25, test_key=test_value, udp.rpm=3500, vehicle.speed=60
```

### データフロー図

```
外部システム (テスト)
  ↓ UDP multicast: echo 'temperature=25' | nc -u 239.255.0.1 12345
PAL Daemon (pal_daemon)
  ↓ Parse: "temperature=25" → key="udp.temperature", value="25"
  ↓ TCP client: connect 127.0.0.1:50051
  ↓ Send: "SET udp.temperature 25\n"
Data Broker (db_daemon)
  ↓ Process SET command
  ↓ Store in HashMap
  ↓ Response: "OK: Set udp.temperature=25\n"
PAL Daemon
  ✓ Log success
```

---

## トラブルシューティング

### db_daemonが起動しない

#### 症状

```bash
adb shell "ps -A | grep db_daemon"
# 出力なし
```

#### 確認手順

**1. initログ確認**

```bash
adb logcat -d | grep "init.*db_daemon"
```

**2. SELinux違反確認**

```bash
adb logcat -d | grep "avc.*denied.*db_daemon"
```

**3. バイナリ確認**

```bash
adb shell "ls -lZ /vendor/bin/db_daemon"
```

**期待される出力**:
```
-rwxr-xr-x 1 root shell u:object_r:db_daemon_exec:s0 ... /vendor/bin/db_daemon
```

**4. init設定確認**

```bash
adb shell "ls -l /vendor/etc/init/db_daemon.rc"
```

#### 対処方法

- SELinux違反がある場合: `vendor/db/sepolicy/db_daemon.te` を確認
- バイナリが存在しない場合: フルビルドして `adb emu kill` → 再起動
- SELinuxラベルが正しくない場合: 手動でpushではなくフルビルドが必要

---

### TCP serverに接続できない

#### 症状

```bash
adb shell "echo 'LIST' | nc 127.0.0.1 50051"
# タイムアウトまたはエラー
```

#### 確認手順

**1. プロセス状態確認**

```bash
adb shell "ps -AZ | grep db_daemon"
```

- `inet_csk_accept` 状態か確認（TCP接続待機中）

**2. ログ確認**

```bash
adb logcat -d | grep "db_daemon.*TCP server listening"
```

**期待される出力**:
```
[INFO  db_daemon] TCP server listening on 127.0.0.1:50051
```

**3. netstatで確認**

```bash
adb shell "netstat -tlnp | grep 50051"
```

**期待される出力**:
```
tcp    0    0 127.0.0.1:50051    0.0.0.0:*    LISTEN    497/db_daemon
```

#### 対処方法

- リスニングログがない場合: db_daemonを再起動（`adb reboot`）
- プロセスはあるが接続できない場合: SELinuxポリシーを確認

---

### PAL-Db連携が動作しない

#### 症状

UDPパケットを送信してもDbにデータが保存されない

#### 確認手順

**1. PALの起動確認**

```bash
adb shell "ps -A | grep pal_daemon"
```

**2. PALのログ確認**

```bash
adb logcat -d | grep "pal_daemon" | grep -E "Received|Forwarding|Failed"
```

**期待される出力**:
```
[INFO pal_daemon] Received UDP multicast packet
[INFO pal_daemon] Forwarding to DB: ...
[INFO pal_daemon] Successfully forwarded to Data Broker
```

**エラー例**:
```
[ERROR pal_daemon] Failed to create TCP socket for DB: Permission denied
[ERROR pal_daemon] Failed to connect to DB: Connection refused
```

**3. SELinux違反確認**

```bash
adb logcat -d | grep "avc.*denied.*pal_daemon.*tcp_socket"
```

#### 対処方法

- `Permission denied`: `vendor/pal/sepolicy/pal_daemon.te` でTCP socket権限を確認
- `Connection refused`: db_daemonの起動とリスニング状態を確認
- データが保存されない: PALログで "Successfully forwarded" を確認

---

## プロトコル仕様

### コマンド形式

すべてのコマンドは改行(`\n`)で終端します。

#### GET

```
GET <key>\n
```

**レスポンス**:
- 成功: `OK: <value>\n`
- 失敗: `ERROR: Key not found\n`

#### SET

```
SET <key> <value>\n
```

**レスポンス**:
- 成功: `OK: Set <key>=<value>\n`
- 失敗: `ERROR: SET requires key and value\n`

#### LIST

```
LIST\n
```

**レスポンス**:
- データあり: `OK: key1=value1, key2=value2, ...\n`
- データなし: `OK: (empty)\n`

#### QUIT

```
QUIT\n
```

**レスポンス**:
- `OK: Goodbye\n`

---

## 参考リソース

- **実装ファイル**: `vendor/db/src/main.rs`
- **ビルド定義**: `vendor/db/Android.bp`
- **init設定**: `vendor/db/db_daemon.rc`
- **SELinuxポリシー**: `vendor/db/sepolicy/db_daemon.te`
- **PAL実装知見**: `docs/pal-implementation-notes.md`
- **実装計画**: `docs/poc-implementation-comparison.md`

---

## 次のステップ

- Android Appの実装（C++ client library + JNI）
- 認証機能の追加（フェーズ2）
- gRPC化またはUDS対応（フェーズ3）
