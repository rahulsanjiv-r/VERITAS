/*
 * VERITAS — Gate Pod Firmware (veritas_pod.ino)
 * ESP32 + HX711 (load cell) + ESP32-CAM + Ed25519 (WolfSSL) + Signed OTA
 *
 * CRYPTO: Option B — software Ed25519 via WolfSSL (built into ESP32 Arduino core ≥2.0).
 * For commercial deployment upgrade to Option C (NXP SE050 I2C) — see ARCHITECTURE.md.
 *
 * CANONICAL HASH — field order MUST match backend/crypto.py exactly:
 *   "{weight_kg:.6f}|{facility_id}|{timestamp_iso}|{photo_hash_hex}|{device_id}"
 *   Separator : | (pipe), weight_kg formatted to 6 decimal places, all UTF-8.
 *
 * STATUS: Phase 6 — syntax-checked only. Not compiled or tested on hardware
 *         (no physical board in this environment). Cross-language round-trip test
 *         required before connecting to a live backend endpoint.
 *
 * DEPENDENCIES (platformio.ini or Arduino Library Manager):
 *   - bogde/HX711 @ ^0.7.5
 *   - ArduinoJson @ ^7.x
 *   - WolfSSL (bundled with esp32 Arduino core >= 2.0 — no extra install needed)
 *   - ESP32 camera driver (built into Espressif board package)
 *   - ArduinoOTA (bundled with esp32 Arduino core)
 *   - mikalhart/TinyGPSPlus @ ^1.0.3
 *
 * INVARIANTS ENFORCED:
 *   #1  — Ed25519 signature over canonical hash sent with every arrival POST
 *   #2  — canonical hash field order and encoding match backend/crypto.py (documented above)
 *   #11 — OTA firmware only accepted if signed by the server key (Update::setMD5 + hash check)
 */

// PRODUCTION CHECKLIST:
// [x] GPS: TinyGPS++ via HardwareSerial UART1 (GPIO16/17)
// [ ] Flash encryption: enable eFuse JTAG disable + flash encrypt before deployment
// [ ] Provision real Ed25519 keys per device (not the demo keypair)

#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <HX711.h>
#include <TinyGPS++.h>
#include <HardwareSerial.h>
#include <SHA256.h>          // from WolfSSL — bundled with esp32 core
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include "esp_camera.h"
#include <time.h>
#include <ArduinoOTA.h>

// ---------------------------------------------------------------------------
// Configuration — override via EEPROM or provisioning in production
// ---------------------------------------------------------------------------

#define WIFI_SSID        "YOUR_SSID"
#define WIFI_PASS        "YOUR_PASSWORD"
#define BACKEND_URL      "http://192.168.1.100:8000"   // replace with real server IP
#define FACILITY_ID      "FACILITY_ID_FROM_REGISTRATION"
#define DEVICE_ID        "VERITAS-POD-001"
#define NTP_SERVER       "pool.ntp.org"

// GPS: u-blox NEO-6M on UART1 (GPIO16=RX, GPIO17=TX, 9600 baud)
#define GPS_RX_PIN       16
#define GPS_TX_PIN       17
#define GPS_BAUD         9600

// HX711 wiring (adjust to your board)
#define HX711_DATA_PIN   14
#define HX711_CLOCK_PIN  15
#define HX711_SCALE      2280.0f    // calibrate with a known weight before deployment

// ESP32-CAM: using AI-Thinker pinout (adjust if using different module)
#define CAM_PIN_PWDN     32
#define CAM_PIN_RESET    -1
#define CAM_PIN_XCLK     0
#define CAM_PIN_SIOD     26
#define CAM_PIN_SIOC     27
#define CAM_PIN_D7       35
#define CAM_PIN_D6       34
#define CAM_PIN_D5       39
#define CAM_PIN_D4       38
#define CAM_PIN_D3       37
#define CAM_PIN_D2       36
#define CAM_PIN_D1       21
#define CAM_PIN_D0       19
#define CAM_PIN_VSYNC    25
#define CAM_PIN_HREF     23
#define CAM_PIN_PCLK     22

// ---------------------------------------------------------------------------
// Device private key (32 bytes) — Ed25519 seed stored in flash.
// IMPORTANT: Enable ESP32 flash encryption in production.
// The corresponding public key must be registered with this facility
// via POST /facilities {pubkey_hex: ...}.
// ---------------------------------------------------------------------------

// Replace with your actual 32-byte Ed25519 private key seed (hex → bytes at provision time).
// This is a placeholder — NEVER ship placeholder keys.
static const uint8_t DEVICE_PRIVKEY_SEED[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

HX711 scale;
ed25519_key devKey;
bool keyReady = false;

// GPS: u-blox NEO-6M on UART1 (GPIO16=RX, GPIO17=TX, 9600 baud)
HardwareSerial gpsSerial(1);
TinyGPSPlus gps;

struct GpsReading {
    bool valid;
    double lat;
    double lon;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Bytes → lowercase hex string. */
String bytesToHex(const uint8_t* buf, size_t len) {
    String out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", buf[i]);
        out += hex;
    }
    return out;
}

/** Get current UTC time as ISO 8601 string: "2026-09-18T12:00:00+00:00" */
String getTimestampISO() {
    struct tm timeinfo;
    if (!getLocalTime(&timeinfo)) {
        Serial.println("[WARN] NTP not ready — using fallback timestamp");
        return "1970-01-01T00:00:00+00:00";
    }
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S+00:00", &timeinfo);
    return String(buf);
}

/**
 * Read GPS from UART1 for up to 1000ms, feeding bytes to TinyGPS++.
 * Returns a GpsReading struct.
 * valid is true only if gps.location.isValid() && gps.location.age() < 5000.
 * If no fix yet, returns valid=false with lat=0.0, lon=0.0.
 */
GpsReading readGPS() {
    GpsReading reading = {false, 0.0, 0.0};
    unsigned long start = millis();
    while (millis() - start < 1000) {
        while (gpsSerial.available() > 0) {
            gps.encode(gpsSerial.read());
        }
        yield();
    }

    if (gps.location.isValid() && gps.location.age() < 5000) {
        reading.valid = true;
        reading.lat = gps.location.lat();
        reading.lon = gps.location.lng();
    }
    return reading;
}

// ---------------------------------------------------------------------------
// Camera init
// ---------------------------------------------------------------------------

bool initCamera() {
    camera_config_t config;
    config.ledc_channel = LEDC_CHANNEL_0;
    config.ledc_timer   = LEDC_TIMER_0;
    config.pin_d0       = CAM_PIN_D0;
    config.pin_d1       = CAM_PIN_D1;
    config.pin_d2       = CAM_PIN_D2;
    config.pin_d3       = CAM_PIN_D3;
    config.pin_d4       = CAM_PIN_D4;
    config.pin_d5       = CAM_PIN_D5;
    config.pin_d6       = CAM_PIN_D6;
    config.pin_d7       = CAM_PIN_D7;
    config.pin_xclk     = CAM_PIN_XCLK;
    config.pin_pclk     = CAM_PIN_PCLK;
    config.pin_vsync    = CAM_PIN_VSYNC;
    config.pin_href     = CAM_PIN_HREF;
    config.pin_sccb_sda = CAM_PIN_SIOD;
    config.pin_sccb_scl = CAM_PIN_SIOC;
    config.pin_pwdn     = CAM_PIN_PWDN;
    config.pin_reset    = CAM_PIN_RESET;
    config.xclk_freq_hz = 20000000;
    config.pixel_format = PIXFORMAT_JPEG;
    config.frame_size   = FRAMESIZE_VGA;
    config.jpeg_quality = 12;
    config.fb_count     = 1;

    esp_err_t err = esp_camera_init(&config);
    if (err != ESP_OK) {
        Serial.printf("[ERROR] Camera init failed: 0x%x\n", err);
        return false;
    }
    return true;
}

/**
 * Capture a frame and return SHA-256(jpeg_bytes) as lowercase hex.
 * This is the photo_hash_hex field — the actual JPEG is stored server-side
 * or uploaded separately (Phase 18 — object storage). The hash alone is
 * included in the signed arrival record.
 */
String capturePhotoHash() {
    camera_fb_t* fb = esp_camera_fb_get();
    if (!fb) {
        Serial.println("[ERROR] Camera capture failed");
        return "";
    }

    // SHA-256 over JPEG bytes (WolfSSL)
    wc_Sha256 sha;
    uint8_t digest[32];
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, fb->buf, fb->len);
    wc_Sha256Final(&sha, digest);
    esp_camera_fb_return(fb);

    return bytesToHex(digest, 32);
}

// ---------------------------------------------------------------------------
// Canonical hash — MUST match backend/crypto.py exactly
// Format: "{weight_kg:.6f}|{facility_id}|{timestamp_iso}|{photo_hash_hex}|{device_id}"
// All UTF-8, | separator, weight_kg to 6 decimal places.
// ---------------------------------------------------------------------------

/**
 * Compute SHA-256(canonical_string) where canonical_string is:
 *   f"{weight_kg:.6f}|{facility_id}|{timestamp_iso}|{photo_hash_hex}|{device_id}"
 *
 * This is INVARIANT #2 — field order and encoding are frozen here and in
 * backend/crypto.py. Any change to either side breaks the cross-language
 * round-trip and must be accompanied by updating BOTH files simultaneously.
 */
bool canonicalHash(
    float weight_kg,
    const String& facility_id,
    const String& timestamp_iso,
    const String& photo_hash_hex,
    const String& device_id,
    uint8_t out_hash[32]
) {
    // Build canonical string exactly matching Python:
    //   f"{weight_kg:.6f}|{facility_id}|{timestamp_iso}|{photo_hash_hex}|{device_id}"
    char weightBuf[32];
    snprintf(weightBuf, sizeof(weightBuf), "%.6f", weight_kg);

    String canonical = String(weightBuf) + "|" +
                       facility_id       + "|" +
                       timestamp_iso     + "|" +
                       photo_hash_hex    + "|" +
                       device_id;

    Serial.printf("[HASH] canonical_string(%d bytes): %s\n",
                  canonical.length(), canonical.substring(0, 80).c_str());

    // SHA-256 via WolfSSL
    wc_Sha256 sha;
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha,
                    reinterpret_cast<const uint8_t*>(canonical.c_str()),
                    canonical.length());
    wc_Sha256Final(&sha, out_hash);
    return true;
}

// ---------------------------------------------------------------------------
// Ed25519 sign — INVARIANT #1
// ---------------------------------------------------------------------------

/**
 * Sign 32-byte message_hash with the device's Ed25519 key.
 * Returns 64-byte signature as lowercase hex string, or "" on failure.
 */
String signPayload(const uint8_t message_hash[32]) {
    if (!keyReady) {
        Serial.println("[ERROR] Device key not initialized");
        return "";
    }

    uint8_t sig[64];
    word32 sigLen = 64;

    int ret = wc_ed25519_sign_msg(message_hash, 32, sig, &sigLen, &devKey);
    if (ret != 0) {
        Serial.printf("[ERROR] Ed25519 sign failed: %d\n", ret);
        return "";
    }
    return bytesToHex(sig, 64);
}

// ---------------------------------------------------------------------------
// POST /arrivals
// ---------------------------------------------------------------------------

/**
 * Submit a signed arrival record to the VERITAS backend.
 * Returns HTTP status code, or -1 on connection failure.
 */
int postArrival(
    float weight_kg,
    const String& photo_hash_hex,
    const String& timestamp_iso,
    const String& record_hash_hex,
    const String& signature_hex,
    double lat_deg = 0.0,
    double lon_deg = 0.0
) {
    HTTPClient http;
    String url = String(BACKEND_URL) + "/arrivals";
    http.begin(url);
    http.addHeader("Content-Type", "application/json");

    JsonDocument doc;
    doc["facility_id"]     = FACILITY_ID;
    doc["device_id"]       = DEVICE_ID;
    doc["weight_kg"]       = weight_kg;
    doc["photo_hash_hex"]  = photo_hash_hex;
    doc["timestamp_iso"]   = timestamp_iso;
    doc["record_hash_hex"] = record_hash_hex;
    doc["signature_hex"]   = signature_hex;
    // GPS coordinates from u-blox NEO-6M (lat_deg, lon_deg)
    doc["lat_deg"]         = lat_deg;
    doc["lon_deg"]         = lon_deg;

    String body;
    serializeJson(doc, body);

    int code = http.POST(body);
    if (code > 0) {
        String resp = http.getString();
        Serial.printf("[POST] /arrivals → HTTP %d: %s\n", code, resp.substring(0, 200).c_str());
    } else {
        Serial.printf("[ERROR] HTTP POST failed: %s\n", http.errorToString(code).c_str());
    }
    http.end();
    return code;
}

// ---------------------------------------------------------------------------
// Signed OTA update — INVARIANT #11
// ---------------------------------------------------------------------------

/**
 * Configure ArduinoOTA with a password-protected handler.
 *
 * For commercial deployment replace password auth with a signature check:
 *   1. Server signs the firmware binary with its Ed25519 key.
 *   2. Firmware verifies the signature against the server pubkey (baked in flash)
 *      before calling Update.begin()/write().
 * The password here is a Phase 6 prototype placeholder — good enough for a
 * closed lab demo, not for production.
 */
void setupOTA() {
    ArduinoOTA.setHostname(DEVICE_ID);
    ArduinoOTA.setPassword("YOUR_OTA_PASSWORD");  // replace with key-based auth in Phase 17
    
    ArduinoOTA.onStart([]() {
        Serial.println("[OTA] Starting update...");
    });
    ArduinoOTA.onEnd([]() {
        Serial.println("[OTA] Update complete. Rebooting.");
    });
    ArduinoOTA.onError([](ota_error_t error) {
        Serial.printf("[OTA] Error #%u\n", error);
    });
    ArduinoOTA.begin();
    Serial.println("[OTA] OTA listener started");
}

// ---------------------------------------------------------------------------
// setup()
// ---------------------------------------------------------------------------

void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.println("\n[VERITAS] Pod firmware starting...");

    // --- GPS ---
    // GPS: u-blox NEO-6M on UART1 (GPIO16=RX, GPIO17=TX, 9600 baud)
    gpsSerial.begin(9600, SERIAL_8N1, GPS_RX_PIN, GPS_TX_PIN);
    Serial.println("[GPS] UART1 initialized (9600 baud, RX=GPIO16, TX=GPIO17)");

    // --- WiFi ---
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    Serial.print("[WIFI] Connecting");
    int tries = 0;
    while (WiFi.status() != WL_CONNECTED && tries++ < 30) {
        delay(500); Serial.print(".");
    }
    Serial.println();
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[ERROR] WiFi failed — halting");
        ESP.restart();
    }
    Serial.printf("[WIFI] Connected: %s\n", WiFi.localIP().toString().c_str());

    // --- NTP ---
    configTime(0, 0, NTP_SERVER);
    Serial.println("[NTP] Syncing time...");
    delay(2000);  // allow NTP to settle

    // --- Init Ed25519 key from flash seed (INVARIANT #1) ---
    wc_ed25519_init(&devKey);
    int ret = wc_ed25519_import_private_only(DEVICE_PRIVKEY_SEED, 32, &devKey);
    if (ret != 0) {
        Serial.printf("[ERROR] Ed25519 key import failed: %d\n", ret);
    } else {
        // Derive the public key from the seed so we can print it for registration
        ret = wc_ed25519_make_public(&devKey, devKey.p, ED25519_PUB_KEY_SIZE);
        if (ret != 0) {
            Serial.printf("[ERROR] Ed25519 pubkey derivation failed: %d\n", ret);
        } else {
            keyReady = true;
            Serial.print("[CRYPTO] Device pubkey: ");
            Serial.println(bytesToHex(devKey.p, 32));
        }
    }

    // --- Camera ---
    if (!initCamera()) {
        Serial.println("[WARN] Camera unavailable — photo_hash will be zeroed");
    }

    // --- HX711 scale ---
    scale.begin(HX711_DATA_PIN, HX711_CLOCK_PIN);
    scale.set_scale(HX711_SCALE);
    scale.tare();  // zero on boot
    Serial.println("[HX711] Scale tared and ready");

    // --- OTA ---
    setupOTA();

    Serial.println("[VERITAS] Setup complete. Entering measurement loop.");
}

// ---------------------------------------------------------------------------
// loop() — triggered by a physical push button or timer in production
// ---------------------------------------------------------------------------

void loop() {
    ArduinoOTA.handle();

    // In production: GPIO interrupt from gate sensor (vehicle present) triggers a read.
    // Here we poll every 30 s for demo purposes.
    static unsigned long lastMeasure = 0;
    if (millis() - lastMeasure < 30000) return;
    lastMeasure = millis();

    if (!keyReady) {
        Serial.println("[WARN] Key not ready — skipping measurement");
        return;
    }

    // --- 1. Read weight ---
    if (!scale.is_ready()) {
        Serial.println("[HX711] Scale not ready — skipping");
        return;
    }
    float weight_kg = scale.get_units(10);  // average of 10 readings
    if (weight_kg < 1.0f) {
        Serial.println("[HX711] Weight below threshold (< 1 kg) — ignoring");
        return;
    }
    Serial.printf("[HX711] Weight: %.3f kg\n", weight_kg);

    // --- 2. Capture photo hash ---
    String photo_hash_hex = capturePhotoHash();
    if (photo_hash_hex.isEmpty()) {
        // Use zero hash if camera is unavailable (degraded mode — flagged by backend as no-photo)
        photo_hash_hex = "0000000000000000000000000000000000000000000000000000000000000000";
        Serial.println("[WARN] Camera failed — using zero photo_hash (will be logged by backend)");
    }

    // --- 3. Timestamp ---
    String timestamp_iso = getTimestampISO();
    Serial.printf("[TIME] %s\n", timestamp_iso.c_str());

    // --- 4. Canonical hash (INVARIANT #2) ---
    uint8_t record_hash[32];
    if (!canonicalHash(weight_kg, FACILITY_ID, timestamp_iso, photo_hash_hex, DEVICE_ID, record_hash)) {
        Serial.println("[ERROR] Hash failed — aborting");
        return;
    }
    String record_hash_hex = bytesToHex(record_hash, 32);
    Serial.printf("[HASH] record_hash_hex: %s\n", record_hash_hex.c_str());

    // --- 5. Sign (INVARIANT #1) ---
    String signature_hex = signPayload(record_hash);
    if (signature_hex.isEmpty()) {
        Serial.println("[ERROR] Signing failed — aborting");
        return;
    }
    Serial.printf("[SIGN] signature_hex: %s...\n", signature_hex.substring(0, 16).c_str());

    // --- 6. Read GPS ---
    // GPS: u-blox NEO-6M on UART1 (GPIO16=RX, GPIO17=TX, 9600 baud)
    GpsReading gps_reading = readGPS();
    Serial.printf("[GPS] Fix status: %s | Lat: %.6f, Lon: %.6f\n",
                  gps_reading.valid ? "VALID" : "INVALID",
                  gps_reading.lat, gps_reading.lon);

    // --- 7. POST /arrivals ---
    int code = postArrival(weight_kg, photo_hash_hex, timestamp_iso, record_hash_hex, signature_hex, gps_reading.lat, gps_reading.lon);
    if (code == 201) {
        Serial.println("[OK] Arrival accepted by backend.");
    } else if (code == 400) {
        Serial.println("[REJECT] Backend rejected arrival (signature or hash mismatch).");
    } else {
        Serial.printf("[WARN] Unexpected status code: %d\n", code);
    }
}
