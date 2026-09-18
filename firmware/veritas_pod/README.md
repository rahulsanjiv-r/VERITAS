# VERITAS firmware stub — veritas_pod.ino
# ESP32 + HX711 (load cell) + Camera + Ed25519 signing + signed OTA

# STATUS: Phase 6 skeleton — not yet compiled or tested on hardware.
# All crypto and canonical hash field order MUST match backend/crypto.py exactly.
# Cross-language round-trip test required before wiring up any live endpoint.

# Field order for canonical hash (must match backend/crypto.py CANONICAL_FIELD_ORDER):
# "{weight_kg:.6f}|{facility_id}|{timestamp_iso}|{photo_hash_hex}|{device_id}"
# Separator: | (pipe), weight formatted to 6 decimal places, all UTF-8

# This file is a placeholder. Real firmware implementation requires:
# 1. HX711 library for load cell reading
# 2. ESP32 camera driver (ESP32-CAM or Heltec)
# 3. Ed25519 Arduino library (Option B: software) or NXP SE050 SDK (Option C)
# 4. ArduinoJson for POST body serialization
# 5. ESP32 HTTPClient for the backend POST
# 6. Signed OTA via Update::setMD5() + signature verification (invariant #11)

# See ARCHITECTURE.md and THREAT-MODEL.md for the full firmware spec and threat analysis.
