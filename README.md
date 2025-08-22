# Stegosaurus Wrecks

This project hides data inside images using least significant bit (LSB) steganography.

## Security Scheme

Each payload is encoded with a 32-bit length and a CRC32 checksum before being
embedded. During decoding, the length and checksum are verified to detect
truncation or tampering. Images encoded prior to this scheme that lack the
checksum are still supported through a legacy terminator-based fallback.
