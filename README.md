# FritzTheCat

FritzTheCat is a Streamlit application that hides text or binary data inside images using simple LSB steganography.

## Chunked Images

When the source image cannot be compressed to meet the desired target size, the app automatically
splits the payload across multiple images. Each output image holds a consecutive portion of the
original message or file.

### Reassembling
1. Decode each image in the order they were produced (`*_part1.png`, `*_part2.png`, ...).
2. For text payloads, concatenate the decoded strings.
3. For binary payloads, concatenate the decoded byte chunks and then decompress if zlib was used.

The resulting string or binary blob will match the original payload.
