# Gecko Browser Data Decryptor

A proof-of-concept tool written in TypeScript for extracting and decrypting data from Gecko-based browsers (Firefox, Thunderbird, etc.).

## Features

- Extracts and decrypts stored passwords
- Collects browser cookies
- Extracts bookmarks
- Collects browsing history
- Supports multiple Gecko-based browsers:
  - Firefox
  - Thunderbird
  - SeaMonkey
  - Pale Moon
  - Waterfox
  - and more

## Requirements

- Node.js (v14+)
- Windows OS (the tool uses Windows-specific paths and libraries)
- Target browsers must be installed (to access their NSS libraries for decryption)

## Dependencies

- `ffi-napi`: For interacting with native libraries (mozglue.dll, nss3.dll)
- `ref-napi`: For working with C data structures in JavaScript
- `sqlite3`: For querying browser databases

## Installation

1. Clone this repository
2. Install dependencies:
   ```
   npm install
   ```
3. Build the project:
   ```
   npm run build
   ```

## Usage

Run the tool:
```
npm start
```

Follow the prompts to enter:
1. Windows username (to locate browser profiles)
2. Output directory for extracted data

The tool will then extract available data from all supported browsers and save results as JSON files in the specified output directory.

## Output Files

- `gecko_passwords.json`: Decrypted website credentials
- `gecko_cookies.json`: Browser cookies
- `gecko_bookmarks.json`: Saved bookmarks
- `gecko_history.json`: Browsing history

## Technical Details

This tool works by:
1. Locating browser profile directories for various Gecko-based browsers
2. Loading the browser's native NSS libraries for decryption
3. Reading and parsing browser database files (SQLite)
4. Decrypting encrypted data using the browsers' own decryption functions
5. Exporting the results to JSON format

## Disclaimer

This tool is meant for educational and research purposes only. Only use it on systems you own or have permission to analyze. Extracting browser data without proper authorization may be illegal in your jurisdiction.
