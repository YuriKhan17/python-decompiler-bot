# Python Malware Decompiler Bot

A Telegram bot for analyzing potentially malicious Python files. This bot can scan, decompile, and analyze Python code for various obfuscation techniques commonly used in malware.

## Features

- **Multiple Encoding Pattern Detection**: Supports various encoding techniques beyond `marshal.loads()`:
  - Base64 encoding/decoding
  - Zlib compression/decompression
  - Combined encoding (base64 + zlib)
  - Custom decode functions
  - Eval/exec patterns
  - Lambda expressions
  
- **Complete Bytecode Analysis**:
  - Dumps all byte blobs, not just first matches
  - Decompiles nested functions recursively
  - Provides hex dumps of binary data
  
- **Comprehensive Reporting**:
  - Creates detailed analysis reports
  - Logs all results in text files
  - Sends results via Telegram
  
- **Optional Sandbox Environment**:
  - Can run scripts in a sandboxed environment
  - Captures runtime behavior
  - Implements timeout protection

## Installation

### Prerequisites

- Python 3.7+
- Telegram Bot Token (get from [@BotFather](https://t.me/BotFather))

### Required Libraries

```bash
pip install python-telegram-bot uncompyle6
```

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/YuriKhan17/python-decompiler-bot.git
   cd python-decompiler-bot
   ```

2. Edit `decompiler_bot.py` and replace `YOUR_BOT_TOKEN` with your actual Telegram bot token:
   ```python
   TOKEN = "YOUR_BOT_TOKEN"  # Replace with your actual token
   ```

3. Run the bot:
   ```bash
   python decompiler_bot.py
   ```

## Usage

1. Start a chat with your bot on Telegram
2. Send a Python file (.py) to the bot
3. The bot will analyze the file and return:
   - An analysis report
   - Decompiled code (if obfuscated code is found)
   - Extracted binary data
   - Hex dumps of bytecode

## Bot Commands

- `/start` - Show
