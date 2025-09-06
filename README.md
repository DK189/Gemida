# Gemida

**Gemini Assistant for IDA Pro** — integrate Google Gemini AI into IDA Pro to assist with reverse engineering.

## ✨ Features

- **Analyze current function**  
  Extracts pseudocode of the current function (and its callees within a safe token budget), sends it to Gemini, and receives back:
  - Suggested **new function names** (if applicable).  
  - **Comments** prefixed with `[Gemida]`, describing the purpose of each function.

- **Analyze all functions**  
  Processes the entire project in batches (200k–300k tokens each) to generate suggested names and comments across the whole binary.

- **Automatic integration**  
  Suggested names are automatically applied in IDA (renaming functions).  
  Suggested comments are added inline in IDA, prefixed with `[Gemida]` to make them distinguishable from manual notes.

- **Context-aware analysis**  
  Function groups are built by collecting callees recursively, ensuring Gemini receives enough context for better suggestions.

- **Environment variable for API key**  
  The plugin reads your Gemini API key from `GEMIDA_API_KEY`.  
  If not found, Gemida will alert you to set it before running.

## 🚀 Installation

1. Copy the plugin files to your IDA Pro `plugins/` directory:
   ```
   gemida.py
   gemida/
     ├── __init__.py
     ├── core.py
     ├── ida_utils.py
     └── llm.py
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Set your Gemini API key:
  By powershell:
   ```ps1
   setx GEMIDA_API_KEY "your_api_key_here"
   ```
   or run bellow command in cmd to open `Environment Variables` window
   ```cmd
   rundll32 sysdm.cpl,EditEnvironmentVariables
   ```
   and set variable with key `GEMIDA_API_KEY`.

4. Restart IDA Pro.

## 🛠 Usage

- Open **Plugins → Gemida** ( hotkeys **Ctrl+Shift+G** ).
- Choose one of:
  - **Analyze current function**
  - **Analyze all functions**
- Monitor progress and logs in the `Output` window.

## 💻 Compatibility

Gemida has been tested with IDA Pro 8.3.

We recommend using IDA Pro 8.3 or later for best results.

## 📌 Notes

- Destructor-like functions will **not** use `~`. Instead, Gemida will generate names with suffix `__DESTRUCTOR__` to keep them valid in C.  
- Comments are always prefixed with `[Gemida]` for clarity.  
- Large binaries will be split into multiple requests to respect token limits.

## 💡 Roadmap

- Support for additional reverse-engineering automation tasks.
- Advanced heuristics to refine AI-generated names.
- Improved context handling for very large projects.
- ...
