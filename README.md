# SPECTRE_OS 📡

**SPECTRE_OS** is a decentralized, off-grid communication device built to operate without reliance on traditional cellular or internet infrastructure. By leveraging the power of ESP32 microcontrollers and long-range LoRa radio frequency, this system enables secure, peer-to-peer messaging and data transfer.

---

## 👥 Core Team & Responsibilities

- **Dhruv:** Architecture & RTOS (Real-Time Operating System)  
- **Krishna:** Hardware Integration & Device Drivers  
- **Kshitij:** User Interface (UI) & Quality Assurance (QA)

---

## 🛠️ Hardware Stack

- **Microcontroller:** Generic ESP32 DevKit V1  
- **Communication:** Ra-02 LoRa Module (433MHz/Sub-GHz)  
- **Display Output:** (Configurable via `platformio.ini`)
  - 16x2 Character LCD (I2C) *OR*
  - 0.96" OLED Display (I2C) *OR*
  - Color TFT Display (SPI)  
- **Input:** Push buttons (Debounced via AceButton library)

---

## 💻 Software & Development Environment

This project uses **PlatformIO** (via VS Code) rather than the standard Arduino IDE to handle advanced dependency management and build configurations.

### 🔧 Initial Setup (For All Contributors)

1. Download and install [Visual Studio Code](https://code.visualstudio.com/)  
2. Open VS Code → Extensions → install **PlatformIO IDE**  
3. Clone this repository:

```bash
git clone https://github.com/krishnag-12/SPECTRE_OS.git
Open the cloned SPECTRE_OS folder in VS Code

PlatformIO will automatically read the platformio.ini file and install all required libraries (RadioLib, AceButton, and display libraries).

📚 Project Documentation (MCP)

This repository is configured with a Model Context Protocol (MCP) server to keep workspace documentation synced.

Ensure your IDE reads the .vscode/mcp.json file to securely access:

Architectural docs
Driver specifications
🌿 Contribution Guidelines & Git Workflow

To keep the project stable and avoid conflicts, follow this workflow:

1️⃣ Create a Branch (Never use main directly)
git checkout -b feature/lora-initialization
# or
git checkout -b ui/oled-menu-design
2️⃣ Commit Changes Frequently
git add .
git commit -m "Added initial LoRa packet transmission logic"
3️⃣ Sync Before Pushing
git pull origin main
git push origin feature/lora-initialization
4️⃣ Create a Pull Request (PR)
Open a PR on GitHub
Merge into main
Tag teammates for review
📁 Project Structure
SPECTRE_OS/
├── .vscode/               # IDE and MCP configurations
├── include/               # Header files (.h)
├── lib/                   # Private libraries
├── src/                   # Source files (.cpp)
│   └── main.cpp           # Entry point
├── .gitignore             # Ignored files (/.pio/)
├── platformio.ini         # Build & dependencies
└── README.md              # Documentation
🚀 How to Add This to GitHub

After saving this as README.md:

git add README.md
git commit -m "Added project README file for team reference"
git push origin main
