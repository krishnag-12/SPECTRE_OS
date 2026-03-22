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
- **Display Output:** *(Configurable via `platformio.ini`)*
  - 16x2 Character LCD (I2C) *OR*
  - 0.96" OLED Display (I2C) *OR*
  - Color TFT Display (SPI)
- **Input:** Push buttons (Debounced via AceButton library)

---

## 💻 Software & Development Environment

This project uses **PlatformIO** (via VS Code) rather than the standard Arduino IDE to handle advanced dependency management and build configurations.

### **Initial Setup (For All Contributors)**
1. Download and install [Visual Studio Code](https://code.visualstudio.com/).
2. Open VS Code, go to the Extensions tab, and install the **PlatformIO IDE** extension.
3. Clone this repository to your local machine:
```bash
git clone [https://github.com/krishnag-12/SPECTRE_OS.git](https://github.com/krishnag-12/SPECTRE_OS.git)
def open the cloned SPECTRE_OS folder in VS Code. PlatformIO will automatically read the platformio.ini file and download all necessary libraries (RadioLib, AceButton, and your chosen Display library).
```
📚 Project Documentation (MCP)
This repository is configured with a Model Context Protocol (MCP) server to keep workspace documentation synced. Ensure your IDE is reading the `.vscode/mcp.json` file to securely access the latest architectural docs and driver specifications.

🌿 Contribution Guidelines & Git Workflow
To prevent code conflicts and keep the main project stable, please follow this branching workflow:

1. Never work directly on main. Always create a new branch for the specific feature or bug you are working on.
   
```bash
git checkout -b feature/lora-initialization
# or
git checkout -b ui/oled-menu-design
```
2. Commit your changes regularly.
Write clear, descriptive commit messages.
   
```bash
git add .
git commit -m "Added initial LoRa packet transmission logic"
```
3. Sync before you push.
Always pull the latest changes from main before pushing your branch to GitHub.
   
```bash
git pull origin main
git push origin feature/lora-initialization
```
4. Create a Pull Request (PR).
Go to GitHub and open a PR to merge your feature branch into main. Tag your teammates to review the code before merging.

📁 Project Structure
Plaintext
SPECTRE_OS/
├── .vscode/               # IDE and MCP configurations
├── include/               # Custom header files (.h)
├── lib/                   # Private, project-specific libraries
├── src/                   # Main source code (.cpp files)
│   └── main.cpp           # Primary entry point
├── .gitignore             # Ignored files (includes /.pio/)
├── platformio.ini         # Environment and dependency configuration
└── README.md              # Project documentation
