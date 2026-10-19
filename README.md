# SAMURAI SHODOWN V SPECIAL - Accessibility Screen Reader Mod

A real-time, non-invasive accessibility screen reader and audio narrator for **SAMURAI SHODOWN V SPECIAL** on Windows.

Built specifically for visually impaired and blind players, this mod hooks into the game process via non-invasive Windows memory reading (`ReadProcessMemory`) to provide complete spoken narration of all game menus, settings, character selections, and match screens.

> **IMPORTANT REQUIREMENT:**
> **This mod is designed and tested exclusively for the official Steam release of SAMURAI SHODOWN V SPECIAL.**
> It requires the Steam version's asset and memory layout (`SSVS.exe`) to function properly. Non-Steam versions or differing game builds are **not supported**.

---

## Features

- **Full Front-End Menu Narration:**
  - Main Menu, Modes (Story, Versus, Training, Online, Gallery).
  - Room Settings, Lobby, Ranking & Leaderboards.
  - Game Settings, Video, Audio, and Input/Controls configurations.
  - Pause Menu and in-game confirmation dialogs.
- **Accurate 3x9 Character Select Grid Narration:**
  - Full narration of Player 1 and Player 2 cursor navigation.
  - 100% accurate alignment with the physical Neo-Geo character select grid (27 characters + Secret Boss Mizuki Rashojin).
  - Announcements for Slash / Bust style selection and character lock-in.
- **Multi-Synthesizer & Screen Reader Support:**
  - Automatic detection of running screen readers via **NVDA Controller Client** and **Prism** (supporting NVDA, JAWS, SAPI5, and more).
  - Zero latency speech output.
- **Non-Invasive:**
  - Zero DLL injection.
  - Zero modification of game files or ROM binaries.
  - Zero interference with game input or controllers.

---

## Character Selection Layout

The character select screen consists of a 3-row by 9-column grid, plus the hidden boss:

| Row | Col 1 | Col 2 | Col 3 | Col 4 | Col 5 | Col 6 | Col 7 | Col 8 | Col 9 |
|---|---|---|---|---|---|---|---|---|---|
| **Line 1** | Yoshitora Tokugawa | Gaoh (Hinowa no Kami) | Haohmaru | Genjuro Kibagami | Shizumaru Hisame | Kazuki Kazama | Sogetsu Kazama | Gaira Caffeine | Ukyo Tachibana |
| **Line 2** | Mina Majikina | Zankuro Minazuki | Nakoruru | Rera | Liu Yunfei | Basara Kubikiri | Tam Tam | Rasetsumaru | Rimururu |
| **Line 3** | Enja | Shiro Tokisada Amakusa | Suija | Galford D. Weller | Charlotte Christine | Yokai Kusaregedo | Kyoshiro Senryo | Jubei Yagyu | Hattori Hanzo |

- **Secret Character (Mizuki Rashojin):** Highlight **Gaoh** on Line 1, Col 2, and press **Down twice**.

---

## Installation & Usage

### Option 1: Using the Ready-to-Use ZIP (Recommended)
1. Download [`SSVS_Mod_Acessibilidade.zip`](SSVS_Mod_Acessibilidade.zip) directly from the repository.
2. Extract the contents into a `mod` subfolder inside your Steam game directory:
   ```
   SteamLibrary\steamapps\common\SAMURAI SHODOWN V SPECIAL\mod\
   ```
3. Start **NVDA** (or your preferred screen reader).
4. Run `Iniciar_Narrador.bat` (or start the game via Steam, then launch the batch file).
5. The narrator will announce: *"Narrador Samurai Shodown V Special ativado."* and begin speaking menus and selections immediately.

### Option 2: Building from Source
Requirements: Windows 10/11 with .NET Framework 4.5+ installed.
1. Clone the repository:
   ```bash
   git clone https://github.com/ohackercego/ssvs-accessibility-mod.git
   ```
2. Run the build script using PowerShell:
   ```powershell
   powershell -ExecutionPolicy Bypass -File build.ps1
   ```
3. The compiled `SsvsNarrator.exe` (x64) will be generated.

---

## Files Included in Release

- `SsvsNarrator.exe`: Compiled 64-bit narrator application.
- `SsvsNarrator.cs`: Complete C# source code.
- `Iniciar_Narrador.bat`: One-click startup script.
- `SSVS_Mod_Acessibilidade.zip`: Pre-packaged release zip for end-users.
- `nvdaControllerClient.dll`: Official 64-bit NVDA communication library.
- `prism.dll`: Multi-backend speech synthesis engine.
- `SpeechCore.dll`, `SRAL.dll`, `tolk.dll`, `UniversalSpeech.dll`: Additional screen reader bridging libraries.

---

## Keyboard / Console Controls
- When waiting for the game to start: Press **Spacebar**, **Enter**, or **O** in the narrator console window to manually open a Windows File Explorer dialog and select your `SSVS.exe`.

---

## License
MIT License. Developed for accessibility and screen reader integration for visually impaired fighting game enthusiasts.
