# DefenseR

English · [Русский](README.ru.md)

A smart layer on top of Microsoft Defender for a home Windows PC. It watches processes, the network, startup entries and new files, explains what it finds in plain language and offers actions, always with your confirmation.

DefenseR does not replace an antivirus and has no kernel driver. It is a personal project at an early stage.

## What it does

- **Overview and incidents.** Rules notice disabled protection, programs running from temp folders, new startup entries and other suspicious things.
- **File scan.** A local model (LightGBM, trained on EMBER 2018) rates programs by their structure without running them, and checks the digital signature. New programs in Downloads, on the desktop, in the temp folder and on removable drives are checked on their own. Scripts and shortcuts are read for dangerous commands, ZIP archives are looked into without unpacking, and names like `invoice.pdf.exe` are flagged. A file can also be looked up on VirusTotal (only its SHA-256 is sent).
- **Chains of events.** When a recently arrived unsigned file was run, added itself to startup and went online, that is shown as one story with a timeline instead of separate alerts.
- **Behaviour profile.** DefenseR learns which programs normally go online and reports new ones.
- **Responses.** End a process, quarantine a file, block a program's network access, turn a startup entry off. Everything is reversible and happens only on your command.
- **Explanations from Claude.** On request, an incident is explained in plain language. You need your own Anthropic API key.
- **Running in the background.** A notification-area icon, Windows notifications, start with Windows, automatic updates.
- **Two languages.** English and Russian, switched in the settings.

## Install

Download `DefenseR_x.y.z_x64-setup.exe` from the [releases](../../releases/latest) page and run it. The installer is not signed with a publisher certificate, so SmartScreen shows a warning: "More info" → "Run anyway".

After that the app updates itself. An update is accepted only if its signature matches the public key built into the app.

## Privacy

- Files, the process list and network connections never leave the computer.
- VirusTotal receives only a file's SHA-256: when you press the button or, if you turn it on in the settings, automatically for files the model calls malicious.
- Anthropic receives only the text of an incident you pressed "Explain with AI" on; the path to your profile folder is replaced with `%USERPROFILE%`.
- API keys are kept in Windows Credential Manager, not in the app's files.
- The app contacts GitHub to look for updates.

## Building from source

You need Node.js, Rust and the [Tauri prerequisites](https://tauri.app/start/prerequisites/) for Windows.

```bash
npm install
npm run tauri dev
```

The trained model is in `src-tauri/model`. The scripts to retrain it are in `ml/`; the EMBER dataset is not part of the repository.

Tests run on every commit in GitHub Actions; releases are built and signed on the maintainer's machine.

## Releasing a new version

1. Bump the version in `src-tauri/tauri.conf.json`, `src-tauri/Cargo.toml` and `package.json`, and commit.
2. Run `npm run release -- "What's new"`.

The script builds the installer, signs it with the key in `~/.tauri/defenser.key` and publishes the release on GitHub. The private key never enters the repository; without it, no update can be released for copies that are already installed.

## License

[MIT](LICENSE)
