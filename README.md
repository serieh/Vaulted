### Vaulted

Vaulted is a command-line tool for securely backing up and restoring files, with a focus on web browser bookmarks. It encrypts your data locally using a strong passphrase and automatically uploads the backups to your personal Google Drive.

***

### Key Features

* **Secure Encryption**: Your files are protected with **AES-GCM** encryption and a key derived from your passphrase using **Argon2** (or PBKDF2 as a fallback) for robust security.
* **Google Drive Integration**: Seamlessly connects to your Google Drive to store encrypted backups, managing them with a configurable retention policy to save space.
* **Cross-Platform**: Supports Windows, macOS, and Linux, and provides desktop notifications to keep you informed of backup status.
* **Simple Automation**: Can store your passphrase in your OS's secure keyring for hands-free, automated backups.
* **Easy to Use**: The command-line interface provides simple commands to `setup` your configuration, `run` a backup, or `decrypt` a file.
