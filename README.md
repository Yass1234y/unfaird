# macOSAppstoreDecrypter

I built this to turn a spare M1 MacBook Air into a self-hosted IPA download and decryption server, you can check at: https://decrypt.34306.lol. It can be access in a browser, you find an app by name or Bundle ID, and then the Mac handles the App Store download and decryption in the background.

The service includes a download queue, live progress, a local cache, user accounts and support for separate multiple App Store region accounts.

## Requirements

The decryptor depends on M1 macOS:

- MacBook Air (M1, 2020), M1 chip only
- (at least) 8 GB unified memory
- 512 GB SSD
- macOS Big Sur 11.2.3 or lower (you can downgrade macOS for it)
- Python 3
- An Apple ID that can access the App Store

It only supports the Mac M1 with macOS 11.2.3 or lower!

I used this on a 8 GB M1 so some large apps cannot complete a full decryption. Some apps that runs out of memory during decrypt so that I need to make a fall back to decrypting the main executable only. In that case, embedded frameworks and plug-ins remain encrypted (not affected much if you don't need).

## Installation

Clone or download the repository, then open a terminal in its directory:

```bash
cd macOSAppstoreDecrypter
chmod +x setup.sh
./setup.sh
```

The installer prepares the bundled tools, installs Flask, creates `.env`, signs `ipatool` into the configured Apple ID, and installs a LaunchDaemon for the web server. It also asks whether the site should stay on the local network or be exposed through a Cloudflare Tunnel.

If you enable `lidawake`, the Mac will keep running after the lid is closed. Keep it connected to power and make sure it did not heat up.

## Configuration

The installer creates `.env` from `.env.example`. You can also create it manually:

```bash
cp .env.example .env
nano .env
```

For a single storefront, set at least these values:

| Setting | Purpose |
| --- | --- |
| `MAC_PASSWORD` | The macOS login password used locally for `sudo` and keychain operations. |
| `APPLE_ID_EMAIL` | The Apple ID used by `ipatool`. |
| `APPLE_ID_PASSWORD` | The password for that Apple ID. |
| `STORE_COUNTRY` | A two-letter storefront code such as `vn`, `cn`, `jp` or `us`. |

The credentials in `.env` are stored as plain text. The installer limits the file to the current user with mode `600`, and Git ignores it, but you should still use a secondary Apple ID and treat the Mac as a trusted machine.

### Multiple storefronts

Each storefront needs its own Apple ID and its own home directory because `ipatool` keeps one login per configuration directory. Leave `APPLE_ID_EMAIL` and `APPLE_ID_PASSWORD` empty, then create `regions.json` next to `app.py`:

```json
{
  "vn": {
    "email": "vn-account@example.com",
    "pass": "password",
    "home": "~/ipatool-homes/vn",
    "country": "vn",
    "label": "Vietnam"
  },
  "cn": {
    "email": "cn-account@example.com",
    "pass": "password",
    "home": "~/ipatool-homes/cn",
    "country": "cn",
    "label": "China"
  },
  "jp": {
    "email": "jp-account@example.com",
    "pass": "password",
    "home": "~/ipatool-homes/jp",
    "country": "jp",
    "label": "Japan"
  }
}
```

The other settings in `.env.example` control the daily quota, cache lifetime, reserved disk space, admin credentials, server port, and data paths.

## After installation

The service listens on port `6347` by default:

- Local: `http://127.0.0.1:6347`
- Local network: `http://<mac-ip>:6347`
- Admin page: `http://<mac-ip>:6347/admin`

On the first run, an admin password is generated if you did not set one in `.env`. It is written to `server.log` and to `ADMIN_PASSWORD.txt` inside `DATA_DIR`, which defaults to `/var/tmp/macOSAppstoreDecrypter`.

The Cloudflare option makes the service reachable from the internet. Only enable it if that is intentional and add any access controls you need in front of the service.

## Common commands

```bash
# Follow the server log
tail -f server.log

# Check whether the service is responding
curl http://127.0.0.1:6347/health

# Restart the server
sudo launchctl kickstart -k system/com.macOSAppstoreDecrypter.server

# Stop the server
sudo launchctl bootout system/com.macOSAppstoreDecrypter.server

# Manage lid-closed operation after lidawake has been installed
sudo lidawake on
sudo lidawake off
lidawake status
```

## Legal note

Use this project for research only. Use of the software and of your Apple ID remains your responsibility. The project is provided as-is, without warranty.

## License

The project source is released under the [MIT License](LICENSE). The bundled third-party tools remain subject to their own licenses.

## Credits

- [ipatool](https://github.com/majd/ipatool) handles App Store authentication and IPA downloads.
- [unfaird](https://github.com/Lakr233/unfaird) by [Lakr233](https://github.com/Lakr233) provides the decryption work this project builds on.
