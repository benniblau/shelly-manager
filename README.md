# Shelly Device Manager

A Python application that automatically discovers Shelly smart home devices on your local network, checks for available firmware updates, and can perform bulk updates using the official Shelly APIs.

## Features

- 🔍 **Network Discovery**: Automatically scans all local network interfaces to find Shelly devices
- 🔄 **Update Checking**: Checks for available firmware updates using official Shelly APIs
- 🚀 **Bulk Updates**: Install updates on multiple devices with a single command
- 🏠 **Device Information**: Displays detailed information about each discovered device
- ⚡ **Fast Scanning**: Uses asynchronous I/O for efficient network scanning
- 🔧 **Cross-Generation Support**: Works with both Gen1 and Gen2+ Shelly devices
- 🤖 **Automation Support**: Can run in auto-update mode for unattended operation

## Supported Devices

This application works with all Shelly devices that expose the standard Shelly HTTP API, including:

- Shelly 1/1PM/1L
- Shelly 2.5/Plus 2PM
- Shelly 4Pro
- Shelly Plug/Plug S/Plus Plug US/IT
- Shelly Dimmer/Dimmer 2/Plus Dimmer
- Shelly RGBW2/RGB
- Shelly Uni
- Shelly EM/3EM
- Shelly Door/Window/Motion sensors
- And many more...

## Requirements

- Python 3.7+
- Network connectivity to Shelly devices

## Installation

1. Clone or download this repository
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Basic Scan

Simply run the application to scan for devices and check for updates:

```bash
python app.py
```

### Advanced Options

```bash
# Enable debug mode for troubleshooting
python app.py --debug

# Use shorter timeout for faster scanning
python app.py --timeout 3

# Auto-update mode (installs updates without prompting)
python app.py --auto-update

# Include beta/development versions when checking for updates
python app.py --include-beta

# Combine options
python app.py --debug --timeout 3 --auto-update --include-beta
```

### Bulk Updates

After scanning, if devices with available updates are found, you'll be prompted:

```
============================================================
BULK UPDATE AVAILABLE
============================================================
Found 3 device(s) with available updates:
  • shellyplus1pm-cc7b5c8173e4 (SNSW-001P16EU)
    Current: v1.6.2 → Available: v1.7.0
  • shelly1pmminig3-54320440a4a0 (S3SW-001P8EU)
    Current: v1.6.2 → Available: v1.7.0

⚠️  Important notes:
   • Devices will reboot during the update process
   • Updates typically take 2-5 minutes per device
   • Do not power off devices during the update
   • Network connectivity is required throughout the process

Do you want to install updates on all 3 device(s)? [y/N]:
```

Choose `y` to proceed with bulk updates or `n` to skip.

The application will:

1. Automatically detect all local network interfaces
2. Scan each network for Shelly devices
3. Retrieve detailed information from each device
4. Check for available firmware updates
5. Display a comprehensive summary
6. Offer to install updates on all devices that need them

### Beta Version Support

By default, the application only checks for stable firmware versions. To include beta/development versions:

```bash
python app.py --include-beta
```

**Important considerations for beta versions:**
- Beta versions may contain bugs or incomplete features
- Only use beta versions if you need specific new features or bug fixes
- Beta versions are intended for testing and development purposes
- Always backup device configurations before updating to beta versions

When beta mode is enabled, the application will:
- Check both stable and beta versions during scanning
- Prioritize beta versions when available (if newer than stable)
- Install beta versions when performing updates
- Clearly mark beta versions in the output with "(beta)" label

### Example Output

```
Shelly Device Manager
====================
Starting Shelly device discovery...
Found network: 192.168.1.0/24
Scanning network range: 192.168.1.0/24
Checking 254 IP addresses...
Found Shelly device: Shelly-Kitchen (SHSW-25) at 192.168.1.150
Found Shelly device: Shelly-Living Room (SHPLG-S) at 192.168.1.151

Discovery complete! Found 2 Shelly device(s)

Getting detailed information for 2 device(s)...

--- Shelly-Kitchen (192.168.1.150) ---
WiFi: MyNetwork (RSSI: -45)
Uptime: 72 hours
✅ Up to date: 20230913-114008/v1.14.0-gcb84623

--- Shelly-Living Room (192.168.1.151) ---
WiFi: MyNetwork (RSSI: -52)
Uptime: 168 hours
🔄 UPDATE AVAILABLE: 20231107-162056/v1.14.1-gfa1bc37 (current: 20230913-114008/v1.14.0-gcb84623)

============================================================
SHELLY DEVICE SUMMARY (2 device(s) found)
============================================================
1. Shelly-Kitchen
   Type: SHSW-25
   IP: 192.168.1.150
   MAC: AA:BB:CC:DD:EE:FF
   Firmware: 20230913-114008/v1.14.0-gcb84623
   Status: ✅ Up to date

2. Shelly-Living Room
   Type: SHPLG-S
   IP: 192.168.1.151
   MAC: AA:BB:CC:DD:EE:01
   Firmware: 20230913-114008/v1.14.0-gcb84623
   Status: 🔄 UPDATE AVAILABLE

🔔 1 device(s) have updates available!

⏱️  Scan completed in 12.3 seconds
```

## How It Works

1. **Network Detection**: The app uses `netifaces` to detect all available network interfaces and their IP ranges
2. **Device Discovery**: Asynchronously scans each IP address in the network ranges, looking for devices that respond to `http://[ip]/shelly`
3. **Device Verification**: Validates that responding devices are actual Shelly devices by checking the response format
4. **Status Retrieval**: Fetches detailed status information from `http://[ip]/status`
5. **Update Checking**: Uses both Gen2+ (`/rpc/Shelly.CheckForUpdate`) and Gen1 (`/ota/check`) APIs to check for updates
6. **Bulk Updates**: Uses Gen2+ (`/rpc/Shelly.Update`) and Gen1 (`/ota/start`) APIs to install updates

## Update Process

When you choose to install updates:

1. **Safety Checks**: The app verifies update availability before proceeding
2. **Sequential Updates**: Updates are installed one device at a time to avoid network overload
3. **Reboot Management**: Devices automatically reboot during the update process
4. **Progress Tracking**: Real-time status updates show which devices are being updated
5. **Error Handling**: Failed updates are reported with detailed error messages

**Important**: During updates, devices will:
- Temporarily lose network connectivity
- Reboot automatically (takes 1-2 minutes)
- Resume normal operation with new firmware

## Configuration

You can modify the following parameters in the `ShellyDeviceManager` class:

- `timeout`: HTTP request timeout (default: 5 seconds)
- `concurrent_limit`: Maximum concurrent network requests (default: 50)

## Troubleshooting

### Update Issues

**Common update scenarios:**

- **Gen3 "Already in Progress"**: Normal response indicating update was successfully initiated
- **HTTP 500 Error**: Device may already be up to date or temporarily busy  
- **Connection Timeout**: Device might be rebooting or network congested
- **Update Failed**: Device might have restrictions or insufficient storage
- **No Response**: Device could be in AP mode or disconnected
- **"No update info available"**: Device may need manual update check first

**Gen3 Device Specific Notes:**

Gen3 (Mini 1PM G3) devices have unique update behavior:
- May return "Already in progress" which indicates successful update initiation
- Sometimes return empty response data (treated as success)
- Require fresh update check before installation in some cases
- The application automatically handles these Gen3-specific behaviors

**Solutions:**

1. **Retry Later**: Wait 5-10 minutes and run the scan again
2. **Individual Updates**: Update devices one at a time instead of bulk
3. **Check Network**: Ensure stable WiFi connection for all devices
4. **Manual Update**: Use the Shelly app for problematic devices

### Discovery Issues

If no devices are found:

1. **Network Connectivity**: Ensure Shelly devices are connected to the same network as your computer
2. **Device Status**: Verify devices are powered on and connected to WiFi
3. **AP Mode**: Make sure devices are not in Access Point mode
4. **Firewall**: Check that your firewall isn't blocking HTTP requests
5. **Network Size**: Very large networks (>1000 hosts) are automatically skipped to prevent network flooding

## Security Notes

- This application only reads device information and checks for updates by default
- Bulk update functionality requires explicit user confirmation (unless `--auto-update` is used)
- All communication uses standard HTTP requests to the local network
- Updates are downloaded directly from Shelly servers by the devices themselves
- No device settings or configuration are modified beyond firmware updates
- The app respects device authentication if enabled

## Command Line Options

```bash
# Show help
python app.py --help

# Basic scan (safe, read-only)
python app.py

# Debug mode (shows detailed API responses)
python app.py --debug

# Faster scanning with shorter timeout
python app.py --timeout 2

# Fully automated mode (scans and updates without prompts)
python app.py --auto-update

# Combined options for automation with debugging
python app.py --debug --auto-update --timeout 3
```

## License

This project is provided as-is for educational and personal use.

## Contributing

Feel free to submit issues, feature requests, or pull requests to improve this tool!
