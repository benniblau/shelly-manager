import asyncio
import aiohttp
import json
import ipaddress
import netifaces
import socket
import sys
import argparse
from typing import List, Dict, Optional, Tuple
import time


class ShellyDeviceManager:
    """Manager class for discovering and managing Shelly devices."""
    
    def __init__(self, debug=False, auto_update=False, include_beta=False, networks=None):
        self.devices: List[Dict] = []
        self.timeout = 5.0
        self.concurrent_limit = 50
        self.debug = debug
        self.auto_update = auto_update
        self.include_beta = include_beta
        # Explicit ranges to scan instead of the locally attached ones. Needed when
        # the devices live on a routed subnet this host is not itself part of.
        self.networks = list(networks) if networks else []
        # How long to wait for a device to come back on the new firmware, and how
        # often to look. A Shelly OTA plus reboot takes well under two minutes.
        self.verify_timeout = 240
        self.verify_interval = 10
        self.update_batch_size = 5
        # A stalled OTA is often transient, so retry once after a reboot.
        self.update_attempts = 2

    def debug_print(self, message):
        """Print debug message if debug mode is enabled."""
        if self.debug:
            print(f"DEBUG: {message}")
        
    def get_local_networks(self) -> List[str]:
        """Get the network ranges to scan.

        Explicitly configured ranges win: interface discovery only ever sees
        directly attached subnets, so devices on a routed subnet are invisible
        to it even when they are perfectly reachable.
        """
        if self.networks:
            for network in self.networks:
                print(f"Scanning configured network: {network}")
            return self.networks

        networks = []

        try:
            # Get all network interfaces
            interfaces = netifaces.interfaces()
            
            for interface in interfaces:
                # Skip loopback interfaces
                if interface.startswith('lo'):
                    continue
                    
                addrs = netifaces.ifaddresses(interface)
                
                # Check IPv4 addresses
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        ip = addr_info.get('addr')
                        netmask = addr_info.get('netmask')
                        
                        if ip and netmask and not ip.startswith('127.'):
                            try:
                                # Create network from IP and netmask
                                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                                if str(network) in networks:
                                    continue  # several interfaces can share a subnet
                                networks.append(str(network))
                                print(f"Found network: {network}")
                            except ValueError:
                                continue
                                
        except Exception as e:
            print(f"Error getting network interfaces: {e}")
            # Fallback to common private networks
            networks = ['192.168.1.0/24', '192.168.0.0/24', '10.0.0.0/24']
            print("Using fallback networks:", networks)
            
        return networks
    
    async def check_shelly_device(self, session: aiohttp.ClientSession, ip: str) -> Optional[Dict]:
        """Check if the given IP hosts a Shelly device and return device info."""
        try:
            url = f"http://{ip}/shelly"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                if response.status == 200:
                    # content_type=None: judge the payload, not the declared mimetype,
                    # so a device serving JSON as text/html is still recognised.
                    data = await response.json(content_type=None)
                    if not isinstance(data, dict):
                        return None

                    # Debug: Print raw response for first few devices
                    self.debug_print(f"Raw /shelly response from {ip}: {data}")
                    
                    # Verify it's a Shelly device - check for common Shelly fields
                    shelly_indicators = ['type', 'name', 'mac', 'id', 'model', 'gen', 'fw_id', 'ver']
                    if any(field in data for field in shelly_indicators):
                        # Extract device type from various possible fields
                        device_type = (data.get('type') or 
                                     data.get('model') or 
                                     data.get('id', '').split('-')[0] if data.get('id') else 'Unknown')
                        
                        # Extract firmware version from various possible fields  
                        firmware = (data.get('fw') or 
                                  data.get('fw_id') or
                                  data.get('ver') or
                                  'Unknown')
                        
                        # Extract device name
                        device_name = (data.get('name') or 
                                     data.get('id') or
                                     f"Shelly-{ip}")
                        
                        device_info = {
                            'ip': ip,
                            'type': device_type,
                            'name': device_name,
                            'mac': data.get('mac', 'Unknown'),
                            'fw': firmware,
                            'ver': data.get('ver', firmware),  # Store both fw and ver for compatibility
                            'discoverable': data.get('discoverable', True),
                            'auth': data.get('auth', False),
                            'gen': data.get('gen', 1),  # Default to Gen1 if not specified
                            'slot': data.get('slot'),  # active flash slot (Gen2+)
                            'device_data': data
                        }
                        
                        print(f"Found Shelly device: {device_info['name']} ({device_info['type']}) at {ip} [Gen{device_info['gen']}]")
                        return device_info
                        
        except asyncio.TimeoutError:
            pass  # Timeout is expected for non-Shelly devices
        except Exception as e:
            # Enable debugging for connection issues
            self.debug_print(f"Error checking {ip}: {e}")
            pass
            
        return None
    
    async def scan_network_range(self, network_range: str) -> List[Dict]:
        """Scan a network range for Shelly devices."""
        print(f"Scanning network range: {network_range}")
        
        try:
            network = ipaddress.IPv4Network(network_range)
        except ValueError as e:
            print(f"Invalid network range {network_range}: {e}")
            return []
        
        # Create semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(self.concurrent_limit)
        
        async def scan_ip_with_semaphore(session: aiohttp.ClientSession, ip: str):
            async with semaphore:
                return await self.check_shelly_device(session, ip)
        
        # Create connector with increased limits
        connector = aiohttp.TCPConnector(limit=100, limit_per_host=20)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            # Create tasks for all IPs in the network
            tasks = []
            for ip in network.hosts():
                if network.num_addresses > 1000:  # Skip large networks to avoid overwhelming
                    print(f"Network {network_range} too large ({network.num_addresses} hosts), skipping...")
                    break
                    
                tasks.append(scan_ip_with_semaphore(session, str(ip)))
            
            if not tasks:
                return []
                
            print(f"Checking {len(tasks)} IP addresses...")
            
            # Execute all tasks and collect results
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out None results and exceptions
            devices = []
            for result in results:
                if result is not None and not isinstance(result, Exception):
                    devices.append(result)
                    
        return devices
    
    async def discover_devices(self) -> List[Dict]:
        """Discover all Shelly devices on local networks."""
        print("Starting Shelly device discovery...")
        
        networks = self.get_local_networks()
        if not networks:
            print("No networks found!")
            return []
        
        all_devices = []
        
        # Scan each network
        for network in networks:
            devices = await self.scan_network_range(network)
            all_devices.extend(devices)
        
        self.devices = all_devices
        print(f"\nDiscovery complete! Found {len(all_devices)} Shelly device(s)")
        
        return all_devices
    
    async def get_device_status(self, session: aiohttp.ClientSession, device: Dict) -> Optional[Dict]:
        """Get detailed status information for a device."""
        try:
            url = f"http://{device['ip']}/status"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                if response.status == 200:
                    return await response.json()
        except Exception as e:
            print(f"Error getting status for {device['name']}: {e}")
        return None
    
    async def check_for_updates(self, session: aiohttp.ClientSession, device: Dict) -> Optional[Dict]:
        """Check for firmware updates for a device."""
        device_ip = device['ip']
        device_name = device['name']
        generation = device.get('gen', 1)
        
        # Try Gen2+ devices first (newer API) if it's Gen2 or Gen3
        if generation >= 2:
            try:
                url = f"http://{device_ip}/rpc"
                async with session.post(url, json={"id": 1, "method": "Shelly.CheckForUpdate"},
                                      timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                    if response.status == 200:
                        data = await response.json(content_type=None)
                        self.debug_print(f"Gen2+ update response for {device_name}: {data}")
                        if 'result' in data:
                            return {'format': 'gen2', 'data': data['result']}
                        elif isinstance(data, dict):  # Direct response or empty dict
                            # Empty dict {} means no updates available for Gen2+ devices
                            return {'format': 'gen2', 'data': data}
            except Exception as gen2_error:
                self.debug_print(f"Gen2+ update check failed for {device_name}: {gen2_error}")
                        
        # Try Gen1 devices (older API) - only as fallback if Gen2+ completely failed
        # For Gen2+ devices, if we got ANY response above (including empty {}), don't try Gen1
        if generation < 2:  # Only try Gen1 API for actual Gen1 devices
            try:
                url = f"http://{device_ip}/ota/check"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                    if response.status == 200:
                        data = await response.json()
                        self.debug_print(f"Gen1 update response for {device_name}: {data}")
                        return {'format': 'gen1', 'data': data}
                    else:
                        self.debug_print(f"Gen1 update check returned status {response.status} for {device_name}")
            except Exception as gen1_error:
                self.debug_print(f"Gen1 update check failed for {device_name}: {gen1_error}")
                    
        # Try alternative endpoints only if we haven't gotten any response yet
        alternatives = ['/rpc/Shelly.GetStatus', '/status']
        for alt_endpoint in alternatives:
            try:
                url = f"http://{device_ip}{alt_endpoint}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                    if response.status == 200:
                        data = await response.json()
                        # Check if this endpoint provides update info
                        if any(key in data for key in ['update', 'fw_update', 'ota']):
                            self.debug_print(f"Alternative endpoint {alt_endpoint} response for {device_name}: {data}")
                            return {'format': 'alternative', 'data': data}
            except Exception:
                continue
                    
        return None
    
    async def get_device_details(self) -> None:
        """Get detailed information and update status for all discovered devices."""
        if not self.devices:
            print("No devices to check. Run discovery first.")
            return
        
        print(f"\nGetting detailed information for {len(self.devices)} device(s)...")
        
        connector = aiohttp.TCPConnector(limit=20)
        async with aiohttp.ClientSession(connector=connector) as session:
            for device in self.devices:
                print(f"\n--- {device['name']} ({device['ip']}) ---")
                
                # Get device status
                status = await self.get_device_status(session, device)
                if status:
                    device['status'] = status
                    
                    # Extract useful status information
                    if 'wifi_sta' in status:
                        wifi_info = status['wifi_sta']
                        print(f"WiFi: {wifi_info.get('ssid', 'Unknown')} (RSSI: {wifi_info.get('rssi', 'Unknown')})")
                    
                    if 'uptime' in status:
                        uptime_seconds = status['uptime']
                        uptime_hours = uptime_seconds // 3600
                        print(f"Uptime: {uptime_hours} hours")
                
                # Check for updates
                update_info = await self.check_for_updates(session, device)
                if update_info:
                    device['update_info'] = update_info
                    
                    # Process update information based on format
                    has_update = False
                    update_format = update_info.get('format', 'unknown')
                    update_data = update_info.get('data', {})
                    
                    if update_format == 'gen2':
                        # Gen2+ format - check both stable and beta versions
                        stable_info = update_data.get('stable')
                        beta_info = update_data.get('beta') if self.include_beta else None
                        
                        self.debug_print(f"Stable info: {stable_info}, Beta info: {beta_info}, Include beta: {self.include_beta}")
                        
                        # Determine which version to use (prefer beta if enabled and available)
                        selected_version = None
                        version_type = "stable"
                        
                        if beta_info and beta_info.get('version'):
                            selected_version = beta_info.get('version')
                            version_type = "beta"
                        elif stable_info and stable_info.get('version'):
                            selected_version = stable_info.get('version')
                            version_type = "stable"
                        
                        if selected_version:
                            current_version = device.get('ver', device.get('fw', 'Unknown'))
                            
                            # Extract version numbers for comparison
                            if current_version != 'Unknown':
                                # Compare versions - if they're different, there might be an update
                                if selected_version != current_version:
                                    has_update = True
                                    version_label = f"{selected_version} ({version_type})" if version_type == "beta" else selected_version
                                    print(f"🔄 UPDATE AVAILABLE: {version_label} (current: {current_version})")
                                    # Store update information for later use
                                    device['available_version'] = selected_version
                                    device['available_version_type'] = version_type
                                else:
                                    print(f"✅ Up to date: {current_version}")
                            else:
                                print(f"✅ Up to date: {current_version}")
                        else:
                            # Empty response or no version info means up to date
                            print(f"✅ Up to date: {device.get('ver', device.get('fw', 'Unknown'))}")
                            
                    elif update_format == 'gen1':
                        # Gen1 format
                        if 'has_update' in update_data:
                            has_update = update_data.get('has_update', False)
                            if has_update:
                                new_version = update_data.get('new_version', 'Unknown')
                                current_version = device.get('ver', device.get('fw', 'Unknown'))
                                device['available_version'] = new_version
                                print(f"🔄 UPDATE AVAILABLE: {new_version} (current: {current_version})")
                            else:
                                print(f"✅ Up to date: {device.get('ver', device.get('fw', 'Unknown'))}")
                        elif 'status' in update_data:
                            # Some Gen1 devices use 'status' field
                            status = update_data.get('status', '')
                            if status == 'pending' or 'update' in status.lower():
                                has_update = True
                                new_version = update_data.get('new_version', update_data.get('version', 'Unknown'))
                                device['available_version'] = new_version
                                print(f"🔄 UPDATE AVAILABLE: {new_version} (current: {device.get('ver', device.get('fw', 'Unknown'))})")
                            else:
                                print(f"✅ Up to date: {device.get('ver', device.get('fw', 'Unknown'))}")
                        else:
                            # Check other possible indicators
                            version_fields = ['new_version', 'latest_version', 'version']
                            found_update = False
                            for field in version_fields:
                                if field in update_data:
                                    new_version = update_data[field]
                                    current_version = device.get('ver', device.get('fw', 'Unknown'))
                                    if new_version != current_version:
                                        has_update = True
                                        device['available_version'] = new_version
                                        print(f"🔄 UPDATE AVAILABLE: {new_version} (current: {current_version})")
                                        found_update = True
                                        break
                            if not found_update:
                                print(f"✅ Up to date: {device.get('ver', device.get('fw', 'Unknown'))}")
                                
                    elif update_format == 'alternative':
                        # Alternative endpoint format
                        update_fields = ['update', 'fw_update', 'ota']
                        for field in update_fields:
                            if field in update_data:
                                update_section = update_data[field]
                                if isinstance(update_section, dict):
                                    if update_section.get('has_update') or update_section.get('available'):
                                        has_update = True
                                        new_version = update_section.get('new_version', update_section.get('version', 'Unknown'))
                                        device['available_version'] = new_version
                                        print(f"🔄 UPDATE AVAILABLE: {new_version} (current: {device.get('ver', device.get('fw', 'Unknown'))})")
                                        break
                        if not has_update:
                            print(f"✅ Up to date: {device.get('ver', device.get('fw', 'Unknown'))}")
                    else:
                        print(f"❓ Unknown update response format: {update_format}")
                        
                    device['has_update'] = has_update
                else:
                    print("❌ Could not check for updates")
                    device['has_update'] = False
    
    @staticmethod
    def _rpc_error(data) -> Optional[Tuple[int, str]]:
        """Extract (code, message) from an RPC error, or None if there is no error.

        Errors come back in two shapes depending on the endpoint used:
        POST /rpc nests them under 'error', POST /rpc/<Method> returns them flat.
        """
        if not isinstance(data, dict):
            return None
        error = data.get('error') if isinstance(data.get('error'), dict) else None
        if error is None and 'code' in data and 'message' in data:
            error = data
        if error is None:
            return None
        return error.get('code'), str(error.get('message', 'Unknown error'))

    async def install_update(self, session: aiohttp.ClientSession, device: Dict) -> Dict:
        """Ask a device to start installing a firmware update.

        Returns {'accepted': bool, 'reason': str}. Note that 'accepted' only means
        the device took the request - it does NOT mean the firmware was installed.
        A Shelly answers HTTP 200 with a null result the moment the OTA starts, and
        an OTA that later fails is never reported back over the API, so the caller
        must confirm the outcome with verify_update().
        """
        device_ip = device['ip']
        device_name = device['name']
        generation = device.get('gen', 1)

        try:
            if generation >= 2:
                # The JSON-RPC envelope has to go to /rpc. Posting it to
                # /rpc/Shelly.Update makes the device read the whole envelope as the
                # params object, so 'stage' would be dropped and it would always
                # fall back to stable.
                url = f"http://{device_ip}/rpc"

                # Use the channel the update was actually detected on, so that
                # --include-beta does not request a beta build on a device that only
                # has a stable one on offer.
                stage = device.get('available_version_type') or ("beta" if self.include_beta else "stable")
                payload = {"id": 1, "method": "Shelly.Update", "params": {"stage": stage}}

                self.debug_print(f"Installing {stage} update for {device_name}")

                async with session.post(url, json=payload,
                                      timeout=aiohttp.ClientTimeout(total=30)) as response:
                    try:
                        data = await response.json(content_type=None)
                    except Exception as json_error:
                        self.debug_print(f"JSON parsing error for {device_name}: {json_error}")
                        return {'accepted': False,
                                'reason': f'unreadable response (HTTP {response.status})'}

                    self.debug_print(f"Gen2+ update install response for {device_name}: {data}")

                    error = self._rpc_error(data)
                    if error:
                        code, message = error
                        if code == -106 and 'already in progress' in message.lower():
                            # An OTA is running. That is not a success by itself -
                            # it is also what a device stuck in a failed OTA says.
                            return {'accepted': True, 'reason': 'update already in progress'}
                        if code == -114 and 'no update info' in message.lower():
                            return {'accepted': False,
                                    'reason': 'no update info available on the device'}
                        return {'accepted': False, 'reason': f'{message} (code {code})'}

                    if response.status != 200:
                        return {'accepted': False, 'reason': f'HTTP {response.status}'}

                    return {'accepted': True, 'reason': 'OTA started'}
            else:
                # Gen1 update installation
                url = f"http://{device_ip}/ota?update=true"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                    if response.status == 200:
                        data = await response.json(content_type=None)
                        self.debug_print(f"Gen1 update install response for {device_name}: {data}")
                        return {'accepted': True, 'reason': 'OTA started'}
                    return {'accepted': False, 'reason': f'HTTP {response.status}'}

        except Exception as e:
            return {'accepted': False, 'reason': f'{type(e).__name__}: {e}'}

    async def reboot_device(self, session: aiohttp.ClientSession, device: Dict) -> bool:
        """Reboot a Gen2+ device and wait for it to answer again."""
        if device.get('gen', 1) < 2:
            return False
        try:
            async with session.post(f"http://{device['ip']}/rpc",
                                    json={"id": 1, "method": "Shelly.Reboot"},
                                    timeout=aiohttp.ClientTimeout(total=15)) as response:
                await response.read()
        except Exception as e:
            self.debug_print(f"Reboot request failed for {device['name']}: {e}")
            return False

        for _ in range(12):
            await asyncio.sleep(5)
            try:
                async with session.get(f"http://{device['ip']}/shelly",
                                       timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                    await response.json(content_type=None)
                return True
            except Exception:
                continue
        return False

    async def verify_update(self, session: aiohttp.ClientSession, device: Dict,
                            target_version: str) -> Tuple[bool, str]:
        """Poll a device until it actually runs target_version.

        A successful OTA reboots the device, so it normally disappears for a while
        and comes back on the new version. A device that answers the whole time on
        the old version has silently aborted the update.
        """
        deadline = time.time() + self.verify_timeout
        observed = device.get('ver', 'Unknown')
        went_away = False

        while time.time() < deadline:
            await asyncio.sleep(self.verify_interval)
            try:
                url = f"http://{device['ip']}/shelly"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                    data = await response.json(content_type=None)
                observed = data.get('ver', observed)
                device['slot'] = data.get('slot', device.get('slot'))
                if observed == target_version:
                    return True, observed
            except Exception:
                # Unreachable is expected while it reboots into the new firmware.
                went_away = True
                self.debug_print(f"{device['name']} unreachable while updating (rebooting?)")

        if went_away:
            return False, f"{observed} (rebooted but did not reach {target_version})"
        return False, observed


    async def bulk_update_devices(self) -> Dict:
        """Install updates on all devices that have updates available.

        Returns counts of what really happened, so a caller (cron) can tell a clean
        run from one where devices were left behind.
        """
        devices_with_updates = [d for d in self.devices if d.get('has_update', False)]

        if not devices_with_updates:
            print("\n✅ No devices need updates!")
            return {'updated': 0, 'stalled': 0, 'rejected': 0}


        print(f"\n🔄 Installing updates on {len(devices_with_updates)} device(s)...")
        print("⚠️  This process may take several minutes as devices will reboot during updates.\n")
        
        connector = aiohttp.TCPConnector(limit=self.update_batch_size * 4)
        updated, stalled, rejected = [], [], []

        async def update_one(index: int, device: Dict) -> None:
            device_name = device['name']
            current_version = device.get('ver', device.get('fw', 'Unknown'))
            target_version = device.get('available_version', 'Unknown')

            print(f"[{index}/{len(devices_with_updates)}] Updating {device_name} "
                  f"({current_version} → {target_version})...")

            observed = current_version
            for attempt in range(1, self.update_attempts + 1):
                result = await self.install_update(session, device)
                if not result['accepted']:
                    print(f"❌ {device_name}: update refused - {result['reason']}")
                    rejected.append((device_name, device, result['reason']))
                    return

                ok, observed = await self.verify_update(session, device, target_version)
                if ok:
                    print(f"✅ {device_name}: now running {observed}")
                    device['ver'] = observed
                    device['has_update'] = False
                    updated.append(device_name)
                    return

                print(f"❌ {device_name}: still on {observed} after {self.verify_timeout}s "
                      f"(attempt {attempt}/{self.update_attempts}) - the device accepted the "
                      f"OTA but did not install it")
                if attempt < self.update_attempts:
                    # A half-finished OTA can leave the device holding memory it never
                    # frees, so give it a clean start before trying again.
                    print(f"   ↻ rebooting {device_name} and retrying...")
                    await self.reboot_device(session, device)

            stalled.append((device_name, device, observed))

        async with aiohttp.ClientSession(connector=connector) as session:
            # Update in batches: each device is verified before its slot in the batch
            # is reused, so the summary reflects what really happened rather than
            # what was merely requested.
            for start in range(0, len(devices_with_updates), self.update_batch_size):
                batch = devices_with_updates[start:start + self.update_batch_size]
                await asyncio.gather(*(update_one(start + n + 1, device)
                                       for n, device in enumerate(batch)))

        print(f"\n📊 Bulk update summary:")
        print(f"   ✅ {len(updated)} device(s) verified on the new firmware")
        print(f"   ❌ {len(stalled)} device(s) accepted the update but never installed it")
        print(f"   ❌ {len(rejected)} device(s) refused the update request")

        if rejected:
            print(f"\n❌ Update request refused:")
            for device_name, _device, reason in rejected:
                print(f"   • {device_name}: {reason}")

        if stalled:
            print(f"\n❌ Update accepted but not installed:")
            for device_name, device, observed in stalled:
                print(f"   • {device_name} ({device['ip']}) still on {observed} "
                      f"after {self.update_attempts} attempt(s)")

            print(f"\n   These devices take the OTA request, download the firmware and then")
            print(f"   abort without rebooting. The device reports nothing about the failure,")
            print(f"   which is why an unverified run looks like it succeeded.")
            print(f"   Try again later - the download can also fail transiently - and if a")
            print(f"   device keeps refusing, flash it locally via its web UI")
            print(f"   (Settings → Firmware → upload) or replace it.")

        if updated:
            print(f"\n⏳ {len(updated)} device(s) rebooted onto the new firmware.")

        return {'updated': len(updated), 'stalled': len(stalled), 'rejected': len(rejected)}

    async def prompt_for_bulk_update(self) -> bool:
        """Prompt user for bulk update confirmation."""
        devices_with_updates = [d for d in self.devices if d.get('has_update', False)]

        if not devices_with_updates:
            return False

        # Without a terminal there is nobody to answer, and silently doing nothing
        # is how an unattended run pretends to work. Say so instead.
        if not self.auto_update and not sys.stdin.isatty():
            print(f"\n⚠️  {len(devices_with_updates)} device(s) need updates, but there is no "
                  f"terminal to confirm on.")
            print("   Pass --auto-update to install them unattended (e.g. from cron).")
            return False


        # Auto-update mode - skip prompt
        if self.auto_update:
            print(f"\n🔄 Auto-update mode enabled - installing updates on {len(devices_with_updates)} device(s)...")
            return True
            
        print(f"\n{'='*60}")
        print(f"BULK UPDATE AVAILABLE")
        print(f"{'='*60}")
        print(f"Found {len(devices_with_updates)} device(s) with available updates:")
        
        for device in devices_with_updates:
            current_version = device.get('ver', device.get('fw', 'Unknown'))
            update_info = device.get('update_info', {})
            update_data = update_info.get('data', {})
            
            new_version = device.get('available_version') or update_data.get('new_version', 'Unknown')

            print(f"  • {device['name']} ({device['type']})")
            print(f"    Current: v{current_version} → Available: v{new_version}")
        
        print(f"\n⚠️  Important notes:")
        print(f"   • Devices will reboot during the update process")
        print(f"   • Updates typically take 2-5 minutes per device")
        print(f"   • Do not power off devices during the update")
        print(f"   • Network connectivity is required throughout the process")
        
        while True:
            try:
                choice = input(f"\nDo you want to install updates on all {len(devices_with_updates)} device(s)? [y/N]: ").strip().lower()
                if choice in ['y', 'yes']:
                    return True
                elif choice in ['n', 'no', '']:
                    return False
                else:
                    print("Please enter 'y' for yes or 'n' for no.")
            except KeyboardInterrupt:
                print("\n\nOperation cancelled by user.")
                return False
            except EOFError:
                print("\nInput cancelled.")
                return False
    
    def print_summary(self) -> None:
        """Print a summary of discovered devices."""
        if not self.devices:
            print("\nNo Shelly devices found.")
            return
            
        print(f"\n{'='*60}")
        print(f"SHELLY DEVICE SUMMARY ({len(self.devices)} device(s) found)")
        print(f"{'='*60}")
        
        devices_with_updates = [d for d in self.devices if d.get('has_update', False)]
        
        for i, device in enumerate(self.devices, 1):
            update_status = "🔄 UPDATE AVAILABLE" if device.get('has_update', False) else "✅ Up to date"
            
            # Show available version and type if an update is available
            if device.get('has_update', False) and device.get('available_version'):
                available_version = device['available_version']
                version_type = device.get('available_version_type', 'stable')
                if version_type == 'beta':
                    update_status = f"🔄 UPDATE AVAILABLE: {available_version} (beta)"
                else:
                    update_status = f"🔄 UPDATE AVAILABLE: {available_version}"
            
            print(f"{i}. {device['name']}")
            print(f"   Type: {device['type']}")
            print(f"   IP: {device['ip']}")
            print(f"   MAC: {device['mac']}")
            print(f"   Firmware: {device.get('ver', device.get('fw', 'Unknown'))}")
            print(f"   Status: {update_status}")
            print()
        
        if devices_with_updates:
            print(f"🔔 {len(devices_with_updates)} device(s) have updates available!")
            if self.include_beta:
                print("   (Including beta/development versions)")
        else:
            print("✅ All devices are up to date!")
            if self.include_beta:
                print("   (Checked both stable and beta versions)")
    
    async def run(self) -> int:
        """Run the complete device discovery and update check process.

        Returns a process exit code: 0 when there is nothing left to do, 1 when
        devices were left un-updated, 2 when no devices were found at all. This is
        what makes an unattended run monitorable - cron only notices failures if
        they show up in the exit status.
        """
        print("Shelly Device Manager")
        print("====================")

        start_time = time.time()

        # Discover devices
        await self.discover_devices()

        if not self.devices:
            print("\n❌ No Shelly devices found on the network.")
            print("\nTroubleshooting:")
            print("1. Make sure Shelly devices are connected to the same network")
            print("2. Check that devices are powered on and connected to WiFi")
            print("3. Verify devices are not in AP mode")
            print("4. If the devices are on a routed subnet this host is not part of,")
            print("   name it explicitly: -n 10.10.2.0/24")
            return 2


        # Get detailed information and check for updates
        await self.get_device_details()
        
        # Print summary
        self.print_summary()
        
        # Prompt for bulk update if updates are available
        outcome = None
        if await self.prompt_for_bulk_update():
            outcome = await self.bulk_update_devices()

        elapsed_time = time.time() - start_time
        print(f"\n⏱️  Scan completed in {elapsed_time:.1f} seconds")

        if outcome is not None:
            return 1 if (outcome['stalled'] or outcome['rejected']) else 0
        # Nothing was installed: that is only fine if nothing needed installing.
        return 1 if any(d.get('has_update') for d in self.devices) else 0


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Shelly Device Manager - Network Scanner and Update Checker')
    parser.add_argument('-d', '--debug', action='store_true', 
                       help='Enable debug output to troubleshoot device discovery and update checking')
    parser.add_argument('-t', '--timeout', type=float, default=5.0,
                       help='HTTP request timeout in seconds (default: 5.0)')
    parser.add_argument('--auto-update', action='store_true',
                       help='Install updates without asking. This is the flag to use for '
                            'unattended runs such as cron; without it a run with no terminal '
                            'only reports what it would have done')
    parser.add_argument('--include-beta', action='store_true',
                       help='Include beta/development versions when checking for updates')
    parser.add_argument('-n', '--network', action='append', metavar='CIDR',
                       help='Network range to scan, e.g. 10.10.2.0/24. May be repeated. '
                            'Required when the devices are on a routed subnet this host '
                            'is not part of, since interface discovery cannot see those.')
    parser.add_argument('--verify-timeout', type=int, default=240,
                       help='Seconds to wait for a device to come back on the new '
                            'firmware before calling the update failed (default: 240)')

    args = parser.parse_args()

    try:
        manager = ShellyDeviceManager(debug=args.debug, auto_update=args.auto_update,
                                      include_beta=args.include_beta, networks=args.network)
        manager.timeout = args.timeout
        manager.verify_timeout = args.verify_timeout

        if args.debug:
            print("🐛 Debug mode enabled - showing detailed API responses")
        if args.auto_update:
            print("🤖 Auto-update mode enabled - updates will be installed automatically")
        if args.include_beta:
            print("🧪 Beta mode enabled - including beta/development versions")
            
        sys.exit(await manager.run())
    except KeyboardInterrupt:
        print("\n\n❌ Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ An error occurred: {e}")
        if args.debug:
            import traceback
            print("Full traceback:")
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    print("Starting Shelly Device Manager...")
    asyncio.run(main())