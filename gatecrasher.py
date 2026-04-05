import argparse
import requests
import concurrent.futures
import sys
from urllib.parse import urlparse
import threading

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    ENDC = '\033[0m'

class GateCrasherUltimate:
    def __init__(self, target, threads, filter_codes, max_results):
        parsed = urlparse(target)
        if not parsed.scheme: target = "http://" + target
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.path = parsed.path.rstrip('/')
        self.target_full = target.rstrip('/')
        self.threads = threads
        self.filter_codes = filter_codes
        self.max_results = max_results
        self.session = requests.Session()
        
        self.found_results = []
        self.seen_lengths = set()
        self.stop_event = threading.Event()
        
        print(f"{Colors.CYAN}[*] Target: {self.target_full}{Colors.ENDC}")
        self.base_len = self._get_baseline()
        self.seen_lengths.add(self.base_len)
        
        # Load all wordlists
        self.methods_list = self.load_payloads("methods.txt")
        self.headers_list = self.load_payloads("headers.txt")
        self.paths_list = self.load_payloads("paths.txt")

        # Fallback if methods.txt is empty
        if not self.methods_list:
            self.methods_list = ["GET", "POST", "PUT", "PATCH"]

    def _get_baseline(self):
        try:
            r = self.session.get(self.target_full, timeout=5, verify=False, allow_redirects=False)
            print(f"{Colors.CYAN}[*] Baseline length: {len(r.content)}{Colors.ENDC}")
            return len(r.content)
        except Exception as e:
            print(f"{Colors.RED}[!] Connection Error: {e}{Colors.ENDC}"); sys.exit(1)

    def load_payloads(self, filename):
        try:
            with open(f"payloads/{filename}", "r") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return []

    def analyze(self, r, tech, detail):
        if self.stop_event.is_set(): return
        if r is not None:
            res_len = len(r.content)
            if r.status_code in self.filter_codes: return
            
            # Filter 2: Unique Length check (The "Anti-Noise" filter)
            if res_len not in self.seen_lengths:
                self.seen_lengths.add(res_len)
                result = f"[{r.status_code}] Len: {res_len} | {tech}: {detail}"
                self.found_results.append(result)
                print(f"{Colors.GREEN}[V] Found ({len(self.found_results)}/{self.max_results}): {result}{Colors.ENDC}")

                # Filter 3: Kill Switch
                if len(self.found_results) >= self.max_results:
                    print(f"\n{Colors.YELLOW}[!] Limit reached. Stopping scan...{Colors.ENDC}")
                    self.stop_event.set()

    def generate_mutations(self):
        """Generates Structural, Encoding, and Host mutations"""
        mutes = [] # List of (path, header_dict, tech_name)
        parts = [p for p in self.path.split('/') if p]
        if not parts: return mutes
        
        last = parts[-1]
        prefix = "/".join(parts[:-1])
        full_prefix = f"/{prefix}/" if prefix else "/"

        # 1. Host Header Injection (localhost/127.0.0.1)
        mutes.append((self.path, {"Host": "localhost"}, "Host-Spoof"))
        mutes.append((self.path, {"Host": "127.0.0.1"}, "Host-Spoof"))

        # 2. Case Sensitivity
        mutes.append((f"{full_prefix}{last.upper()}", {}, "Case-Mutation"))
        mutes.append((f"{full_prefix}{last.capitalize()}", {}, "Case-Mutation"))
        
        # 3. Single & Double URL Encoding
        char_enc = f"%{ord(last[0]):02x}"
        mutes.append((f"{full_prefix}{char_enc}{last[1:]}", {}, "Encode-Mutation"))
        double_enc = f"%25{ord(last[0]):02x}"
        mutes.append((f"{full_prefix}{double_enc}{last[1:]}", {}, "Double-Encode"))
        
        # 4. Slashes & Dots
        mutes.append((f"//{self.path}", {}, "Double-Slash"))
        mutes.append((f"{self.path}/", {}, "Trailing-Slash"))
        mutes.append((f"{self.path}/.", {}, "Dot-Slash"))
        
        # 5. Parameter Pollution & Extensions
        mutes.append((f"{self.path}?id=1&id=2", {}, "Param-Pollution"))
        mutes.append((f"{self.path}.json", {}, "Extension-Fuzz"))
        
        return mutes

    def run_logic(self):
        print(f"{Colors.BOLD}--- Running Omni-Final Attack ---{Colors.ENDC}")
        omni_mutes = self.generate_mutations()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Iterate through methods from methods.txt
            for method in self.methods_list:
                if self.stop_event.is_set(): break
                
                # A. Test Auto-Generated Mutations
                for path_mut, head_mut, tech in omni_mutes:
                    executor.submit(self.worker, method, path_mut, head_mut, tech)

                # B. Test paths.txt (v5 Anchored style)
                for p_suffix in self.paths_list:
                    executor.submit(self.worker, method, f"{self.path}{p_suffix}", {}, "Path-List")

                # C. Test headers.txt (Combined with current method)
                for h_str in self.headers_list:
                    if ":" in h_str:
                        name, val = h_str.split(":", 1)
                        executor.submit(self.worker, method, self.path, {name.strip(): val.strip()}, "Header-List")

    def worker(self, m, p, h_dict, tech):
        if self.stop_event.is_set(): return
        url = self.base_url + p
        try:
            # Merge Host spoofing with potential session headers
            r = self.session.request(m, url, headers=h_dict, timeout=5, verify=False, allow_redirects=False)
            detail = f"{m} {p}"
            if h_dict: detail += f" {h_dict}"
            self.analyze(r, tech, detail)
        except: pass

def main():
    parser = argparse.ArgumentParser(description="GateCrasher Omni-Final")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g. http://ip:5000/admin)")
    parser.add_argument("-t", "--threads", type=int, default=30, help="Number of concurrent threads")
    parser.add_argument("-fc", "--filter-codes", default="403,404", help="Status codes to ignore")
    parser.add_argument("-r", "--results", type=int, default=3, help="Max unique results before stopping")
    args = parser.parse_args()

    f_codes = [int(c.strip()) for c in args.filter_codes.split(",")]
    
    gc = GateCrasherUltimate(args.url, args.threads, f_codes, args.results)
    gc.run_logic()
    
    print(f"\n{Colors.BOLD}{Colors.CYAN}--- Final Successful Bypasses ---{Colors.ENDC}")
    for res in gc.found_results:
        print(res)

if __name__ == "__main__":
    # Disable SSL warnings for local lab testing
    requests.packages.urllib3.disable_warnings()
    main()
