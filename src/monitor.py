
import random
import os
import json
import requests
import logging
import datetime
from dateutil import parser
from concurrent.futures import ThreadPoolExecutor, as_completed
from checker_utils import WhoisChecker, check_dns_resolver, check_psl_txt_resolver
from gh_manager import GHManager

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

PSL_JSON_URL = "https://github.com/groundcat/psl-json/raw/refs/heads/main/public_suffix_list.extended.json"
STATE_FILE = "data/monitor_state.json"
WHOIS_API_URL_LIST = os.environ.get("WHOIS_API_URL_LIST", "").split(",")

# Clean up empty strings in API list
WHOIS_API_URL_LIST = [url.strip() for url in WHOIS_API_URL_LIST if url.strip()]

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            logger.error("Failed to load state file, starting fresh.")
            return {}
    return {}

def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)

def generate_body(domain_entry, whois_data):
    """
    Generates Markdown body for the issue.
    """
    psl_entry = domain_entry.get('psl_entry_string')
    section = domain_entry.get('section')
    icann_domain = domain_entry.get('icann_normalized_domain')
    
    req = domain_entry.get('requestor', {})
    
    # Format registry records from Whois Data
    reg_str = ""
    if whois_data:
        # We try to mimic the structure: key-value pairs
        # Common fields: reserved, registered, creationDate, expirationDate, status, nameServers
        fields = [
            'reserved', 'registered', 'registrar', 'creationDateISO8601', 
            'expirationDateISO8601', 'updatedDateISO8601', 'nameServers'
        ]
        
        # Helper to format status list
        w_data_inner = whois_data.get('data')
        if w_data_inner:
             statuses = w_data_inner.get('status', [])
             status_txts = [s.get('text', '') for s in statuses if isinstance(s, dict)]
             reg_str += f"- **status**: {', '.join(status_txts)}\n"

             for f in fields:
                val = w_data_inner.get(f)
                if val:
                    if isinstance(val, list):
                        val = ", ".join(str(v) for v in val)
                    reg_str += f"- **{f}**: {val}\n"
    else:
        reg_str = "No Whois Data Available."

    body = f"""
## PSL Entry Details

**Section**: {section}
**PSL Entry String**: {psl_entry}
**PSL Domain**: {domain_entry.get('psl_domain')}
**ICANN Normalized Domain**: {icann_domain}
**ICANN TLD**: {domain_entry.get('icann_tld')}

### Requestor
- **Description**: {req.get('requestor_description')}
- **Contact Name**: {req.get('requestor_contact_name')}
- **Contact Email**: {req.get('requestor_contact_email')}

### Registry Records (Live Whois)
{reg_str}
    """
    return body

def check_dns_concurrent(domains, resolver_ip):
    results = {}
    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_domain = {executor.submit(check_dns_resolver, d, resolver_ip): d for d in domains}
        for future in as_completed(future_to_domain):
            d = future_to_domain[future]
            try:
                results[d] = future.result()
            except Exception:
                results[d] = "SERVFAIL"
    return results

def check_txt_concurrent(domains, resolver_ip):
    results = {}
    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_domain = {executor.submit(check_psl_txt_resolver, d, resolver_ip): d for d in domains}
        for future in as_completed(future_to_domain):
            d = future_to_domain[future]
            results[d] = future.result()
    return results

def main():
    token = os.environ.get("GITHUB_TOKEN")
    repo_name = os.environ.get("GITHUB_REPOSITORY")
    
    if not token or not repo_name:
        logger.error("Missing environment variables GITHUB_TOKEN or GITHUB_REPOSITORY")
        # For safety in dev environment, maybe don't exit if just testing build, but in prod exit.
        if not os.environ.get("SAFE_MODE_DEV"):
             exit(1)

    gh = GHManager(token, repo_name)
    state = load_state()
    
    # 1. Fetch PSL Data to get the list of domains
    logger.info("Fetching PSL JSON...")
    try:
        resp = requests.get(PSL_JSON_URL)
        resp.raise_for_status()
        psl_data = resp.json()
    except Exception as e:
        logger.error(f"Failed to fetch PSL JSON: {e}")
        return

    # Map domains -> entry
    domain_map = {}
    for entry in psl_data:
        d = entry.get('icann_normalized_domain')
        if d:
            domain_map[d] = entry

    # Initialize state (and migrate/clean old data)
    clean_state = {}
    
    for domain, entry in domain_map.items():
        # Check if exists in loaded state and has new format
        if domain in state and 'whois' in state[domain]:
             clean_state[domain] = state[domain]
             # Update static fields just in case
             clean_state[domain]['psl_entry_string'] = entry.get('psl_entry_string')
             clean_state[domain]['section'] = entry.get('section', 'icann')
             clean_state[domain]['is_negation'] = entry.get('is_negation', False)
        else:
            # Initialize new entry
            clean_state[domain] = {
                'psl_entry_string': entry.get('psl_entry_string'),
                'section': entry.get('section', 'icann'),
                'is_negation': entry.get('is_negation', False),
                'whois': {
                    'expiration_date': None,
                    'creation_date': None,
                    'last_checked': None,
                    'consecutive_empty': 0,
                    'data': None # cache full data for generating body
                },
                'dns_history': [], # List of status strings
                'txt_history': [],  # List of bools
                'flags': {}
            }
            
    state = clean_state

    # 2. Whois Checks
    # Logic:
    # - If exp date <= 10 days -> Check
    # - If exp date > 10 days -> Skip
    # - If exp date empty:
    #    - If consec empty < 5 -> Check
    #    - If consec empty >= 5 -> Skip
    
    today = datetime.datetime.now(datetime.timezone.utc).date()
    domains_to_check_whois = []
    
    for domain, data in state.items():
        # Only check if active in PSL (exists in current map)
        if domain not in domain_map: continue
        
        w = data.get('whois', {})
        exp_iso = w.get('expiration_date')
        consec = w.get('consecutive_empty', 0)
        
        should_check = False
        
        if not w.get('last_checked'):
            should_check = True
        elif exp_iso:
            try:
                exp_date = parser.isoparse(exp_iso).date()
                days_diff = (exp_date - today).days
                if days_diff <= 10:
                    should_check = True
            except:
                should_check = True # Parse error, recheck
        else:
            # Empty expiration date
            if consec < 5:
                should_check = True
                
        if should_check:
            domains_to_check_whois.append(domain)

    logger.info(f"Checking Whois for {len(domains_to_check_whois)} domains...")
    
    # Shuffle for random ordering
    random.shuffle(domains_to_check_whois)

    whois_checker = WhoisChecker(WHOIS_API_URL_LIST)
    
    # Run Whois Concurrently
    if WHOIS_API_URL_LIST and domains_to_check_whois:
        with ThreadPoolExecutor(max_workers=min(20, len(domains_to_check_whois) or 1)) as executor:
            future_to_domain = {executor.submit(whois_checker.query_domain, d): d for d in domains_to_check_whois}
            
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                result = future.result()
                
                # Update State
                w_state = state[domain]['whois']
                w_state['last_checked'] = today.isoformat()
                
                if result: # Success
                    data_content = result.get('data') if result else {}
                    if data_content is None: data_content = {}
                    
                    w_state['data'] = data_content
                    w_state['expiration_date'] = data_content.get('expirationDateISO8601')
                    w_state['creation_date'] = data_content.get('creationDateISO8601')
                    
                    if w_state['expiration_date']:
                        w_state['consecutive_empty'] = 0
                    else:
                        w_state['consecutive_empty'] += 1
                else:
                    # Failed to fetch (timeout or error)
                    w_state['consecutive_empty'] += 1

    # 3. DNS Checks
    # Run against R1 and R2 for ALL domains (filtered by negation?)
    domains_to_check_dns = [d for d in state if d in domain_map and not state[d].get('is_negation')]
    
    if domains_to_check_dns:
        logger.info(f"Checking DNS for {len(domains_to_check_dns)} domains...")
        
        # DNS Run 1 (1.1.1.1)
        r1_results = check_dns_concurrent(domains_to_check_dns, '1.1.1.1')
        # DNS Run 2 (8.8.8.8)
        r2_results = check_dns_concurrent(domains_to_check_dns, '8.8.8.8')
        
        # TXT Checks (only for private section)
        private_domains = [d for d in domains_to_check_dns if state[d].get('section') == 'private']
        txt_r1_results = check_txt_concurrent(private_domains, '1.1.1.1')
        txt_r2_results = check_txt_concurrent(private_domains, '8.8.8.8')
        
        # Process Results
        for domain in domains_to_check_dns:
            res1 = r1_results.get(domain, "SERVFAIL")
            res2 = r2_results.get(domain, "SERVFAIL")
            
            final_status = "OK"
            
            is_error_1 = res1 in ["NXDOMAIN", "SERVFAIL"]
            is_error_2 = res2 in ["NXDOMAIN", "SERVFAIL"]
            
            if is_error_1 and is_error_2:
                # Both failed. Prioritise NXDOMAIN
                if res1 == "NXDOMAIN" or res2 == "NXDOMAIN":
                    final_status = "NXDOMAIN"
                else:
                    final_status = "SERVFAIL"
            
            # Update History
            hist = state[domain]['dns_history']
            hist.append(final_status)
            if len(hist) > 5:
                hist = hist[-5:]
            state[domain]['dns_history'] = hist
            
            # Process TXT
            if domain in private_domains:
                t1 = txt_r1_results.get(domain, False)
                t2 = txt_r2_results.get(domain, False)
                
                # Logic: If both fail to find it, it's missing.
                # If at least one finds it -> Exists.
                exists = t1 or t2
                
                txt_hist = state[domain]['txt_history']
                txt_hist.append(exists)
                if len(txt_hist) > 5:
                    txt_hist = txt_hist[-5:]
                state[domain]['txt_history'] = txt_hist
                

    # 4. GitHub Issue Management
    logger.info("Managing GitHub Issues...")
    
    for domain, data in state.items():
        if domain not in domain_map: continue
        
        psl_entry = data['psl_entry_string']
        section_tag = f"{data['section']} section"
        entry_details = domain_map[domain]
        whois_cache = data['whois']
        
        # Generate Body
        body = generate_body(entry_details, whois_cache)
        
        # --- STATIC CHECKS ---
        
        # 1. Expiration
        # "expirationDateISO8601' is ... (<= 10 days) -> check whois" (Done above)
        # GitHub Logic: "expiration_date_iso8601 = today or within 5 days before today" -> Issue.
        exp_iso = whois_cache.get('expiration_date')
        if exp_iso:
            try:
                exp_date = parser.isoparse(exp_iso).date()
                days_diff = (exp_date - today).days
                
                days_since_expiry = (today - exp_date).days
                
                if -5 <= days_since_expiry <= 5:
                    flags = data.get('flags', {})
                    # Only alert if we have history (key exists) and it wasn't expired before
                    if 'expired' in flags:
                        was_expired = flags['expired']
                        if not was_expired:
                            gh.create_or_update_issue(psl_entry, body, "domain expired", [section_tag])
                    
                    flags['expired'] = True
                    data['flags'] = flags
                elif days_since_expiry < -5:
                     # Reset flag if domain is renewed/future expiry
                     data.setdefault('flags', {})['expired'] = False
            except:
                pass
                
        # 2. Registry Hold
        w_data = whois_cache.get('data')
        statuses = w_data.get('status', []) if w_data else []
        is_hold = False
        for s in statuses:
            txt = s.get('text', '').lower() if isinstance(s, dict) else ''
            if 'hold' in txt:
                is_hold = True
                break
        
        flags = data.get('flags', {})
        
        # Only alert if history exists
        if 'hold' in flags:
            was_hold = flags['hold']
            if is_hold and not was_hold:
                gh.create_or_update_issue(psl_entry, body, "registry hold", [section_tag])
            elif not is_hold and was_hold:
                 # Optional: close issue if hold removed?
                 gh.remove_tag_and_check_close(psl_entry, "registry hold")
            
        flags['hold'] = is_hold
        data['flags'] = flags

        # 3. New Registration
        # Only check on the day of "creation_date_iso8601 = today"
        crt_iso = whois_cache.get('creation_date')
        if crt_iso:
            try:
                c_date = parser.isoparse(crt_iso).date()
                if c_date == today:
                     gh.create_or_update_issue(psl_entry, body, "new registration", [section_tag])
            except:
                pass

        # --- DYNAMIC CHECKS (History Based) ---
        
        # DNS Errors
        # Last 5 entries are Errors.
        
        dns_hist = data.get('dns_history', [])
        
        if len(dns_hist) >= 5:
            last_5 = dns_hist[-5:]
            
            is_consistent_nx = all(x == "NXDOMAIN" for x in last_5)
            is_consistent_sf = all(x == "SERVFAIL" for x in last_5)
            
            flags = data.get('flags', {})
            current_dns_flag = flags.get('dns_error') # "NXDOMAIN", "SERVFAIL", or None
            
            if is_consistent_nx:
                if current_dns_flag != "NXDOMAIN":
                    gh.create_or_update_issue(psl_entry, body, "nxdomain error", [section_tag])
                    flags['dns_error'] = "NXDOMAIN"
            elif is_consistent_sf:
                if current_dns_flag != "SERVFAIL":
                    gh.create_or_update_issue(psl_entry, body, "servfail error", [section_tag])
                    flags['dns_error'] = "SERVFAIL"
            else:
                today_status = dns_hist[-1]
                if today_status == "OK" and current_dns_flag:
                    # Remove tags
                    if current_dns_flag == "NXDOMAIN":
                        gh.remove_tag_and_check_close(psl_entry, "nxdomain error")
                    elif current_dns_flag == "SERVFAIL":
                         gh.remove_tag_and_check_close(psl_entry, "servfail error")
                    flags['dns_error'] = None
            
            data['flags'] = flags

        # TXT Lost
        if data['section'] == 'private':
            txt_hist = data.get('txt_history', [])
            if len(txt_hist) >= 5:
                is_consistent_lost = all(x is False for x in txt_hist[-5:])
                
                flags = data.get('flags', {})
                was_lost = flags.get('txt_lost', False)
                
                if is_consistent_lost:
                    if not was_lost:
                        gh.create_or_update_issue(psl_entry, body, "_psl txt lost", [section_tag])
                        flags['txt_lost'] = True
                else:
                    if txt_hist[-1] is True and was_lost:
                        gh.remove_tag_and_check_close(psl_entry, "_psl txt lost")
                        flags['txt_lost'] = False
                data['flags'] = flags

    # Save State
    save_state(state)
    logger.info("Done.")

if __name__ == "__main__":
    main()
