
import os
import json
import requests
import logging
import datetime
from dateutil import parser
from dns_checker import DNSChecker
from gh_manager import GHManager

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

PSL_JSON_URL = "https://github.com/groundcat/psl-json/raw/refs/heads/main/public_suffix_list.extended.json"
STATE_FILE = "data/monitor_state.json"

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

def generate_body(entry):
    """
    Generates Markdown body for the issue.
    """
    reg = entry.get('registry_records', {})
    req = entry.get('requestor', {})
    
    # Flatten registry records for display
    reg_str = ""
    for k, v in reg.items():
        if isinstance(v, list):
             v = ", ".join([i.get('text', '') if isinstance(i, dict) else str(i) for i in v])
        reg_str += f"- **{k}**: {v}\n"

    body = f"""
## PSL Entry Details

**Section**: {entry.get('section')}
**PSL Entry String**: {entry.get('psl_entry_string')}
**PSL Domain**: {entry.get('psl_domain')}
**ICANN Normalized Domain**: {entry.get('icann_normalized_domain')}
**ICANN TLD**: {entry.get('icann_tld')}

### Requestor
- **Description**: {req.get('requestor_description')}
- **Contact Name**: {req.get('requestor_contact_name')}
- **Contact Email**: {req.get('requestor_contact_email')}

### Registry Records
{reg_str}
    """
    return body

def main():
    token = os.environ.get("GITHUB_TOKEN")
    repo_name = os.environ.get("GITHUB_REPOSITORY")
    
    if not token or not repo_name:
        logger.error("Missing environment variables GITHUB_TOKEN or GITHUB_REPOSITORY")
        exit(1)

    gh = GHManager(token, repo_name)
    dns_checker = DNSChecker()
    
    # Load previous state
    prev_state = load_state()
    is_first_run = not bool(prev_state)
    new_state = {}

    # Fetch PSL data
    logger.info("Fetching PSL JSON...")
    try:
        resp = requests.get(PSL_JSON_URL)
        resp.raise_for_status()
        psl_data = resp.json()
    except Exception as e:
        logger.error(f"Failed to fetch PSL JSON: {e}")
        return

    today = datetime.datetime.now(datetime.timezone.utc).date()
    # today_iso = today.isoformat()

    for entry in psl_data:
        psl_entry = entry.get('psl_entry_string')
        if not psl_entry: continue
        
        domain = entry.get('icann_normalized_domain')
        if not domain: continue # Should generally exist

        is_negation = entry.get('is_negation', False)
        section = entry.get('section', 'icann')
        
        body = generate_body(entry)
        section_tag = f"{section} section"
        
        # Helper to get previous state for this entry
        prev_entry_state = prev_state.get(psl_entry, {})

        # Prepare new state entry
        new_state[psl_entry] = {
            'dns_error': None,
            'psl_txt_exists': None,
            'is_hold': False,
            'is_expired': False
        }

        # -------------------
        # STATIC CHECKS
        # -------------------
        
        reg_records = entry.get('registry_records', {})
        
        # 1. Domain Expired
        # condition: expiration_date_iso8601 = today or within 5 days before today
        # 1. Domain Expired
        # condition: expiration_date_iso8601 = today or within 5 days before today.
        # Logic: If expired in window and NOT flagged as expired in previous run, create issue.
        # This prevents re-alerting on the same expiration event.
        
        exp_iso = reg_records.get('expiration_date_iso8601')
        is_expired_in_window = False
        if exp_iso:
            try:
                exp_date = parser.isoparse(exp_iso).date()
                days_diff = (today - exp_date).days
                if 0 <= days_diff <= 5:
                    is_expired_in_window = True
            except Exception as e:
                pass # logger.warning(f"Failed to parse expiration date for {psl_entry}: {e}")
        
        new_state[psl_entry]['is_expired'] = is_expired_in_window
        
        prev_is_expired = prev_entry_state.get('is_expired', False)
        
        if not is_first_run and is_expired_in_window and not prev_is_expired:
             gh.create_or_update_issue(psl_entry, body, "domain expired", [section_tag])
        # Only alert on the edge (False -> True) to avoid noise.

        # 2. Registry Hold
        # condition: "status" text contains "hold"
        statuses = reg_records.get('status', [])
        is_hold = False
        for s in statuses:
            txt = s.get('text', '').lower() if isinstance(s, dict) else ''
            if 'hold' in txt:
                is_hold = True
                break
        
        new_state[psl_entry]['is_hold'] = is_hold
        prev_is_hold = prev_entry_state.get('is_hold', False)
        
        if not is_first_run and is_hold and not prev_is_hold:
            gh.create_or_update_issue(psl_entry, body, "registry hold", [section_tag])

        # 3. New Registration
        # condition: creation_date_iso8601 = today
        # 3. New Registration
        # condition: creation_date_iso8601 = today
        create_iso = reg_records.get('creation_date_iso8601')
        if not is_first_run and create_iso:
            try:
                c_date = parser.isoparse(create_iso).date()
                if c_date == today:
                    gh.create_or_update_issue(psl_entry, body, "new registration", [section_tag])
            except Exception:
                pass

        # -------------------
        # DYNAMIC CHECKS (DNS)
        # -------------------

        # Only check if not negation
        if not is_negation:
            # Check DNS Error (NXDOMAIN/SERVFAIL)
            dns_status = dns_checker.check_dns_error(domain)
            new_state[psl_entry]['dns_error'] = dns_status
            
            prev_dns = prev_entry_state.get('dns_error')
            
            # Logic: NoError YESTERDAY -> Error TODAY => Flag
            if not is_first_run and prev_dns is None and dns_status in ["NXDOMAIN", "SERVFAIL"]:
                tag = "nxdomain error" if dns_status == "NXDOMAIN" else "servfail error"
                gh.create_or_update_issue(psl_entry, body, tag, [section_tag])
            
            # Logic: Error YESTERDAY -> NoError TODAY => Remove tag
            if prev_dns in ["NXDOMAIN", "SERVFAIL"] and dns_status is None:
                # Remove both potential error tags
                gh.remove_tag_and_check_close(psl_entry, "nxdomain error")
                gh.remove_tag_and_check_close(psl_entry, "servfail error")


            # Check _psl TXT
            # Only for 'private' section
            if section == 'private':
                has_txt = dns_checker.check_psl_txt(domain)
                new_state[psl_entry]['psl_txt_exists'] = has_txt
                
                prev_txt = prev_entry_state.get('psl_txt_exists')
                
                # Logic: Existed YESTERDAY (True) -> Missing TODAY (False) => Flag
                if not is_first_run and prev_txt is True and has_txt is False:
                    gh.create_or_update_issue(psl_entry, body, "_psl txt lost", [section_tag])
                
                # Logic: Missing YESTERDAY -> Exists TODAY => Remove tag
                if prev_txt is False and has_txt is True:
                     gh.remove_tag_and_check_close(psl_entry, "_psl txt lost")

    # Save State
    save_state(new_state)
    logger.info("Done.")

if __name__ == "__main__":
    main()
