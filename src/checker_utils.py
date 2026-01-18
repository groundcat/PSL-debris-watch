import requests
import dns.resolver
import dns.exception
import random
import threading
import concurrent.futures
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class WhoisChecker:
    def __init__(self, api_urls):
        self.api_urls = api_urls
        self.active_apis = api_urls.copy()
        self.api_lock = threading.Lock()

    def check_api(self, api_url, domain):
        """
        Query a WHOIS API for domain information.
        Returns: (success: bool, data: dict or None, error_msg: str or None)
        """
        try:
            params = {'domain': domain}
            # Add timeout to avoid hanging
            response = requests.get(api_url, params=params, timeout=15)

            # Check HTTP status
            if response.status_code != 200:
                return False, None, f"HTTP {response.status_code}"

            # Check JSON response
            data = response.json()
            msg = data.get('msg', '')

            # Treat "No WHOIS or RDAP server found" or "Query successful" as successful API response
            if msg == 'Query successful' or 'No WHOIS or RDAP server found' in msg:
                return True, data, None

            return False, None, f"Unexpected msg: {msg}"

        except requests.exceptions.Timeout:
            return False, None, "Request timeout"
        except requests.exceptions.RequestException as e:
            return False, None, f"Request error: {str(e)}"
        except Exception as e:
            return False, None, f"Error: {str(e)}"

    def query_domain(self, domain):
        """
        Query domain using available APIs with retry logic.
        Tries shuffled available APIs until success or all fail.
        Returns: dict with 'data' or None
        """
        with self.api_lock:
            if not self.active_apis:
                return None
            apis_to_try = self.active_apis.copy()

        random.shuffle(apis_to_try)

        for api_url in apis_to_try:
            success, data, error_msg = self.check_api(api_url, domain)

            if success:
                return data
            else:
                with self.api_lock:
                    if api_url in self.active_apis:
                        logger.warning(f"API {api_url} failed ({error_msg})")
                        # self.active_apis.remove(api_url) # Keep trying, be gentle

        return None

def check_dns_resolver(domain, resolver_ip):
    """
    Check DNS against a specific resolver.
    Returns: "NXDOMAIN", "SERVFAIL", "NOERROR", or "TIMEOUT/ERROR"
    """
    res = dns.resolver.Resolver()
    res.nameservers = [resolver_ip]
    res.timeout = 3.0
    res.lifetime = 3.0

    try:
        res.resolve(domain, 'A')
        return "NOERROR"
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN"
    except dns.resolver.NoNameservers:
        return "SERVFAIL"
    except dns.resolver.NoAnswer:
        # It resolved (no error), just no A record.
        return "NOERROR"
    except dns.exception.Timeout:
        return "TIMEOUT"
    except Exception:
        return "SERVFAIL" # Treat misc errors as servfail-ish

def check_psl_txt_resolver(domain, resolver_ip):
    """
    Checks for _psl.{domain} TXT record.
    Returns: True (found), False (not found or error)
    """
    target = f"_psl.{domain}"
    res = dns.resolver.Resolver()
    res.nameservers = [resolver_ip]
    res.timeout = 3.0
    res.lifetime = 3.0
    
    try:
        answers = res.resolve(target, 'TXT')
        if answers:
            return True
    except:
        pass
    return False

