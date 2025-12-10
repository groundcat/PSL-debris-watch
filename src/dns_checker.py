
import dns.resolver
import dns.exception
import logging

logger = logging.getLogger(__name__)

class DNSChecker:
    RESOLVERS = ['1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4']

    def __init__(self):
        pass

    def check_dns_error(self, domain):
        """
        Checks if the domain resolves on all resolvers.
        Returns "NXDOMAIN" or "SERVFAIL" only if ALL resolvers agree.
        Returns None if any resolver succeeds.
        """
        results = []
        for r_ip in self.RESOLVERS:
            res = dns.resolver.Resolver()
            res.nameservers = [r_ip]
            res.timeout = 2.0
            res.lifetime = 2.0
            
            try:
                # 'NS' record check is preferred for determining domain existence/delegation health.
                res.resolve(domain, 'NS')
                results.append("NOERROR")
            except dns.resolver.NXDOMAIN:
                results.append("NXDOMAIN")
            except dns.resolver.NoNameservers:
                results.append("SERVFAIL") 
            except dns.resolver.NoAnswer:
                results.append("NOERROR")
            except dns.exception.Timeout:
                results.append("TIMEOUT")
            except Exception:
                # Treat other unknown query failures as SERVFAIL-equivalent
                results.append("SERVFAIL")

        # Analyze results
        if all(r == "NXDOMAIN" for r in results):
            return "NXDOMAIN"
        
        if all(r == "SERVFAIL" for r in results):
            return "SERVFAIL"
            
        return None

    def check_psl_txt(self, domain):
        """
        Checks for _psl.{domain} TXT record.
        Returns False if ALL resolvers say it does not exist (NXDOMAIN or NoAnswer).
        Returns True if at least one finds it.
        """
        target = f"_psl.{domain}"
        found = False
        
        for r_ip in self.RESOLVERS:
            res = dns.resolver.Resolver()
            res.nameservers = [r_ip]
            res.timeout = 2.0
            res.lifetime = 2.0
            
            try:
                answers = res.resolve(target, 'TXT')
                if answers:
                    found = True
                    break
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except Exception:
                # Treat timeouts etc as non-existence/failure for that resolver
                continue
        
        return found
