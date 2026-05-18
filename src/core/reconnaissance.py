# Minimal Netra class for testing
class Netra:
    def run_reconnaissance(self, domain):
        return {
            'subdomains': [f'www.{domain}', f'api.{domain}', f'mail.{domain}'],
            'emails': [f'contact@{domain}', f'info@{domain}'],
            'technology_fingerprint': {f'https://{domain}': {'server': 'nginx'}},
            'git_exposure': ['No exposures detected'],
            'shodan_data': {}
        }
