class BankBrandProtection:
    """
    Protect against bank brand impersonation
    """
    
    def __init__(self, bank_config: Dict):
        self.bank_name = bank_config['name']
        self.official_domains = set(bank_config['official_domains'])
        self.brand_variations = self._generate_brand_variations()
        self.logo_detector = LogoDetectionModel()
        self.typosquatting_detector = TyposquattingDetector()
        
    def check_brand_impersonation(self, url: str, content: str = None) -> Dict:
        """
        Comprehensive brand impersonation detection
        """
        results = {
            'is_impersonation': False,
            'confidence': 0.0,
            'detected_methods': [],
            'similarity_scores': {}
        }
        
        # 1. Domain typosquatting check
        typosquatting_score = self.typosquatting_detector.analyze(url, self.official_domains)
        results['similarity_scores']['typosquatting'] = typosquatting_score
        
        if typosquatting_score > 0.8:
            results['is_impersonation'] = True
            results['confidence'] = max(results['confidence'], typosquatting_score)
            results['detected_methods'].append('typosquatting')
        
        # 2. Check for bank name in subdomains
        parsed_url = urllib.parse.urlparse(url)
        domain_parts = parsed_url.netloc.split('.')
        
        for part in domain_parts:
            for variation in self.brand_variations:
                if variation in part.lower() and parsed_url.netloc not in self.official_domains:
                    results['is_impersonation'] = True
                    results['confidence'] = max(results['confidence'], 0.9)
                    results['detected_methods'].append('brand_in_subdomain')
                    break
        
        # 3. Check for logo usage in content
        if content:
            logo_matches = self.logo_detector.detect_bank_logos(content, self.bank_name)
            if logo_matches['detected'] and not logo_matches['is_official']:
                results['is_impersonation'] = True
                results['confidence'] = max(results['confidence'], 0.95)
                results['detected_methods'].append('unauthorized_logo_usage')
        
        # 4. Check for official-looking but fake domains
        fake_domain_patterns = [
            f'{self.bank_name.lower()}-secure.com',
            f'secure-{self.bank_name.lower()}.com',
            f'{self.bank_name.lower()}-online.net',
            f'online-{self.bank_name.lower()}.org'
        ]
        
        for pattern in fake_domain_patterns:
            if pattern in parsed_url.netloc.lower():
                results['is_impersonation'] = True
                results['confidence'] = 1.0
                results['detected_methods'].append('fake_domain_pattern')
                break
        
        return results
    
    def _generate_brand_variations(self) -> List[str]:
        """Generate common brand variations for detection"""
        name_lower = self.bank_name.lower()
        
        variations = [
            name_lower,
            name_lower.replace(' ', ''),
            name_lower.replace(' ', '-'),
            name_lower.replace(' ', '_'),
            ''.join([c for c in name_lower if c.isalpha()]),  # Letters only
        ]
        
        # Common misspellings
        common_misspellings = {
            'bank': ['bnak', 'bakn'],
            'america': ['america', 'amerika'],
            'chase': ['chaze', 'chace'],
            'wells': ['wels', 'well'],
            'fargo': ['fargo', 'fagro']
        }
        
        # Add specific bank misspellings
        for word, misspellings in common_misspellings.items():
            if word in name_lower:
                for misspelling in misspellings:
                    variations.append(name_lower.replace(word, misspelling))
        
        return list(set(variations))