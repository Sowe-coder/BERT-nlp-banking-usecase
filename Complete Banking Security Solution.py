class BankingSecurityOrchestrator:
    """
    Complete banking phishing detection and prevention system
    """
    
    def __init__(self, bank_config: Dict):
        self.bank_config = bank_config
        
        # Initialize all components
        self.phishing_detector = BankingPhishingDetector(
            bank_name=bank_config['name'],
            strict_mode=True
        )
        
        self.brand_protection = BankBrandProtection(bank_config)
        
        self.transaction_protector = BankingTransactionProtector(
            customer_profile={},  # Will be set per customer
            risk_threshold=0.8
        )
        
        self.alert_system = BankingAlertSystem(bank_config)
        
        self.compliance_logger = ComplianceLogger(
            regulations=['GDPR', 'PCI-DSS', 'SOX', 'GLBA']
        )
        
        # Real-time threat feeds
        self.threat_feeds = [
            FinancialServicesInformationSharingAndAnalysisCenter(),
            AntiPhishingWorkingGroup(),
            FinancialThreatExchange()
        ]
        
    async def protect_customer_session(self, session_data: Dict) -> Dict:
        """
        Comprehensive protection for customer banking session
        """
        protection_result = {
            'session_id': session_data['session_id'],
            'customer_id': session_data['customer_id'],
            'timestamp': datetime.utcnow().isoformat(),
            'protection_layers': [],
            'risks_detected': [],
            'actions_taken': []
        }
        
        # Layer 1: Device and location verification
        device_check = await self._verify_device_and_location(session_data)
        protection_result['protection_layers'].append('device_verification')
        
        if device_check['risk_level'] > 0.7:
            protection_result['risks_detected'].append({
                'type': 'DEVICE_RISK',
                'severity': 'HIGH',
                'details': device_check
            })
            protection_result['actions_taken'].append('ENHANCED_VERIFICATION')
        
        # Layer 2: Behavioral analysis
        behavior_analysis = await self._analyze_behavior(session_data)
        protection_result['protection_layers'].append('behavioral_analysis')
        
        if behavior_analysis['anomalies_detected']:
            protection_result['risks_detected'].append({
                'type': 'BEHAVIORAL_ANOMALY',
                'severity': 'MEDIUM',
                'details': behavior_analysis
            })
        
        # Layer 3: Real-time phishing detection for any links clicked
        if 'clicked_urls' in session_data:
            for url in session_data['clicked_urls']:
                phishing_check = self.phishing_detector.detect_banking_phishing(url)
                protection_result['protection_layers'].append('phishing_detection')
                
                if phishing_check['risk_level'] in ['HIGH', 'CRITICAL']:
                    protection_result['risks_detected'].append({
                        'type': 'PHISHING_ATTEMPT',
                        'severity': phishing_check['risk_level'],
                        'url': url,
                        'details': phishing_check
                    })
                    
                    # Take immediate action
                    self.alert_system.notify_customer(
                        session_data['customer_id'],
                        'PHISHING_ALERT',
                        {'url': url, 'risk_level': phishing_check['risk_level']}
                    )
                    protection_result['actions_taken'].append('CUSTOMER_ALERTED')
        
        # Layer 4: Transaction monitoring
        if 'transactions' in session_data:
            for transaction in session_data['transactions']:
                transaction_protection = self.transaction_protector.monitor_transaction(
                    transaction, session_data
                )
                protection_result['protection_layers'].append('transaction_monitoring')
                
                if transaction_protection['action'] in ['BLOCK_AND_ALERT', 'REQUIRE_2FA']:
                    protection_result['risks_detected'].append({
                        'type': 'TRANSACTION_RISK',
                        'severity': 'HIGH',
                        'transaction_id': transaction['id'],
                        'details': transaction_protection
                    })
                    protection_result['actions_taken'].append(
                        f'TRANSACTION_{transaction_protection["action"]}'
                    )
        
        # Layer 5: Compliance logging
        self.compliance_logger.log_session_protection(protection_result)
        
        # Determine overall session risk
        overall_risk = self._calculate_overall_risk(protection_result)
        protection_result['overall_risk'] = overall_risk
        
        # Take final action based on risk
        if overall_risk['level'] == 'CRITICAL':
            protection_result['final_action'] = 'TERMINATE_SESSION_AND_ALERT'
            await self._terminate_risky_session(session_data)
        elif overall_risk['level'] == 'HIGH':
            protection_result['final_action'] = 'ENFORCE_STRONG_AUTH'
            await self._enforce_strong_authentication(session_data)
        elif overall_risk['level'] == 'MEDIUM':
            protection_result['final_action'] = 'WARN_AND_MONITOR'
        else:
            protection_result['final_action'] = 'ALLOW_CONTINUE'
        
        return protection_result