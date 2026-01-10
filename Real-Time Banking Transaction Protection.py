class BankingTransactionProtector:
    """
    Real-time protection for banking transactions
    Monitors for phishing during active banking sessions
    """
    
    def __init__(self, customer_profile: Dict, risk_threshold: float = 0.85):
        self.customer_profile = customer_profile
        self.risk_threshold = risk_threshold
        self.session_analyzer = SessionBehaviorAnalyzer()
        self.device_fingerprinter = DeviceFingerprinter()
        
    def monitor_transaction(self, transaction: Dict, session_data: Dict) -> Dict:
        """
        Monitor transaction for phishing indicators
        """
        risk_score = 0.0
        alerts = []
        
        # 1. Check session consistency
        session_risk = self.session_analyzer.analyze_session(session_data)
        if session_risk['anomaly_detected']:
            risk_score += 0.3
            alerts.append({
                'type': 'SESSION_ANOMALY',
                'severity': 'HIGH',
                'description': session_risk['anomaly_description']
            })
        
        # 2. Check device fingerprint
        device_match = self.device_fingerprinter.verify_device(
            session_data.get('device_fingerprint'),
            self.customer_profile['known_devices']
        )
        
        if not device_match['is_known']:
            risk_score += 0.4
            alerts.append({
                'type': 'UNKNOWN_DEVICE',
                'severity': 'HIGH',
                'description': 'Transaction from unrecognized device'
            })
        
        # 3. Check transaction patterns
        transaction_risk = self._analyze_transaction_pattern(transaction)
        risk_score += transaction_risk['score']
        
        if transaction_risk['suspicious']:
            alerts.append({
                'type': 'TRANSACTION_PATTERN',
                'severity': 'MEDIUM',
                'description': transaction_risk['reason']
            })
        
        # 4. Check for social engineering indicators
        if self._detect_social_engineering(transaction, session_data):
            risk_score += 0.5
            alerts.append({
                'type': 'SOCIAL_ENGINEERING',
                'severity': 'CRITICAL',
                'description': 'Potential social engineering attempt detected'
            })
        
        # Determine action
        if risk_score >= self.risk_threshold:
            action = 'BLOCK_AND_ALERT'
        elif risk_score >= 0.6:
            action = 'REQUIRE_2FA'
        elif risk_score >= 0.3:
            action = 'WARN_CUSTOMER'
        else:
            action = 'ALLOW'
        
        return {
            'transaction_id': transaction.get('id'),
            'risk_score': min(risk_score, 1.0),
            'alerts': alerts,
            'action': action,
            'timestamp': datetime.utcnow().isoformat(),
            'customer_id': self.customer_profile['id']
        }
    
    def _detect_social_engineering(self, transaction: Dict, session_data: Dict) -> bool:
        """Detect social engineering patterns"""
        indicators = []
        
        # Unusual time for customer
        transaction_time = datetime.fromisoformat(transaction['timestamp'])
        usual_times = self.customer_profile.get('usual_transaction_times', [])
        
        if usual_times:
            hour = transaction_time.hour
            if hour not in usual_times:
                indicators.append('Unusual transaction time')
        
        # High-value transaction from unusual location
        if transaction.get('amount', 0) > self.customer_profile.get('usual_transaction_limit', 1000):
            current_location = session_data.get('location')
            usual_locations = self.customer_profile.get('usual_locations', [])
            
            if usual_locations and current_location not in usual_locations:
                indicators.append('High-value transaction from unusual location')
        
        # Rapid succession of transactions
        recent_transactions = self.customer_profile.get('recent_transactions', [])
        if len(recent_transactions) >= 3:
            time_diffs = []
            for i in range(1, len(recent_transactions)):
                diff = (datetime.fromisoformat(recent_transactions[i]['timestamp']) - 
                       datetime.fromisoformat(recent_transactions[i-1]['timestamp']))
                time_diffs.append(diff.total_seconds())
            
            if len(time_diffs) >= 2 and all(td < 60 for td in time_diffs[-2:]):
                indicators.append('Rapid succession of transactions')
        
        return len(indicators) >= 2