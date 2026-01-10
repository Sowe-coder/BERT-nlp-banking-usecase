class FinancialBERTPhishingDetector:
    """
    BERT model fine-tuned specifically on financial phishing data
    """
    
    def __init__(self, model_path: str = "microsoft/bert-base-uncased"):
        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model = AutoModel.from_pretrained(model_path)
        
        # Add financial classification head
        self.classifier = nn.Sequential(
            nn.Linear(768, 512),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(512, 256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Linear(128, 3),  # SAFE, SUSPICIOUS, PHISHING
            nn.Softmax(dim=-1)
        )
        
        # Load financial phishing training data
        self.financial_corpus = self._load_financial_corpus()
        
    def analyze_financial_content(self, url: str, content: str) -> Dict:
        """Analyze content with financial context"""
        # Tokenize with financial context
        inputs = self.tokenizer(
            f"URL: {url} Content: {content}",
            padding=True,
            truncation=True,
            max_length=512,
            return_tensors="pt"
        )
        
        # Get BERT embeddings
        with torch.no_grad():
            outputs = self.model(**inputs)
            cls_embedding = outputs.last_hidden_state[:, 0, :]
            
            # Classification
            predictions = self.classifier(cls_embedding)
            
            # Extract probabilities
            probs = predictions[0].numpy()
            
        return {
            'safe_probability': float(probs[0]),
            'suspicious_probability': float(probs[1]),
            'phishing_probability': float(probs[2]),
            'prediction': np.argmax(probs),
            'confidence': float(np.max(probs))
        }
    
    def detect_financial_phishing_patterns(self, text: str) -> List[Dict]:
        """Detect specific financial phishing patterns"""
        patterns = [
            {
                'pattern': r'urgent.*(action|required|verify)',
                'description': 'Urgent action required pattern',
                'severity': 'HIGH'
            },
            {
                'pattern': r'(account|login).*(suspended|locked|disabled)',
                'description': 'Account suspension threat',
                'severity': 'HIGH'
            },
            {
                'pattern': r'(verify|confirm).*(identity|information|details)',
                'description': 'Identity verification request',
                'severity': 'MEDIUM'
            },
            {
                'pattern': r'(security|fraud).*(alert|warning|detected)',
                'description': 'Security/fraud alert',
                'severity': 'MEDIUM'
            },
            {
                'pattern': r'click.*(link|here|below).*(log.?in|sign.?in)',
                'description': 'Direct login link request',
                'severity': 'HIGH'
            },
            {
                'pattern': r'\$\d+.*(refund|rebate|reward)',
                'description': 'Monetary incentive',
                'severity': 'MEDIUM'
            }
        ]
        
        detected_patterns = []
        for pattern_info in patterns:
            matches = re.findall(pattern_info['pattern'], text, re.IGNORECASE)
            if matches:
                detected_patterns.append({
                    'description': pattern_info['description'],
                    'severity': pattern_info['severity'],
                    'matches': matches[:3],  # Limit matches
                    'count': len(matches)
                })
        
        return detected_patterns