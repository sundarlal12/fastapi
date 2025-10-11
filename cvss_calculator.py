# cvss_calculator.py
import math

class CVSS30Calculator:
    def __init__(self):
        self.CVSS_VERSION = "CVSS:3.0"
        
        # Metric weights for CVSS 3.0
        self.WEIGHTS = {
            'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},
            'AC': {'L': 0.77, 'H': 0.44},
            'PR': {'N': 0.85, 'L': 0.62, 'H': 0.27},  # For Unchanged Scope
            'UI': {'N': 0.85, 'R': 0.62},
            'S': {'U': 6.42, 'C': 7.52},
            'C': {'N': 0, 'L': 0.22, 'H': 0.56},
            'I': {'N': 0, 'L': 0.22, 'H': 0.56},
            'A': {'N': 0, 'L': 0.22, 'H': 0.56}
        }
        
        self.EXPLOITABILITY_COEFFICIENT = 8.22
        self.SCOPE_COEFFICIENT = 1.08
        
        self.SEVERITY_RATINGS = [
            {"name": "None", "bottom": 0.0, "top": 0.0},
            {"name": "Low", "bottom": 0.1, "top": 3.9},
            {"name": "Medium", "bottom": 4.0, "top": 6.9},
            {"name": "High", "bottom": 7.0, "top": 8.9},
            {"name": "Critical", "bottom": 9.0, "top": 10.0}
        ]

    def round_up(self, score):
        """Round up to 1 decimal place"""
        return math.ceil(score * 10) / 10

    def get_severity(self, score):
        """Get severity rating from score"""
        score = float(score)
        for rating in self.SEVERITY_RATINGS:
            if rating["bottom"] <= score <= rating["top"]:
                return rating["name"]
        return "None"

    def calculate_cvss(self, vulnerability_type, severity):
        """Calculate CVSS 3.0 scores based on vulnerability type and severity"""
        # Get base metrics for the vulnerability type
        base_metrics = self._get_base_metrics(vulnerability_type, severity)
        
        # Calculate base score
        base_score = self._calculate_base_score(base_metrics)
        
        # Generate vector string
        vector_string = self._generate_vector_string(base_metrics)
        
        return {
            "cvss_vector": vector_string,
            "cvss_base_score": base_score,
            "cvss_base_severity": self.get_severity(base_score)
        }

    def _calculate_base_score(self, metrics):
        """Calculate base CVSS 3.0 score"""
        AV = metrics['AV']
        AC = metrics['AC']
        PR = metrics['PR']
        UI = metrics['UI']
        S = metrics['S']
        C = metrics['C']
        I = metrics['I']
        A = metrics['A']
        
        # Calculate exploitability sub-score
        exploitability = self.EXPLOITABILITY_COEFFICIENT
        exploitability *= self.WEIGHTS['AV'][AV]
        exploitability *= self.WEIGHTS['AC'][AC]
        exploitability *= self.WEIGHTS['PR'][PR]
        exploitability *= self.WEIGHTS['UI'][UI]
        
        # Calculate impact sub-score
        iss = 1 - ((1 - self.WEIGHTS['C'][C]) * 
                   (1 - self.WEIGHTS['I'][I]) * 
                   (1 - self.WEIGHTS['A'][A]))
        
        if S == 'U':
            # Unchanged scope
            impact = self.WEIGHTS['S'][S] * iss
        else:
            # Changed scope
            impact = self.WEIGHTS['S'][S] * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
        
        if impact <= 0:
            base_score = 0
        else:
            if S == 'U':
                base_score = self.round_up(min(exploitability + impact, 10))
            else:
                base_score = self.round_up(min(self.SCOPE_COEFFICIENT * (exploitability + impact), 10))
        
        return base_score

    def _generate_vector_string(self, metrics):
        """Generate CVSS 3.0 vector string"""
        vector_parts = [self.CVSS_VERSION]
        
        for metric in ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']:
            vector_parts.append(f"{metric}:{metrics[metric]}")
        
        return "/".join(vector_parts)

    def _get_base_metrics(self, vulnerability_type, severity):
        """Get base metrics based on vulnerability type and severity"""
        # Default metrics (Network-based, low complexity, no privileges)
        metrics = {
            'AV': 'N',  # Network
            'AC': 'L',  # Low complexity
            'PR': 'N',  # No privileges required
            'UI': 'N',  # No user interaction
            'S': 'U',   # Unchanged scope
            'C': 'H',   # High confidentiality impact
            'I': 'H',   # High integrity impact  
            'A': 'H'    # High availability impact
        }
        
        # Adjust based on vulnerability type
        self._apply_vulnerability_rules(metrics, vulnerability_type)
        
        # Adjust impact based on severity
        self._apply_severity_rules(metrics, severity)
        
        return metrics

    def _apply_vulnerability_rules(self, metrics, vulnerability_type):
        """Apply vulnerability-specific rules"""
        vuln_type = vulnerability_type.lower()
        
        # Network-based attacks
        if any(x in vuln_type for x in ['sql injection', 'rce', 'command injection', 'ssrf']):
            metrics.update({'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N'})
        
        # Client-side attacks
        elif any(x in vuln_type for x in ['xss', 'csrf', 'clickjacking']):
            metrics.update({'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'R'})
        
        # Authentication issues
        elif any(x in vuln_type for x in ['idor', 'broken authentication', 'session fixation']):
            metrics.update({'AV': 'N', 'AC': 'L', 'PR': 'L', 'UI': 'N'})
        
        # Privilege escalation
        elif any(x in vuln_type for x in ['privilege escalation', 'access control']):
            metrics.update({'AV': 'L', 'AC': 'L', 'PR': 'L', 'UI': 'N'})
        
        # Information disclosure
        elif any(x in vuln_type for x in ['information disclosure', 'info leak', 'sensitive data']):
            metrics.update({'C': 'H', 'I': 'L', 'A': 'N'})
        
        # Configuration issues
        elif any(x in vuln_type for x in ['misconfiguration', 'hardcoded', 'secret']):
            metrics.update({'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N'})

    def _apply_severity_rules(self, metrics, severity):
        """Adjust impact based on severity"""
        severity = severity.lower()
        
        if severity == 'critical':
            metrics.update({'C': 'H', 'I': 'H', 'A': 'H'})
        elif severity == 'high':
            metrics.update({'C': 'H', 'I': 'H', 'A': 'H'})
        elif severity == 'medium':
            metrics.update({'C': 'H', 'I': 'L', 'A': 'N'})
        elif severity == 'low':
            metrics.update({'C': 'L', 'I': 'L', 'A': 'N'})
        else:  # info
            metrics.update({'C': 'N', 'I': 'N', 'A': 'N'})