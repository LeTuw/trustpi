from datetime import datetime
import math
import requests

class PiTrustScorer:
    def __init__(self):
        self.base_url = "https://api.mainnet.minepi.com"
    
    def calculate_pi_trust(self, wallet_id):
        """Calculate PiTrust score (300-1000) for a wallet"""
        try:
            # Get all necessary data
            account_info = self._get_account_info(wallet_id)
            operations = self._get_operations(wallet_id, limit=100, include_failed=True)
            transactions = self._get_transactions(wallet_id, order='asc', limit=100)
            
            # Calculate component scores (0-1000 scale)
            payment_reliability = self._calculate_payment_reliability(operations)
            account_tenure = self._calculate_account_tenure(transactions)
            network_strength = self._calculate_network_strength(transactions)
            balance_health = self._calculate_balance_health(account_info, transactions)
            onchain_attestations = self._calculate_onchain_attestations(transactions, account_tenure)
            
            # Apply weights and sum
            weighted_score = (
                0.35 * payment_reliability +
                0.20 * account_tenure +
                0.20 * network_strength +
                0.15 * balance_health +
                0.10 * onchain_attestations
            )
            
            # Ensure KYC'd wallets start at 300
            final_score = max(300, weighted_score)
            final_score = min(final_score, 1000)  # Clamp to 1000
            
            return {
                "wallet_id": wallet_id,
                "pi_trust_score": round(final_score),
                "category": self._get_trust_category(final_score),
                "components": {
                    "payment_reliability": round(payment_reliability),
                    "account_tenure": round(account_tenure),
                    "network_strength": round(network_strength),
                    "balance_health": round(balance_health),
                    "onchain_attestations": round(onchain_attestations)
                },
                "breakdown": self._get_score_breakdown(
                    payment_reliability, account_tenure, network_strength,
                    balance_health, onchain_attestations, final_score
                )
            }
            
        except Exception as e:
            return {"error": str(e)}

    def _calculate_payment_reliability(self, operations_data):
        """Calculate payment reliability score (0-1000)"""
        records = operations_data.get('_embedded', {}).get('records', [])
        if not records:
            return 0
            
        total_ops = len(records)
        successful_ops = sum(1 for op in records if op.get('transaction_successful', True))
        failed_ops = total_ops - successful_ops
        
        success_rate = successful_ops / total_ops if total_ops > 0 else 0
        success_score = success_rate * 700  # 70% of component score
        
        # Penalize failures (up to 30% penalty)
        failure_penalty = min(failed_ops * 50, 300)
        
        return max(success_score - failure_penalty, 0)

    def _calculate_account_tenure(self, transactions_data):
        """Calculate account tenure score (0-1000)"""
        records = transactions_data.get('_embedded', {}).get('records', [])
        if not records:
            return 0
            
        # Get creation date from first transaction
        first_tx = records[-1]  # Oldest transaction
        created_at = first_tx.get('created_at')
        if not created_at:
            return 0
            
        created_dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
        months_active = (datetime.now(created_dt.tzinfo) - created_dt).days / 30.44
        
        # Calculate active months ratio
        active_months = self._count_active_months(records)
        total_months = max(months_active, 1)
        activity_ratio = active_months / total_months
        
        # Combine age and activity
        age_score = min(months_active / 24, 1.0) * 600  # 60% for age
        activity_score = activity_ratio * 400  # 40% for consistency
        
        return age_score + activity_score

    def _calculate_network_strength(self, transactions_data):
        """Calculate network strength score (0-1000)"""
        records = transactions_data.get('_embedded', {}).get('records', [])
        if not records:
            return 0
            
        # Get unique counterparts
        counterparts = set()
        for tx in records:
            if tx.get('source_account'):
                counterparts.add(tx['source_account'])
            # Add other counterpart logic based on operation type
        
        unique_count = len(counterparts)
        
        # Log-scale for network size (0-700 points)
        if unique_count == 0:
            network_size_score = 0
        else:
            network_size_score = min(math.log(unique_count + 1) * 200, 700)
        
        # TODO: Implement verified ratio (300 points)
        # For now, assume 50% are verified if we have counterparts
        verified_score = 300 if unique_count > 0 else 0
        
        return network_size_score + verified_score

    def _calculate_balance_health(self, account_info, transactions_data):
        """Calculate balance health score (0-1000)"""
        if not account_info:
            return 0
            
        # Get current balance
        balances = account_info.get('balances', [])
        native_balance = next((float(bal['balance']) for bal in balances 
                              if bal.get('asset_type') == 'native'), 0)
        
        # Calculate balance score (0-700 points)
        if native_balance <= 0:
            balance_score = 0
        else:
            balance_score = min(math.log(native_balance + 1) * 150, 700)
        
        # TODO: Implement min_balance_ratio (300 points)
        # Estimate from transaction flow
        stability_score = 300 if native_balance > 10 else 150  # Simple heuristic
        
        return balance_score + stability_score

    def _calculate_onchain_attestations(self, transactions_data, account_tenure_score):
        """Calculate on-chain attestations score (0-1000)"""
        records = transactions_data.get('_embedded', {}).get('records', [])
        if not records:
            return 0
            
        # Use tenure as base attestation (500 points)
        tenure_attestation = account_tenure_score * 0.5
        
        # Count trust transactions (500 points)
        trust_txs = sum(1 for tx in records if self._is_trust_transaction(tx))
        trust_score = min(trust_txs * 100, 500)
        
        return tenure_attestation + trust_score

    def _is_trust_transaction(self, transaction):
        """Check if transaction is a trust attestation"""
        memo = transaction.get('memo', '')
        memo_lower = memo.lower()
        return any(keyword in memo_lower for keyword in ['trust', 'vouch', 'attest', 'vouch'])

    def _count_active_months(self, transactions):
        """Count unique months with activity"""
        active_months = set()
        for tx in transactions:
            created_at = tx.get('created_at')
            if created_at:
                month = created_at[:7]  # YYYY-MM
                active_months.add(month)
        return len(active_months)

    def _get_trust_category(self, score):
        """Get trust category based on score"""
        if score >= 900: return "Elite"
        elif score >= 800: return "Trusted Leader"
        elif score >= 700: return "Reliable Partner"
        elif score >= 600: return "Established Member"
        elif score >= 500: return "Active Participant"
        elif score >= 400: return "Newcomer"
        else: return "Unproven"

    def _get_score_breakdown(self, payment, tenure, network, balance, attestations, final_score):
        """Get detailed score breakdown"""
        return {
            "weighted_components": {
                "payment_reliability": round(payment * 0.35),
                "account_tenure": round(tenure * 0.20),
                "network_strength": round(network * 0.20),
                "balance_health": round(balance * 0.15),
                "onchain_attestations": round(attestations * 0.10)
            },
            "kyc_bonus": 300 if final_score >= 300 else 0,
            "interpretation": self._get_interpretation(payment, tenure, network, balance, attestations)
        }

    def _get_interpretation(self, payment, tenure, network, balance, attestations):
        """Get human-readable interpretation"""
        aspects = []
        if payment > 800: aspects.append("excellent payment history")
        elif payment < 400: aspects.append("limited payment history")
        
        if tenure > 800: aspects.append("well-established account")
        elif tenure < 400: aspects.append("recently created account")
        
        if network > 800: aspects.append("strong network connections")
        elif network < 400: aspects.append("limited network diversity")
        
        if balance > 800: aspects.append("healthy balance")
        elif balance < 400: aspects.append("low balance stability")
        
        if attestations > 800: aspects.append("strong community attestations")
        elif attestations < 400: aspects.append("few community attestations")
        
        return "This wallet shows " + ", ".join(aspects) if aspects else "Insufficient data for assessment"

    # API methods
    def _get_account_info(self, account_id):
        try:
            response = requests.get(f"{self.base_url}/accounts/{account_id}", timeout=10)
            return response.json() if response.status_code == 200 else None
        except:
            return None

    def _get_operations(self, account_id, limit=100, include_failed=True):
        try:
            params = {'limit': limit, 'include_failed': str(include_failed).lower()}
            response = requests.get(f"{self.base_url}/accounts/{account_id}/operations", 
                                  params=params, timeout=10)
            return response.json() if response.status_code == 200 else {'_embedded': {'records': []}}
        except:
            return {'_embedded': {'records': []}}

    def _get_transactions(self, account_id, order='desc', limit=100):
        try:
            params = {'order': order, 'limit': limit}
            response = requests.get(f"{self.base_url}/accounts/{account_id}/transactions", 
                                  params=params, timeout=10)
            return response.json() if response.status_code == 200 else {'_embedded': {'records': []}}
        except:
            return {'_embedded': {'records': []}}
