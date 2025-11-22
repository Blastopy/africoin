import requests
import logging
import secrets
from flask import current_app

class WalletService:
    def __init__(self):
        self.base_url = "http://localhost:5000"
        self.api_key = "your_internal_api_key_456"
        logging.info(f"WalletService using direct config: {self.base_url}")
    
    def create_wallet_for_user(self, user_data):
        """Create a wallet for a new user"""
        try:
            init_url = f"{self.base_url}/wallet/init"
            
            payload = {
                'password': 'default_master_password_123'
            }
            
            logging.info(f"Initializing wallet system with master password")
            
            response = requests.post(
                init_url,
                headers={
                    'Content-Type': 'application/json'
                },
                json=payload,
                timeout=10
            )
            
            logging.info(f"Wallet initialization response status: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    logging.info("Wallet system initialized successfully")
                payload = {
                    'user': {
                        'user_id': f"user_{secrets.token_hex(8)}",
                        'username': user_data['username'],
                        'email': user_data['email'],
                        'wallet_name': user_data.get('wallet_name', f"{user_data['first_name']} {user_data['last_name']}'s Wallet"),
                        'initial_balance': user_data.get('initial_balance', 0.0)
                    }
                }
                
                response = requests.post(
                    f"{self.base_url}/wallet/create",
                    headers={
                        'X-API-Key': self.api_key,
                        'Content-Type': 'application/json'
                    },
                    json=payload,
                    timeout=10
                )
                
                if response.status_code == 200:
                    result = response.json()
                    return result
            else:
                logging.error(f"Wallet API returned status {response.status_code}")
                return {'success': False, 'error': f'API returned status {response.status_code}'}
                
        except requests.exceptions.RequestException as e:
            logging.error(f"Wallet API call failed: {str(e)}")
            return {'success': False, 'error': f'API call failed: {str(e)}'}
        except Exception as e:
            logging.error(f"Unexpected error in wallet service: {str(e)}")
            return {'success': False, 'error': f'Unexpected error: {str(e)}'}
    
    def get_wallet_balance(self, wallet_address):
        """Get wallet balance"""
        try:
            # First get the user ID from our database
            from models import User  # Import your User model
            user = User.query.filter_by(wallet_address=wallet_address).first()
            
            if not user or not user.api_user_id:
                return {'success': False, 'error': 'User or API user ID not found'}
            
            response = requests.get(
                f"{self.base_url}/api/user/{user.api_user_id}/wallet",
                headers={
                    'X-API-Key': self.api_key
                },
                timeout=5
            )
            
            if response.status_code == 200:
                result = response.json()
                if result['success']:
                    return {'success': True, 'balance': result['user']['balance']}
                else:
                    return result
            else:
                return {'success': False, 'error': f'API returned status {response.status_code}'}
                
        except Exception as e:
            logging.error(f"Error getting wallet balance: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def send_transaction(self, from_wallet_address, to_address, amount):
        """Send transaction from user's wallet"""
        try:
            # Get user from database
            from models import User
            user = User.query.filter_by(wallet_address=from_wallet_address).first()
            
            if not user or not user.api_user_id:
                return {'success': False, 'error': 'User not found'}
            
            payload = {
                'to_address': to_address,
                'amount': amount
            }
            
            response = requests.post(
                f"{self.base_url}/api/user/{user.api_user_id}/transaction",
                headers={
                    'X-API-Key': self.api_key,
                    'Content-Type': 'application/json'
                },
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {'success': False, 'error': f'API returned status {response.status_code}'}
                
        except Exception as e:
            logging.error(f"Error sending transaction: {str(e)}")
            return {'success': False, 'error': str(e)}