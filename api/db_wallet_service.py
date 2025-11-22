import logging
from models import db, User, Wallet

class DBWalletService:
    def __init__(self):
        self.logger = logging.getLogger('Africoin')
    
    def get_wallet_by_address(self, address):
        """Get wallet by address from database"""
        try:
            wallet = User.query.filter_by(wallet_address=address, is_active=True).first()
            if wallet:
                self.logger.info(f"Found wallet in DB: {address}")
                return {
                    'success': True,
                    'wallet': {
                        'id': wallet.id,
                        'address': wallet.address,
                        'name': wallet.name,
                        'balance': wallet.balance,
                        'user_id': wallet.user_id,
                        'owner_username': wallet.owner.username if wallet.owner else None
                    }
                }
            else:
                self.logger.warning(f"Wallet not found in DB: {address}")
                return {'success': False, 'error': 'Wallet not found'}
                
        except Exception as e:
            self.logger.error(f"Error getting wallet from DB: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def get_user_wallets(self, user_id):
        """Get all wallets for a user"""
        try:
            wallets = Wallet.query.filter_by(user_id=user_id, is_active=True).all()
            wallet_list = []
            
            for wallet in wallets:
                wallet_list.append({
                    'id': wallet.id,
                    'address': wallet.address,
                    'name': wallet.name,
                    'balance': wallet.balance,
                    'created_at': wallet.created_at.isoformat()
                })
            
            return {'success': True, 'wallets': wallet_list}
            
        except Exception as e:
            self.logger.error(f"Error getting user wallets: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def update_wallet_balance(self, address, new_balance):
        """Update wallet balance in database"""
        try:
            wallet = Wallet.query.filter_by(address=address).first()
            if wallet:
                old_balance = wallet.balance
                wallet.balance = new_balance
                db.session.commit()
                
                self.logger.info(f"Updated balance for {address}: {old_balance} -> {new_balance}")
                return {'success': True}
            else:
                return {'success': False, 'error': 'Wallet not found'}
                
        except Exception as e:
            self.logger.error(f"Error updating wallet balance: {str(e)}")
            db.session.rollback()
            return {'success': False, 'error': str(e)}
    
    def create_wallet_record(self, user_id, address, name, balance=0.0):
        """Create a new wallet record in database"""
        try:
            # Check if wallet already exists
            existing_wallet = Wallet.query.filter_by(address=address).first()
            if existing_wallet:
                return {'success': False, 'error': 'Wallet already exists'}
            
            wallet = Wallet(
                address=address,
                name=name,
                balance=balance,
                user_id=user_id,
                is_active=True
            )
            
            db.session.add(wallet)
            db.session.commit()
            
            self.logger.info(f"Created wallet record: {address} for user {user_id}")
            return {'success': True, 'wallet_id': wallet.id}
            
        except Exception as e:
            self.logger.error(f"Error creating wallet record: {str(e)}")
            db.session.rollback()
            return {'success': False, 'error': str(e)}
    
    def get_wallet_with_user(self, address):
        """Get wallet with user information"""
        try:
            wallet = Wallet.query.filter_by(address=address).join(User).first()
            if wallet:
                return {
                    'success': True,
                    'wallet': {
                        'address': wallet.address,
                        'name': wallet.name,
                        'balance': wallet.balance,
                        'user': {
                            'id': wallet.owner.id,
                            'username': wallet.owner.username,
                            'email': wallet.owner.email
                        }
                    }
                }
            else:
                return {'success': False, 'error': 'Wallet not found'}
                
        except Exception as e:
            self.logger.error(f"Error getting wallet with user: {str(e)}")
            return {'success': False, 'error': str(e)}