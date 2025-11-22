# wallet_manager.py
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import secrets
import hashlib
from typing import Optional, Dict, Any
import os, sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from models import db, User, Wallet  # Import your models

class WalletManager:
    def __init__(self):
        self.fernet = None
        self.current_address = None
        self.logger = logging.getLogger('Africoin')
        
    def initialize_wallet_system(self, password: str) -> bool:
        """Initialize the wallet system with a master password"""
        try:
            self.logger.info(f"Starting wallet initialization...")
            
            # Validate password
            if not password or len(password) < 8:
                raise Exception("Password must be at least 8 characters long")
            
            # Generate salt
            salt = secrets.token_bytes(16)
            self.logger.info(f"Generated salt: {len(salt)} bytes")
            
            # Create key derivation function
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            self.logger.info("KDF created successfully")
            
            # Derive key from password
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            self.logger.info(f"Key derived successfully: {len(key)} bytes")
            
            # Initialize Fernet with the key
            self.fernet = Fernet(key)
            self.logger.info("Fernet cipher initialized")
            
            # Store the master key in environment variable or config (for demo purposes)
            # In production, use a secure key management system
            self.logger.info("Wallet system initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize wallet system: {str(e)}", exc_info=True)
            return False
    
    def load_wallet_system(self, password: str) -> bool:
        """Load existing wallet system"""
        try:
            self.logger.info(f"Attempting to load wallet system...")
            
            # For database approach, we don't need to load from file
            # The key management would be handled differently in production
            # For now, we'll reinitialize with the same password
            return self.initialize_wallet_system(password)
            
        except Exception as e:
            self.logger.error(f"Failed to load wallet system: {str(e)}", exc_info=True)
            return False
    
    def create_wallet(self, wallet_name: str, user_id:int = None) -> Optional[str]:
        """Create a new wallet and store in database"""
        try:
            if not self.fernet:
                raise Exception("Wallet system not initialized. Call initialize_wallet_system() first")
            
            user_id = User.query.order_by(User.id.desc()).first().id if User.query.first() else 0

            # Generate new private key and address
            private_key = secrets.token_hex(32)
            address = self._generate_address(private_key)
            
            # Encrypt private key
            encrypted_private_key = self.fernet.encrypt(private_key.encode()).decode()
            
            # Get public key
            public_key = self._get_public_key(private_key)
            
            # Check if wallet already exists
            existing_wallet = Wallet.query.filter_by(address=address).first()
            if existing_wallet:
                self.logger.warning(f"Wallet already exists: {address}")
                return address

            # Create new wallet in database
            wallet = Wallet(
                address=address,
                name=wallet_name,
                encrypted_private_key=encrypted_private_key,
                public_key=public_key,
                balance=0.0,
                user_id=user_id,
                is_active=True
            )
            
            db.session.add(wallet)
            db.session.commit()
            
            # If user_id provided, update user's wallet_address
            if user_id:
                user = User.query.get(user_id)
                if user:
                    user.wallet_address = address
                    db.session.commit()
            
            self.current_address = address
            self.logger.info(f"Wallet created successfully: {address} for user {user_id}")
            return address
            
        except Exception as e:
            self.logger.error(f"Failed to create wallet: {str(e)}")
            db.session.rollback()
            return None
    
    def import_wallet(self, private_key: str, wallet_name: str, user_id: int = None) -> Optional[str]:
        """Import existing wallet from private key and store in database"""
        try:
            if not self.fernet:
                raise Exception("Wallet system not initialized")
            
            address = self._generate_address(private_key)
            encrypted_private_key = self.fernet.encrypt(private_key.encode()).decode()
            public_key = self._get_public_key(private_key)
            
            # Check if wallet already exists
            existing_wallet = Wallet.query.filter_by(address=address).first()
            if existing_wallet:
                self.logger.warning(f"Wallet already exists: {address}")
                return address
            
            # Create wallet in database
            wallet = Wallet(
                address=address,
                name=wallet_name,
                encrypted_private_key=encrypted_private_key,
                public_key=public_key,
                balance=0.0,
                user_id=user_id,
                is_active=True
            )
            
            db.session.add(wallet)
            db.session.commit()
            
            # If user_id provided, update user's wallet_address
            if user_id:
                user = User.query.get(user_id)
                if user:
                    user.wallet_address = address
                    db.session.commit()
            
            self.current_address = address
            self.logger.info(f"Wallet imported successfully: {address} for user {user_id}")
            return address
            
        except Exception as e:
            self.logger.error(f"Failed to import wallet: {str(e)}")
            db.session.rollback()
            return None
    
    def get_private_key(self, address: str) -> Optional[str]:
        """Get decrypted private key for address from database"""
        try:
            if not self.fernet:
                raise Exception("Wallet system not initialized")
            
            # Get wallet from database
            wallet = Wallet.query.filter_by(address=address, is_active=True).first()
            
            if not wallet:
                raise Exception(f"No wallet found for address {address}")
            
            if not wallet.encrypted_private_key:
                raise Exception(f"No private key stored for address {address}")
            
            # Decrypt private key
            private_key = self.fernet.decrypt(wallet.encrypted_private_key.encode()).decode()
            
            return private_key
            
        except Exception as e:
            self.logger.error(f"Error getting private key: {str(e)}")
            return None
    
    def get_wallet_info(self, address: str) -> Optional[Dict[str, Any]]:
        """Get wallet information without private key from database"""
        try:
            wallet = Wallet.query.filter_by(address=address, is_active=True).first()
            
            if not wallet:
                return None
            
            return {
                'name': wallet.name,
                'public_key': wallet.public_key,
                'balance': wallet.balance,
                'user_id': wallet.user_id,
                'created_at': wallet.created_at.isoformat() if wallet.created_at else None,
                'is_active': wallet.is_active
            }
            
        except Exception as e:
            self.logger.error(f"Error getting wallet info: {str(e)}")
            return None
    
    def list_wallets(self) -> list:
        """List all wallet addresses from database"""
        try:
            wallets = Wallet.query.filter_by(is_active=True).with_entities(Wallet.address).all()
            return [wallet.address for wallet in wallets]
        except Exception as e:
            self.logger.error(f"Error listing wallets: {str(e)}")
            return []
    
    def get_wallet_by_user_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get wallet by user ID"""
        try:
            wallet = Wallet.query.filter_by(user_id=user_id, is_active=True).first()
            
            if not wallet:
                return None
            
            return {
                'address': wallet.address,
                'name': wallet.name,
                'balance': wallet.balance,
                'public_key': wallet.public_key,
                'created_at': wallet.created_at.isoformat() if wallet.created_at else None
            }
            
        except Exception as e:
            self.logger.error(f"Error getting wallet by user ID: {str(e)}")
            return None
    
    def update_wallet_balance(self, address: str, new_balance: float) -> bool:
        """Update wallet balance in database"""
        try:
            wallet = Wallet.query.filter_by(address=address, is_active=True).first()
            
            if not wallet:
                raise Exception(f"Wallet not found: {address}")
            
            old_balance = wallet.balance
            wallet.balance = new_balance
            db.session.commit()
            
            self.logger.info(f"Updated balance for {address}: {old_balance} -> {new_balance}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error updating wallet balance: {str(e)}")
            db.session.rollback()
            return False
    
    def get_wallet_balance(self, address: str) -> Optional[float]:
        """Get wallet balance from database"""
        try:
            wallet = Wallet.query.filter_by(address=address, is_active=True).first()
            
            if not wallet:
                raise Exception(f"Wallet not found: {address}")
            
            return wallet.balance
            
        except Exception as e:
            self.logger.error(f"Error getting wallet balance: {str(e)}")
            return None
    
    def delete_wallet(self, address: str) -> bool:
        """Soft delete wallet (set is_active to False)"""
        try:
            wallet = Wallet.query.filter_by(address=address).first()
            
            if not wallet:
                raise Exception(f"Wallet not found: {address}")
            
            wallet.is_active = False
            db.session.commit()
            
            self.logger.info(f"Wallet deactivated: {address}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error deleting wallet: {str(e)}")
            db.session.rollback()
            return False
    
    def get_all_wallets_info(self) -> list:
        """Get information for all wallets"""
        try:
            wallets = Wallet.query.filter_by(is_active=True).all()
            wallet_list = []
            
            for wallet in wallets:
                wallet_list.append({
                    'address': wallet.address,
                    'name': wallet.name,
                    'balance': wallet.balance,
                    'user_id': wallet.user_id,
                    'created_at': wallet.created_at.isoformat() if wallet.created_at else None,
                    'user_username': wallet.owner.username if wallet.owner else None
                })
            
            return wallet_list
            
        except Exception as e:
            self.logger.error(f"Error getting all wallets info: {str(e)}")
            return []
    
    def _generate_address(self, private_key: str) -> str:
        """Generate Africoin address from private key"""
        public_key = self._get_public_key(private_key)
        address_hash = hashlib.sha256(public_key.encode()).hexdigest()[:40]
        return f"AFC{address_hash}"
    
    def _get_public_key(self, private_key: str) -> str:
        """Generate public key from private key"""
        return hashlib.sha256(private_key.encode()).hexdigest()