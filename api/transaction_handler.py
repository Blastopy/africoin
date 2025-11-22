import logging
from typing import Dict, Any, Optional
from wallet_manager import WalletManager
import secrets
from datetime import datetime
import os, sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from api import db_wallet_service


class TransactionHandler:
    def __init__(self, wallet_manager: WalletManager):
        self.wallet_manager = wallet_manager
        self.db_wallet_service = db_wallet_service.DBWalletService()
        self.logger = logging.getLogger('Africoin')
    
    def send_transaction(self, from_address: str, to_address: str, amount: float) -> Dict[str, Any]:
        """Send transaction with comprehensive error handling"""
        try:
            self.logger.info(f"Attempting transaction: {from_address} -> {to_address} ({amount})")
            
            # Validate inputs
            self._validate_transaction_inputs(from_address, to_address, amount)
            
            # Check if sender wallet exists in DATABASE
            db_result = self.db_wallet_service.get_wallet_by_address(from_address)
            if not db_result['success']:
                raise Exception(f"Sender wallet {from_address} not found in database")
            
            # Check if recipient wallet exists in DATABASE
            recipient_result = self.db_wallet_service.get_wallet_by_address(to_address)
            if not recipient_result['success']:
                self.logger.warning(f"Recipient wallet {to_address} not found in database, but proceeding with transaction")
            
            # Check wallet system for private key access
            if not self._is_wallet_accessible(from_address):
                wallets = self.wallet_manager.list_wallets()
                if from_address not in wallets:
                    raise Exception(f"Address {from_address} not found in wallet system. Available: {', '.join(wallets)}")
                else:
                    raise Exception(f"Wallet {from_address} exists but private key is not accessible")
            
            # Get private key for signing
            private_key = self.wallet_manager.get_private_key(from_address)
            if not private_key:
                raise Exception(f"No private key available for address: {from_address}")
            
            # Create and sign transaction
            transaction = self._create_transaction(from_address, to_address, amount, private_key)
            
            # Broadcast transaction
            result = self._broadcast_transaction(transaction)
            
            # Update balances in database
            self._update_balances_after_transaction(from_address, to_address, amount)
            
            self.logger.info(f"Transaction successful: {result['tx_hash']}")
            return {
                'success': True,
                'tx_hash': result['tx_hash'],
                'message': 'Transaction completed successfully'
            }
            
        except Exception as e:
            self.logger.error(f"Transaction failed: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'message': self._get_user_friendly_error(e)
            }
    
    def _update_balances_after_transaction(self, from_address: str, to_address: str, amount: float):
        """Update wallet balances in database after successful transaction"""
        try:
            # Update sender balance
            sender_result = self.db_wallet_service.get_wallet_by_address(from_address)
            if sender_result['success']:
                sender_balance = sender_result['wallet']['balance']
                new_sender_balance = sender_balance - amount
                self.db_wallet_service.update_wallet_balance(from_address, new_sender_balance)
            
            # Update recipient balance
            recipient_result = self.db_wallet_service.get_wallet_by_address(to_address)
            if recipient_result['success']:
                recipient_balance = recipient_result['wallet']['balance']
                new_recipient_balance = recipient_balance + amount
                self.db_wallet_service.update_wallet_balance(to_address, new_recipient_balance)
                
        except Exception as e:
            self.logger.error(f"Error updating balances: {str(e)}")
            # Don't fail the transaction if balance update fails
    
    # ... keep the rest of your existing methods the same ...
    def _get_user_friendly_error(self, error: Exception) -> str:
        """Convert technical errors to user-friendly messages"""
        error_msg = str(error)
        
        if "not found in database" in error_msg:
            return "Wallet address not found. Please check the address and try again."
        elif "No private key" in error_msg:
            return "Wallet not accessible. Please contact support."
        elif "Wallet not accessible" in error_msg:
            return "Wallet system error. Please try again later."
        elif "not found in wallet system" in error_msg:
            return "Wallet address not found in the system."
        elif "Amount must be positive" in error_msg:
            return "Transaction amount must be greater than zero."
        elif "Cannot send to same address" in error_msg:
            return "Cannot send funds to the same wallet address."
        elif "Invalid Africoin address format" in error_msg:
            return "Invalid wallet address format."
        else:
            return "Transaction failed. Please try again."

    def _validate_transaction_inputs(self, from_address: str, to_address: str, amount: float) -> None:
        """Validate transaction inputs"""
        if not from_address or not to_address:
            raise Exception("Sender and recipient addresses are required")
        
        if amount <= 0:
            raise Exception("Amount must be positive")
        
        if from_address == to_address:
            raise Exception("Cannot send to same address")
        
        # Validate address format
        if not from_address.startswith('AFC'):
            raise Exception("Invalid sender Africoin address format")
        if not to_address.startswith('AFC'):
            raise Exception("Invalid recipient Africoin address format")
    
    def _is_wallet_accessible(self, address: str) -> bool:
        """Check if wallet is accessible in wallet system"""
        try:
            self.logger.info(f"Checking wallet accessibility for: {address}")
            
            if not self.wallet_manager.fernet:
                self.logger.error("Wallet system not initialized")
                return False
            
            wallets = self.wallet_manager.list_wallets()
            if address not in wallets:
                self.logger.error(f"Address {address} not found in wallet system")
                return False
            
            private_key = self.wallet_manager.get_private_key(address)
            accessible = private_key is not None
            
            if accessible:
                self.logger.info(f"Wallet {address} is accessible")
            else:
                self.logger.error(f"Private key not accessible for {address}")
                
            return accessible
            
        except Exception as e:
            self.logger.error(f"Wallet accessibility check failed: {str(e)}")
            return False
    
    def _create_transaction(self, from_address: str, to_address: str, amount: float, private_key: str) -> Dict[str, Any]:
        """Create and sign transaction"""
        return {
            'from': from_address,
            'to': to_address,
            'amount': amount,
            'timestamp': self._get_timestamp(),
            'signature': self._sign_transaction(from_address, to_address, amount, private_key)
        }
    
    def _sign_transaction(self, from_address: str, to_address: str, amount: float, private_key: str) -> str:
        """Sign transaction with private key"""
        import hashlib
        transaction_data = f"{from_address}{to_address}{amount}{self._get_timestamp()}"
        return hashlib.sha256((transaction_data + private_key).encode()).hexdigest()
    
    def _broadcast_transaction(self, transaction: Dict[str, Any]) -> Dict[str, Any]:
        """Broadcast transaction to network"""
        # Your existing broadcast logic
        return {
            'tx_hash': f"tx_{secrets.token_hex(16)}",
            'status': 'confirmed',
            'timestamp': self._get_timestamp()
        }
    
    def _get_timestamp(self) -> str:
        return datetime.now().isoformat()