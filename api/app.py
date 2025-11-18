from flask import Flask, jsonify, request, make_response
from flask_restx import Api, Resource, fields
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import jwt
import datetime
from functools import wraps
import json
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from core.blockchain import AfricoinBlockchain
from core.smart_contracts import SmartContractEngine

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'Africoin2025bymainnet'
app.config['JSON_SORT_KEYS'] = False

# Enable CORS

CORS(app,
     resources={r"/*": {"origins": ["http://localhost:7070", "http://127.0.0.1:7070"]}},
     supports_credentials=True)

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Initialize REST API
api = Api(app, 
          version='1.0', 
          title='Africoin API',
          description='Enterprise Blockchain Platform API',
          doc='/api/docs/',
          serve_challenge_on_401=False
         )

# Namespaces
ns_blockchain = api.namespace('blockchain', description='Blockchain operations')
ns_wallet = api.namespace('wallet', description='Wallet operations')
ns_contracts = api.namespace('contracts', description='Smart contracts')
ns_mining = api.namespace('mining', description='Mining operations')
ns_bridge = api.namespace('bridge', description='Cross-chain operations')

# Initialize blockchain
blockchain = AfricoinBlockchain()
contract_engine = SmartContractEngine()

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        if request.method == "OPTIONS":
            return make_response("", 200)
        
        token = request.headers.get('Authorization')
        
        if not token:
            return {'message': 'Token is missing'}, 401
        
        try:
            token = token.replace('Bearer ', '')
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = data['user_id']
        except:
            return {'message': 'Token is invalid'}, 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

# API Models
transaction_model = api.model('Transaction', {
    'from_address': fields.String(required=True),
    'to_address': fields.String(required=True),
    'amount': fields.Float(required=True),
    'fee': fields.Float(default=0.001)
})

contract_model = api.model('Contract', {
    'template': fields.String(required=True),
    'parameters': fields.Raw(required=True),
    'gas_limit': fields.Integer(default=1000000)
})

# Blockchain Endpoints
@ns_blockchain.route('/status')
class BlockchainStatus(Resource):
    @api.doc('get_blockchain_status')
    def get(self):
        """Get blockchain status"""
        status = {
            'block_height': len(blockchain.chain),
            'difficulty': blockchain.difficulty,
            'network_hashrate': blockchain.get_network_hashrate(),
            'pending_transactions': len(blockchain.pending_transactions),
            'block_reward': blockchain.get_block_reward(),
            'total_supply': blockchain.get_total_supply()
        }
        return jsonify(status)

@ns_blockchain.route('/blocks')
class BlockList(Resource):
    @api.doc('get_blocks')
    @api.param('limit', 'Number of blocks to return')
    def get(self):
        """Get recent blocks"""
        limit = min(int(request.args.get('limit', 10)), 100)
        blocks = blockchain.chain[-limit:]
        
        block_data = []
        for block in blocks:
            block_data.append({
                'index': block.index,
                'hash': block.hash,
                'previous_hash': block.previous_hash,
                'timestamp': block.timestamp,
                'transaction_count': len(block.transactions),
                'difficulty': block.difficulty
            })
        
        return jsonify(block_data)

@ns_blockchain.route('/blocks/<int:block_height>')
class BlockDetail(Resource):
    @api.doc('get_block')
    def get(self, block_height):
        """Get specific block"""
        if block_height >= len(blockchain.chain):
            return {'error': 'Block not found'}, 404
        
        block = blockchain.chain[block_height]
        transactions = []
        
        for tx in block.transactions:
            transactions.append({
                'hash': tx.tx_hash,
                'from': getattr(tx, 'sender', 'coinbase'),
                'to': tx.outputs[0].address if tx.outputs else '',
                'amount': tx.outputs[0].amount if tx.outputs else 0,
                'fee': getattr(tx, 'fee', 0)
            })
        
        return jsonify({
            'index': block.index,
            'hash': block.hash,
            'previous_hash': block.previous_hash,
            'timestamp': block.timestamp,
            'transactions': transactions,
            'nonce': block.nonce,
            'difficulty': block.difficulty
        })

@ns_blockchain.route('/transactions/<string:tx_hash>')
class TransactionDetail(Resource):
    @api.doc('get_transaction')
    def get(self, tx_hash):
        """Get transaction details"""
        transaction = blockchain.find_transaction(tx_hash)
        if not transaction:
            return {'error': 'Transaction not found'}, 404
        
        return jsonify({
            'hash': transaction.tx_hash,
            'block_height': transaction.block_height,
            'confirmations': len(blockchain.chain) - transaction.block_height,
            'inputs': [{'address': inp.address, 'amount': inp.amount} for inp in transaction.inputs],
            'outputs': [{'address': out.address, 'amount': out.amount} for out in transaction.outputs],
            'fee': transaction.fee,
            'timestamp': transaction.timestamp
        })

# Wallet Endpoints
@ns_wallet.route('/create')
class CreateWallet(Resource):
    @api.doc('create_wallet')
    @token_required
    def post(self, current_user):
        """Create new wallet"""
        address = blockchain.wallet.generate_new_address()
        return {
            'address': address,
            'message': 'Wallet created successfully'
        }

@ns_wallet.route('/balance/<string:address>')
class WalletBalance(Resource):
    @api.doc('get_balance')
    def get(self, address):
        """Get wallet balance"""
        balance = blockchain.wallet.get_balance(address)
        utxos = blockchain.wallet.get_utxos(address)
        
        return jsonify({
            'address': address,
            'balance': balance,
            'utxo_count': len(utxos),
            'utxos': [{
                'tx_hash': utxo.tx_hash,
                'amount': utxo.amount,
                'confirmations': blockchain.get_confirmations(utxo.tx_hash)
            } for utxo in utxos[:10]]  # Limit to 10 UTXOs
        })

@ns_wallet.route('/send', methods=['POST', 'OPTIONS'])
class SendTransaction(Resource):
    @api.doc('send_transaction')
    
    def options(self):
        return {}, 200
    
    @api.expect(transaction_model)
    @token_required
    def post(self, current_user):
        """Send transaction"""
        data = request.get_json()
        
        transaction = blockchain.wallet.create_transaction(
            data['from_address'],
            data['to_address'],
            data['amount'],
            data.get('fee', 0.001)
        )
        
        if transaction:
            blockchain.pending_transactions.append(transaction)
            
            # Broadcast to network
            blockchain.network.broadcast_transaction(transaction)
            
            return {
                'success': True,
                'tx_hash': transaction.tx_hash,
                'message': 'Transaction created and broadcasted'
            }
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to create transaction'
            }), 400

# Smart Contract Endpoints
@ns_contracts.route('/deploy')
class DeployContract(Resource):
    @api.doc('deploy_contract')
    @api.expect(contract_model)
    @token_required
    def post(self, current_user):
        """Deploy smart contract"""
        data = request.get_json()
        
        try:
            contract_id = contract_engine.deploy_contract(
                data['template'],
                current_user,
                data['parameters']
            )
            
            return jsonify({
                'success': True,
                'contract_id': contract_id,
                'message': 'Contract deployed successfully'
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 400

@ns_contracts.route('/execute/<string:contract_id>')
class ExecuteContract(Resource):
    @api.doc('execute_contract')
    @api.param('function', 'Function to execute')
    @api.param('args', 'Function arguments as JSON array')
    @token_required
    def post(self, current_user, contract_id):
        """Execute contract function"""
        function = request.args.get('function')
        args = request.get_json()
        
        try:
            result = contract_engine.execute_contract(
                contract_id,
                function,
                args,
                current_user
            )
            
            return jsonify(result)
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 400

# Mining Endpoints
@ns_mining.route('/pool/join')
class JoinMiningPool(Resource):
    @api.doc('join_mining_pool')
    @api.param('address', 'Miner payout address')
    def post(self):
        """Join mining pool"""
        address = request.args.get('address')
        
        if not address:
            return {'error': 'Address required'}, 400
        
        pool_info = blockchain.mining_pool.add_miner(address)
        return jsonify(pool_info)

@ns_mining.route('/pool/stats')
class PoolStats(Resource):
    @api.doc('get_pool_stats')
    def get(self):
        """Get mining pool statistics"""
        stats = blockchain.mining_pool.get_stats()
        return jsonify(stats)

# Cross-chain Bridge Endpoints
@ns_bridge.route('/lock')
class LockFunds(Resource):
    @api.doc('lock_funds')
    @api.param('target_chain', 'Target blockchain')
    @api.param('amount', 'Amount to bridge')
    @token_required
    def post(self, current_user):
        """Lock funds for cross-chain transfer"""
        target_chain = request.args.get('target_chain')
        amount = float(request.args.get('amount'))
        
        try:
            result = blockchain.cross_chain_bridge.lock_funds(
                current_user,
                target_chain,
                amount
            )
            return jsonify(result)
        except Exception as e:
            return jsonify({'error': str(e)}), 400

@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin")
    allowed = ["http://localhost:7070", "http://127.0.0.1:7070"]

    if origin in allowed:
        response.headers["Access-Control-Allow-Origin"] = origin

    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)