from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, make_response
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import secrets
import json
from datetime import datetime, timedelta
from models import Contract, Transaction
import threading
import time
from web.data_entry import (RegistrationForms, LoginForm, UpdateProfileForm, ChangePasswordForm, PreferencesForm, ResetPasswordRequestForm, ResetPasswordForm)
from web.extensions import db
from models import User
from urllib.parse import urlparse
import jwt


login_manager = LoginManager()


def create_app():
    app = Flask(__name__, template_folder='web/templates', static_folder='web/static')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
    app.config['SECRET_KEY'] = 'Africoin2025bymainnet'
    db.init_app(app)

    bcrypt = Bcrypt(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'


    with app.app_context():
        db.create_all()

    return app

app = create_app()

# # User model
# class User(db.Model, UserMixin):
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(150), unique=True, nullable=False)
#     password = db.Column(db.String(150), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class AfricoinDashboard:
    def __init__(self, api_url="http://localhost:5000/"):
        self.api_url = api_url
        self.cache = {}
        self.cache_timeout = 30  # seconds
        self.last_update = 0
        
    def get_blockchain_stats(self):
        """Get blockchain statistics"""
        if time.time() - self.last_update < self.cache_timeout:
            return self.cache.get('stats', {})
        
        try:
            response = requests.get(f"{self.api_url}/blockchain/status")
            stats = response.json()
            
            self.cache['stats'] = stats
            self.last_update = time.time()

            return stats
        except Exception as e:
            return {'error': str(e)}
    
    def get_recent_blocks(self, limit=10):
        """Get recent blocks"""
        try:
            response = requests.get(f"{self.api_url}/blockchain/blocks?limit={limit}")
            return response.json()
        except Exception as e:
            return []
    
    def get_network_info(self):
        """Get network information"""
        try:
            # Mock network data - in production, this would come from multiple nodes
            return {
                'node_count': 42,
                'peer_count': 156,
                'network_hashrate': '15.2 TH/s',
                'avg_block_time': '9.8s',
                'transaction_volume_24h': '1,250,000 AFC'
            }
        except Exception as e:
            return {'error': str(e)}

# Dashboard routes
# dashboard = AfricoinDashboard()

@app.route('/')
def index():
    """Main dashboard page"""
    dashboard = AfricoinDashboard()
    stats = dashboard.get_blockchain_stats()
    recent_blocks = dashboard.get_recent_blocks(5)
    network_info = dashboard.get_network_info()
    
    return render_template('index.html',
                         stats=stats,
                         recent_blocks=recent_blocks,
                         network_info=network_info)

@app.route('/blocks')
def blocks_page():
    """Blocks explorer page"""
    dashboard = AfricoinDashboard()
    blocks = dashboard.get_recent_blocks(50)
    return render_template('blocks.html', blocks=blocks)

@app.route('/transactions')
def transactions_page():
    """Transactions page"""
    return render_template('transactions.html')


@app.route('/mining')
def mining_page():
    """Mining dashboard page"""
    return render_template('mining.html')


# @app.route('/api/dashboard/stats')
# def api_dashboard_stats():
#     """API endpoint for dashboard statistics"""
#     stats = dashboard.get_blockchain_stats()
#     return jsonify(stats)

@app.route('/api/dashboard/blocks')
def api_dashboard_blocks():
    """API endpoint for blocks data"""
    limit = request.args.get('limit', 10, type=int)
    blocks = dashboard.get_recent_blocks(limit)
    return jsonify(blocks)



# Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForms()
    if form.validate_on_submit():
        # Generate wallet address
        wallet_address = 'AFC' + secrets.token_hex(20)
        
        # Create user
        user = User(
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            username=form.username.data,
            email=form.email.data,
            phone=form.phone.data,
            country=form.country.data,
            password_hash=generate_password_hash(form.password.data),
            wallet_address=wallet_address,
            created_at=datetime.utcnow()
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        # Check if input is email or username
        user = User.query.filter(
            (User.email == form.email.data) | (User.username == form.email.data)
        ).first()
        
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember.data)
            user.last_login = datetime.utcnow()
            db.session.commit()

            token = jwt.encode(
            {
                "user_id": user.id,
                "exp": datetime.utcnow() + timedelta(hours=5)
            },
                app.config['SECRET_KEY'],
                algorithm="HS256"
            )

            # resp = make_response(jsonify({"message": "Login successful"}))
            resp = redirect('/dashboard')
    # Save token as cookie
            resp.set_cookie(
                "authToken",
                token,
                max_age=5 * 60 * 60,     # 5 hours
                httponly=False,          # frontend JS needs to read it
                secure=False,            # set True if using HTTPS
                samesite="Lax"
            )
            return resp
            next_page = request.args.get('next')
            if not next_page or urlparse(next_page).netloc != '':
                next_page = url_for('dashboard')

            return redirect('/dashboard')
            # flash('Login successful!', 'success')
            # return redirect(next_page)
        else:
            flash('Login unsuccessful. Please check email/username and password.', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    dashboard = AfricoinDashboard()
    stats = dashboard.get_blockchain_stats()
    recent_blocks = dashboard.get_recent_blocks(5)
    network_info = dashboard.get_network_info()
    
   
    # Get user stats
    total_contracts = Contract.query.filter_by(user_id=current_user.id).count()
    active_contracts = Contract.query.filter_by(user_id=current_user.id, status='Active').count()
    return render_template('index.html',
                         stats=stats,
                         recent_blocks=recent_blocks,
                         network_info=network_info,
                         total_contracts=total_contracts,
                         active_contracts=active_contracts)

    
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/profile')
@login_required
def profile():
    form = UpdateProfileForm()
    password_form = ChangePasswordForm()
    preferences_form = PreferencesForm()
    
    # Populate form data
    form.first_name.data = current_user.first_name
    form.last_name.data = current_user.last_name
    form.username.data = current_user.username
    form.email.data = current_user.email
    form.phone.data = current_user.phone
    form.country.data = current_user.country
    
    # Mock data for demonstration
    recent_transactions = [
        {'date': datetime.utcnow(), 'type': 'received', 'amount': 1.5, 'status': 'confirmed'},
        {'date': datetime.utcnow(), 'type': 'sent', 'amount': 0.5, 'status': 'confirmed'}
    ]

    usd_url = 'https://api.frankfurter.app/latest?from=USD'
    r = requests.get(usd_url)
    usdData = r.json()
    exchange_rate = usdData['rates']['ZAR']

    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.created_at.desc()).limit(10).all()

    return render_template('profile.html', 
                         form=form,
                         transactions=transactions,
                         password_form=password_form,
                         preferences_form=preferences_form,
                         recent_transactions=recent_transactions,
                         exchange_rate=exchange_rate)  # Mock exchange rate

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    form = UpdateProfileForm()
    if form.validate_on_submit():
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        current_user.username = form.username.data
        current_user.email = form.email.data
        current_user.phone = form.phone.data
        current_user.country = form.country.data
        
        db.session.commit()
        flash('Your profile has been updated!', 'success')
    else:
        flash('Please correct the errors in the form.', 'danger')
    
    return redirect(url_for('profile'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if check_password_hash(current_user.password_hash, form.current_password.data):
            current_user.password_hash = generate_password_hash(form.new_password.data)
            db.session.commit()
            flash('Your password has been updated!', 'success')
        else:
            flash('Current password is incorrect.', 'danger')
    else:
        flash('Please correct the errors in the form.', 'danger')
    
    return redirect(url_for('profile'))

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            # Here you would typically send a password reset email
            # For now, we'll just show a message
            flash('Check your email for instructions to reset your password.', 'info')
            return redirect(url_for('login'))
        else:
            flash('Email not found.', 'danger')
    
    return render_template('reset_password_request.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    # In a real app, you would verify the token here
    # For demonstration, we'll assume it's valid
    form = ResetPasswordForm()
    if form.validate_on_submit():
        # Find user by token (in real app, you'd decode the token)
        # For now, we'll use a dummy implementation
        flash('Your password has been reset! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', form=form)

@app.route('/contracts')
@login_required
def contracts():
    user_contracts = Contract.query.filter_by(user_id=current_user.id).all()
    return render_template('contracts.html', contracts=user_contracts)

@app.route('/wallet')
@login_required
def wallet():
    usd_url = 'https://api.frankfurter.app/latest?from=USD'
    r = requests.get(usd_url)
    usdData = r.json()
    exchange_rate = usdData['rates']['ZAR']
    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.created_at.desc()).limit(10).all()
    return render_template('wallet.html', transactions=transactions, exchange_rate=exchange_rate)

# API endpoints
@app.route('/api/dashboard_stats')
@login_required
def api_dashboard_stats():
    stats = {
        'balance': current_user.balance,
        'total_contracts': Contract.query.filter_by(user_id=current_user.id).count(),
        'active_contracts': Contract.query.filter_by(user_id=current_user.id, status='Active').count(),
        'pending_transactions': Transaction.query.filter_by(user_id=current_user.id, status='pending').count()
    }
    return jsonify(stats)

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500


@app.errorhandler(403)
def forbidden_error(error):
    return render_template('403.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7070, debug=True)