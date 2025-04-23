# app.py
# type: ignore

import os
import datetime
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from passlib.hash import bcrypt
from dotenv import load_dotenv
from sqlalchemy import Index

load_dotenv()

app = Flask(__name__)

# --- Configuration ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-very-insecure-default-key-please-change')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///instance/banking.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- !!! SET MINIMUM BALANCE REQUIREMENT HERE (or in .env) !!! ---
# Example: Set minimum required balance to 100.00 (Use Decimal)
MINIMUM_BALANCE_REQUIRED = Decimal(os.environ.get('MINIMUM_BALANCE', '100.00'))
# Note: For the "must deposit first" rule, we start balance at 0 and rely on checks

instance_path = os.path.join(app.root_path, 'instance')
if not os.path.exists(instance_path) and app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite:///instance'):
    try: os.makedirs(instance_path)
    except OSError as e: app.logger.error(f"Failed to create instance folder: {e}")

# --- Extensions Initialization ---
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# --- Database Models ---
# (User and Transaction models remain exactly the same as in Response #14)
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(20), unique=True, nullable=True, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    balance_str = db.Column(db.String(30), default='0.00', nullable=False) # Start at 0
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    __table_args__ = ( Index('ix_users_email', 'email', unique=True), Index('ix_users_phone', 'phone', unique=True), )

    @property
    def balance(self):
        try: return Decimal(self.balance_str).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        except (InvalidOperation, TypeError): return Decimal('0.00')

    @balance.setter
    def balance(self, value):
        if not isinstance(value, Decimal):
             try: value = Decimal(str(value))
             except (InvalidOperation, TypeError): value = Decimal('0.00')
        self.balance_str = "{:.2f}".format(value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))

    def set_password(self, password):
        if not password: raise ValueError("Password cannot be empty")
        self.password_hash = bcrypt.hash(password)

    def check_password(self, password):
        if not self.password_hash or not password: return False
        try: return bcrypt.verify(password, self.password_hash)
        except (ValueError, TypeError): return False

    def __repr__(self): return f"<User {self.id}: {self.name} ({self.email})>"

class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', name='fk_transaction_user'), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False, index=True)
    type = db.Column(db.String(20), nullable=False)
    amount_str = db.Column(db.String(30), nullable=False)
    related_user_id = db.Column(db.Integer, db.ForeignKey('users.id', name='fk_transaction_related_user'), nullable=True)
    description = db.Column(db.String(200))
    new_balance_str = db.Column(db.String(30), nullable=False)

    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('transactions', lazy='dynamic', order_by="desc(Transaction.timestamp)"))
    related_user = db.relationship('User', foreign_keys=[related_user_id])

    @property
    def amount(self):
        try: return Decimal(self.amount_str).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        except (InvalidOperation, TypeError): return Decimal('0.00')

    @property
    def new_balance(self):
        try: return Decimal(self.new_balance_str).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        except (InvalidOperation, TypeError): return Decimal('0.00')

    def __repr__(self): return f"<Transaction {self.id}: User {self.user_id} - {self.type} {self.amount_str}>"


# --- Login Manager ---
@login_manager.user_loader
def load_user(user_id):
    try: return User.query.get(int(user_id))
    except (ValueError, TypeError): return None

# --- Helper Functions ---
# (add_transaction function remains the same as in Response #14)
def add_transaction(user_id, type, amount, new_balance, related_user_id=None, description=None, commit_now=False):
     try:
         if not isinstance(amount, Decimal): amount = Decimal(str(amount))
         if not isinstance(new_balance, Decimal): new_balance = Decimal(str(new_balance))

         amount_decimal = amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
         new_balance_decimal = new_balance.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

         trans = Transaction(
             user_id=user_id, timestamp=datetime.datetime.utcnow(), type=type,
             amount_str="{:.2f}".format(amount_decimal.copy_abs()),
             new_balance_str="{:.2f}".format(new_balance_decimal),
             related_user_id=related_user_id, description=description
         )
         db.session.add(trans)
         if commit_now: db.session.commit()
     except (InvalidOperation, TypeError, ValueError) as e:
         db.session.rollback()
         app.logger.error(f"Transaction Logging Error (Data): User {user_id}, {e}")
         raise ValueError(f"Invalid data for transaction logging: {e}")
     except Exception as e:
         db.session.rollback()
         app.logger.error(f"Transaction Logging Error (Commit): User {user_id}, {e}", exc_info=True)
         raise

# (validate_amount function remains the same as in Response #14)
def validate_amount(amount_str):
    """Validates and converts amount string to Decimal. Returns (Decimal, error_message)."""
    try:
        amount = Decimal(amount_str).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        if amount <= Decimal('0.00'): return None, "Amount must be positive."
        return amount, None
    except (InvalidOperation, TypeError): return None, "Invalid amount format entered."


# --- Context Processors ---
@app.context_processor
def inject_global_vars():
    return {
        'current_year': datetime.datetime.now().year,
        'current_user_name': current_user.name if current_user.is_authenticated else None
    }

# --- Routes ---
@app.route('/')
def index(): return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # (Signup logic remains mostly the same as Response #14, ensuring initial balance is 0)
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password')

        errors = {}
        if not name: errors['name'] = 'Name required.'
        if not email: errors['email'] = 'Email required.'
        if not phone: errors['phone'] = 'Phone required.'
        elif not phone.isdigit() or len(phone) < 10: errors['phone'] = 'Invalid phone.'
        if not password: errors['password'] = 'Password required.'
        elif len(password) < 8: errors['password'] = 'Password min 8 chars.'

        if not errors:
            if User.query.filter_by(email=email).first(): errors['email'] = 'Email exists.'
            if phone and User.query.filter_by(phone=phone).first(): errors['phone'] = 'Phone exists.'

        if errors:
             for msg in errors.values(): flash(msg, 'danger')
             return render_template('signup.html', errors=errors, form_data=request.form)

        try:
            new_user = User(name=name, email=email, phone=phone)
            new_user.set_password(password)
            new_user.balance = Decimal('0.00') # Explicitly start at 0

            db.session.add(new_user)
            db.session.flush()

            add_transaction(
                user_id=new_user.id, type='creation', amount=Decimal('0.00'),
                new_balance=new_user.balance, description='Account created', commit_now=False
            )
            db.session.commit()
            flash('Account created! Please log in and make an initial deposit.', 'success') # Modified flash
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Signup Error: {e}", exc_info=True)
            flash('Signup failed. Please try again.', 'danger')
            return render_template('signup.html', errors=errors, form_data=request.form)

    return render_template('signup.html', errors={}, form_data={})

@app.route('/login', methods=['GET', 'POST'])
def login():
    # (Login logic remains the same as Response #14)
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        login_identifier = request.form.get('login_identifier', '').strip()
        password = request.form.get('password')
        remember_me = request.form.get('remember') == 'on'

        if not login_identifier or not password:
             flash('Email/Phone and password are required.', 'danger')
             return render_template('login.html', login_identifier=login_identifier)

        user = User.query.filter( (User.email == login_identifier.lower()) | (User.phone == login_identifier) ).first()

        if user and user.check_password(password):
            login_user(user, remember=remember_me)
            flash(f'Welcome back, {user.name}!', 'success')
            next_page = request.args.get('next')
            if next_page and (not next_page.startswith('/') or next_page.startswith('//')): next_page = None
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid credentials.', 'danger')
            return render_template('login.html', login_identifier=login_identifier)

    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    # (Dashboard logic remains the same as Response #14)
    try: transactions = current_user.transactions.limit(15).all()
    except Exception as e:
        app.logger.error(f"Transaction Fetch Error: User {current_user.id}, {e}", exc_info=True)
        transactions = []
        flash("Could not load transaction history.", "warning")
    # Add a check for initial deposit needed
    initial_deposit_needed = current_user.balance == Decimal('0.00') and not current_user.transactions.filter_by(type='deposit').first()
    if initial_deposit_needed:
        flash('Welcome! Please make an initial deposit to activate withdrawals and transfers.', 'info')

    return render_template('dashboard.html', user=current_user, transactions=transactions, initial_deposit_needed=initial_deposit_needed)


@app.route('/logout')
@login_required
def logout():
    # (Logout logic remains the same as Response #14)
    logout_user()
    flash('You have been successfully logged out.', 'success')
    return redirect(url_for('index'))


@app.route('/deposit', methods=['POST'])
@login_required
def deposit():
    # (Deposit logic remains the same as Response #14)
    amount_str = request.form.get('amount', '').strip()
    amount, error = validate_amount(amount_str)
    if error:
        flash(f'Invalid deposit amount: {error}', 'danger')
        return redirect(url_for('dashboard'))
    user = User.query.get(current_user.id)
    if not user: return redirect(url_for('login'))
    try:
        new_balance = user.balance + amount
        user.balance = new_balance
        add_transaction(user_id=user.id, type='deposit', amount=amount, new_balance=new_balance, description='User deposit')
        db.session.commit()
        flash(f'Deposited ₹{amount:.2f}. New balance: ₹{new_balance:.2f}.', 'success')
    except Exception as e:
        db.session.rollback(); app.logger.error(f"Deposit Error: User {user.email}, {e}", exc_info=True)
        flash('Deposit failed.', 'danger')
    return redirect(url_for('dashboard'))


@app.route('/withdraw', methods=['POST'])
@login_required
def withdraw():
    # --- Check if initial deposit has been made ---
    if current_user.balance == Decimal('0.00') and not current_user.transactions.filter_by(type='deposit').first():
         flash('Please make an initial deposit before withdrawing funds.', 'warning')
         return redirect(url_for('dashboard'))

    amount_str = request.form.get('amount', '').strip()
    amount, error = validate_amount(amount_str)
    if error:
        flash(f'Invalid withdrawal amount: {error}', 'danger')
        return redirect(url_for('dashboard'))

    user = User.query.get(current_user.id)
    if not user: return redirect(url_for('login'))

    # --- Check minimum balance ---
    if (user.balance - amount) < MINIMUM_BALANCE_REQUIRED:
         flash(f'Withdrawal failed. Balance cannot go below ₹{MINIMUM_BALANCE_REQUIRED:.2f}. Current Balance: ₹{user.balance:.2f}', 'danger')
         return redirect(url_for('dashboard'))

    # (Redundant check, but safe)
    if user.balance < amount:
        flash(f'Insufficient funds. Balance: ₹{user.balance:.2f}.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        new_balance = user.balance - amount
        user.balance = new_balance
        add_transaction(user_id=user.id, type='withdrawal', amount=amount, new_balance=new_balance, description='User withdrawal')
        db.session.commit()
        flash(f'Withdrew ₹{amount:.2f}. New balance: ₹{new_balance:.2f}.', 'success')
    except Exception as e:
        db.session.rollback(); app.logger.error(f"Withdrawal Error: User {user.email}, {e}", exc_info=True)
        flash('Withdrawal failed.', 'danger')

    return redirect(url_for('dashboard'))


@app.route('/transfer', methods=['POST'])
@login_required
def transfer():
    # --- Check if initial deposit has been made ---
    if current_user.balance == Decimal('0.00') and not current_user.transactions.filter_by(type='deposit').first():
         flash('Please make an initial deposit before transferring funds.', 'warning')
         return redirect(url_for('dashboard'))

    recipient_identifier = request.form.get('recipient_identifier', '').strip()
    amount_str = request.form.get('amount', '').strip()
    amount, error = validate_amount(amount_str)

    if not recipient_identifier: flash('Recipient Email/Phone required.', 'danger'); return redirect(url_for('dashboard'))
    if error: flash(f'Invalid transfer amount: {error}', 'danger'); return redirect(url_for('dashboard'))

    sender = User.query.get(current_user.id)
    if not sender: return redirect(url_for('login'))

    if recipient_identifier.lower() == sender.email or recipient_identifier == sender.phone:
        flash('Cannot transfer to yourself.', 'warning'); return redirect(url_for('dashboard'))

    recipient = User.query.filter( (User.email == recipient_identifier.lower()) | (User.phone == recipient_identifier) ).first()
    if not recipient: flash(f'Recipient "{recipient_identifier}" not found.', 'danger'); return redirect(url_for('dashboard'))

    # --- Check minimum balance for sender ---
    if (sender.balance - amount) < MINIMUM_BALANCE_REQUIRED:
        flash(f'Transfer failed. Your balance cannot go below ₹{MINIMUM_BALANCE_REQUIRED:.2f}. Current Balance: ₹{sender.balance:.2f}', 'danger')
        return redirect(url_for('dashboard'))

    # (Redundant check, but safe)
    if sender.balance < amount:
        flash(f'Insufficient funds. Balance: ₹{sender.balance:.2f}.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        sender_new_balance = sender.balance - amount
        recipient_new_balance = recipient.balance + amount
        sender.balance = sender_new_balance
        recipient.balance = recipient_new_balance
        add_transaction( user_id=sender.id, type='transfer_out', amount=amount, new_balance=sender_new_balance, related_user_id=recipient.id, description=f"Transfer to {recipient.name}" )
        add_transaction( user_id=recipient.id, type='transfer_in', amount=amount, new_balance=recipient_new_balance, related_user_id=sender.id, description=f"Transfer from {sender.name}" )
        db.session.commit()
        flash(f'Transferred ₹{amount:.2f} to {recipient.name}.', 'success')
    except Exception as e:
        db.session.rollback(); app.logger.error(f"Transfer Error: From {sender.email} To {recipient_identifier}, {e}", exc_info=True)
        flash('Transfer failed.', 'danger')

    return redirect(url_for('dashboard'))

# --- Static Info Routes & Error Handlers ---
# (Keep these the same as Response #14)
@app.route('/locations')
def locations(): return redirect(url_for('index', _anchor='branch'))
# ... other static routes ...
@app.route('/terms')
def terms(): flash("Terms of Service page coming soon.", "info"); return redirect(url_for('index'))

@app.errorhandler(404)
def page_not_found(e): return render_template('404.html'), 404
@app.errorhandler(500)
def internal_server_error(e):
     app.logger.error(f"500 Internal Server Error: {e}", exc_info=True)
     try: db.session.rollback()
     except Exception: pass
     return render_template('500.html'), 500

# --- CLI Command & Main Execution ---
# (Keep these the same as Response #14)
@app.cli.command('init-db')
def init_db_command():
    """Creates database tables."""
    try: db.create_all(); print('Database tables created.')
    except Exception as e: print(f'DB Init Error: {e}')

if __name__ == '__main__':
    with app.app_context():
        try: # Create DB if it doesn't exist
            db_uri = app.config['SQLALCHEMY_DATABASE_URI']
            if db_uri.startswith('sqlite:///'):
                db_path = db_uri.split('sqlite:///')[-1]
                if not os.path.exists(os.path.join(app.root_path, db_path)): db.create_all()
        except Exception as e: app.logger.error(f"DB Creation Check Error: {e}", exc_info=True)
    host = os.environ.get('FLASK_RUN_HOST', '127.0.0.1')
    port = int(os.environ.get('FLASK_RUN_PORT', 5000))
    debug_mode = os.environ.get('FLASK_DEBUG', 'True').lower() in ['true', '1', 't']
    app.run(host=host, port=port, debug=debug_mode)