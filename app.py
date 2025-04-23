--- START OF FILE app.py --- # type: ignore

from flask import Flask, render_template, request, redirect, url_for, flash # Removed unused session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from passlib.hash import bcrypt
import os
import datetime # For current year
from decimal import Decimal, InvalidOperation # For precise currency handling

app = Flask(__name__)
# Use environment variable or random bytes for SECRET_KEY
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', os.urandom(24))
# Use environment variable or default sqlite for DATABASE_URL
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///banking.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info' # Category for login_required flash message

# --- Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False, index=True) # Added index
    password_hash = db.Column(db.String(128), nullable=False)
    # Use String for balance to store precise Decimal values
    balance_str = db.Column(db.String(30), default='0.00', nullable=False) # Made non-nullable

    @property
    def balance(self):
        try:
            return Decimal(self.balance_str)
        except InvalidOperation:
             app.logger.error(f"Could not convert balance_str '{self.balance_str}' to Decimal for user {self.id}")
             return Decimal('0.00') # Return default on error

    @balance.setter
    def balance(self, value):
        # Ensure value is Decimal before storing as string
        if not isinstance(value, Decimal):
             try:
                 value = Decimal(str(value))
             except InvalidOperation:
                  app.logger.error(f"Invalid value '{value}' passed to balance setter for user {self.id}")
                  # Decide on error handling: raise exception or default? Defaulting is safer for state.
                  value = Decimal('0.00') # Or raise an appropriate error
        # Ensure two decimal places for storage consistency
        self.balance_str = "{:.2f}".format(value.quantize(Decimal("0.01")))


    def set_password(self, password):
        self.password_hash = bcrypt.hash(password)

    def check_password(self, password):
        try:
            # Ensure password_hash is a string before verification
            if isinstance(self.password_hash, str):
                 return bcrypt.verify(password, self.password_hash)
            else:
                 app.logger.warning(f"password_hash for user {self.id} is not a string.")
                 return False
        except (ValueError, TypeError) as e: # Handle potential bcrypt errors (e.g., malformed hash)
             app.logger.error(f"Bcrypt error checking password for user {self.id}: {e}")
             return False

# Transaction Model
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    type = db.Column(db.String(20), nullable=False) # e.g., 'creation', 'deposit', 'withdrawal', 'transfer_out', 'transfer_in'
    amount_str = db.Column(db.String(30), nullable=False) # Store amount related to the transaction
    related_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) # For transfers
    description = db.Column(db.String(200))
    new_balance_str = db.Column(db.String(30), nullable=False) # Balance *after* this transaction

    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('transactions', lazy=True, order_by="Transaction.timestamp.desc()"))
    related_user = db.relationship('User', foreign_keys=[related_user_id])

    @property
    def amount(self):
        try:
            return Decimal(self.amount_str)
        except InvalidOperation:
            app.logger.error(f"Could not convert amount_str '{self.amount_str}' to Decimal for transaction {self.id}")
            return Decimal('0.00')

    @property
    def new_balance(self):
        try:
             return Decimal(self.new_balance_str)
        except InvalidOperation:
             app.logger.error(f"Could not convert new_balance_str '{self.new_balance_str}' to Decimal for transaction {self.id}")
             return Decimal('0.00')

# --- Login Manager ---
@login_manager.user_loader
def load_user(user_id):
    try:
         # Use query.get which is optimized for primary key lookup
         return User.query.get(int(user_id))
    except (ValueError, TypeError):
         app.logger.warning(f"Invalid user_id format received: {user_id}")
         return None


# --- Helper Functions ---
def add_transaction(user_id, type, amount, new_balance, related_user_id=None, description=None, commit_now=False):
     """Logs a transaction to the database. Commits immediately if commit_now=True."""
     if not isinstance(amount, Decimal):
         try:
            amount = Decimal(str(amount))
         except InvalidOperation:
             app.logger.error(f"Invalid amount '{amount}' passed to add_transaction for user {user_id}")
             # Decide handling: raise error or default? Defaulting amount is risky. Raising is better.
             raise ValueError("Invalid amount for transaction logging")

     if not isinstance(new_balance, Decimal):
         try:
            new_balance = Decimal(str(new_balance))
         except InvalidOperation:
             app.logger.error(f"Invalid new_balance '{new_balance}' passed to add_transaction for user {user_id}")
             raise ValueError("Invalid new_balance for transaction logging")

     # Ensure amounts are correctly formatted
     amount_decimal = amount.quantize(Decimal("0.01"))
     new_balance_decimal = new_balance.quantize(Decimal("0.01"))

     trans = Transaction(
         user_id=user_id,
         type=type,
         # Always store positive amount in transaction log for clarity, type indicates direction
         amount_str="{:.2f}".format(amount_decimal.copy_abs()),
         new_balance_str="{:.2f}".format(new_balance_decimal),
         related_user_id=related_user_id,
         description=description,
         timestamp=datetime.datetime.utcnow() # Ensure timestamp is set now
     )
     db.session.add(trans)

     if commit_now:
         try:
             db.session.commit()
         except Exception as e:
             db.session.rollback()
             app.logger.error(f"Error committing transaction immediately: {e}")
             raise # Re-raise the exception after rollback


# --- Routes ---
@app.context_processor
def inject_current_year():
    """Inject current year into all templates."""
    return {'current_year': datetime.datetime.now().year}

@app.route('/')
def index():
    # Renders the main landing page (formerly Idbi.html)
    # Ensure this template has links/buttons to /login and /signup
    return render_template('Idbi.html') # Renamed for clarity maybe? Or keep as is.

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
         flash('You are already logged in.', 'info')
         return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower() # Use lowercase email
        password = request.form.get('password') # Don't strip password

        # Basic Validation
        if not name or not email or not password:
            flash('All fields are required.', 'danger')
            # Return render_template to preserve form data if needed, or redirect
            return redirect(url_for('signup'))

        # Add more robust validation (e.g., email format using regex, password strength) here if desired

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('An account with this email already exists. Please log in.', 'warning')
            return redirect(url_for('login')) # Redirect to login might be better UX

        # Create user
        new_user = User(name=name, email=email)
        new_user.set_password(password)
        # Initial balance is set by default='0.00' in model

        try:
            db.session.add(new_user)
            db.session.flush() # Assign an ID to new_user without committing yet

            # Log initial account creation transaction *after* getting ID
            add_transaction(
                user_id=new_user.id,
                type='creation',
                amount=Decimal('0.00'),
                new_balance=new_user.balance, # Use the property getter
                description='Account created'
            )
            db.session.commit() # Commit user and transaction together

            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error creating account for email {email}: {e}")
            flash('An error occurred while creating your account. Please try again later.', 'danger')
            return redirect(url_for('signup')) # Redirect on error

    return render_template('IdbiSign.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
         return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password') # Don't strip password

        if not email or not password:
             flash('Email and password are required.', 'danger')
             return redirect(url_for('login'))

        # Find user by email (case-insensitive due to storing lowercase)
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            remember_me = request.form.get('remember') == 'on' # Check if remember me checkbox exists/is checked
            login_user(user, remember=remember_me)
            flash(f'Login successful! Welcome back, {user.name}.', 'success')

            # Log login event (optional, could be a separate log file or DB table)
            # app.logger.info(f"User {user.email} logged in.")

            # Redirect to intended page if available, otherwise dashboard
            next_page = request.args.get('next')
            # Basic security check for open redirect vulnerability
            if next_page and not next_page.startswith('/'):
                 next_page = None # Discard potentially malicious 'next' URL
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid email or password. Please try again.', 'danger')
            # Don't reveal if email exists or password was wrong for security
            app.logger.warning(f"Failed login attempt for email: {email}")
            return redirect(url_for('login'))

    return render_template('idbilogin.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Fetch recent transactions for display
    try:
        transactions = Transaction.query.filter_by(user_id=current_user.id)\
                                       .order_by(Transaction.timestamp.desc())\
                                       .limit(10)\
                                       .all()
    except Exception as e:
        app.logger.error(f"Error fetching transactions for user {current_user.id}: {e}")
        transactions = []
        flash("Could not load recent transaction history.", "warning")

    return render_template('IDBIbank.html', user=current_user, transactions=transactions)

@app.route('/logout')
@login_required
def logout():
    # Log logout event (optional)
    # app.logger.info(f"User {current_user.email} logged out.")
    logout_user()
    flash('You have been successfully logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/transfer', methods=['POST'])
@login_required
def transfer():
    recipient_email = request.form.get('email', '').strip().lower()
    amount_str = request.form.get('amount', '').strip()

    # --- Input Validation ---
    if not recipient_email:
        flash('Recipient email is required.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        amount = Decimal(amount_str)
        # Ensure positive amount with 2 decimal places max implicitly handled by quantize later
        if amount <= Decimal('0.00'):
            raise ValueError("Amount must be positive.")
        if amount.as_tuple().exponent < -2:
             raise ValueError("Amount cannot have more than two decimal places.")
    except (InvalidOperation, ValueError) as e:
        flash(f'Invalid amount: {e}. Please enter a positive number (e.g., 10.50).', 'danger')
        return redirect(url_for('dashboard'))

    # Standardize amount to 2 decimal places for calculations
    amount = amount.quantize(Decimal("0.01"))

    # --- Transaction Logic ---
    if recipient_email == current_user.email:
        flash('You cannot transfer funds to your own account.', 'warning')
        return redirect(url_for('dashboard'))

    # Get fresh sender object within the transaction scope for accurate balance
    sender = User.query.get(current_user.id)
    if not sender:
         flash('Error retrieving your account data. Please log out and back in.', 'danger')
         app.logger.error(f"Could not find sender user with id {current_user.id} during transfer.")
         return redirect(url_for('dashboard'))

    recipient = User.query.filter_by(email=recipient_email).first()
    if not recipient:
        flash(f'Recipient with email "{recipient_email}" not found.', 'danger')
        return redirect(url_for('dashboard'))

    if sender.balance < amount:
        flash(f'Insufficient funds. Your balance is ${sender.balance:.2f}.', 'danger')
        return redirect(url_for('dashboard'))

    # --- Perform Transfer Atomically ---
    try:
        sender_new_balance = sender.balance - amount
        recipient_new_balance = recipient.balance + amount

        # Update balances using the setter (which handles string conversion)
        sender.balance = sender_new_balance
        recipient.balance = recipient_new_balance

        # Log transactions for both parties *before* commit
        # Note: amount is positive, type indicates direction
        add_transaction(
            user_id=sender.id, type='transfer_out', amount=amount, new_balance=sender_new_balance,
            related_user_id=recipient.id, description=f"Transfer to {recipient.email}"
        )
        add_transaction(
            user_id=recipient.id, type='transfer_in', amount=amount, new_balance=recipient_new_balance,
            related_user_id=sender.id, description=f"Transfer from {sender.email}"
        )

        db.session.commit() # Commit all changes (user balances, transactions) together
        flash(f'Successfully transferred ${amount:.2f} to {recipient.name} ({recipient.email}).', 'success')

    except Exception as e:
        db.session.rollback() # Roll back changes on any error
        app.logger.error(f"Error during transfer from {sender.email} to {recipient.email}: {e}")
        flash('An unexpected error occurred during the transfer. Please try again later or contact support.', 'danger')

    return redirect(url_for('dashboard'))


# --- Placeholder Routes from Homepage ---
# These should ideally point to actual pages or features when implemented
@app.route('/locations')
def find_location():
     flash('Branch locator functionality coming soon!', 'info')
     # Redirect back to index, potentially to a specific section if your landing page has IDs
     return redirect(url_for('index', _anchor='branch')) # Assuming Idbi.html has id="branch"

@app.route('/search')
def search():
    query = request.args.get('query', '')
    # Placeholder - Implement search logic across site content or features
    flash(f"Search functionality for '{query}' is not yet implemented.", 'info')
    return redirect(url_for('index'))

@app.route('/privacy')
def privacy_policy():
     # Placeholder - Render a template with the policy
     # return render_template('privacy.html')
     flash("Privacy Policy page coming soon.", "info")
     return redirect(url_for('index'))


@app.route('/terms')
def terms_service():
     # Placeholder - Render a template
     # return render_template('terms.html')
     flash("Terms of Service page coming soon.", "info")
     return redirect(url_for('index'))


@app.route('/careers')
def careers():
      # Placeholder - Render a template or redirect to external site
     # return render_template('careers.html')
     flash("Careers page coming soon.", "info")
     return redirect(url_for('index'))


# --- Error Handling (Optional but Recommended) ---
@app.errorhandler(404)
def page_not_found(e):
    # Log the error e if needed
    app.logger.warning(f"404 Not Found: {request.path}")
    return render_template('404.html'), 404 # Create a templates/404.html file

@app.errorhandler(500)
def internal_server_error(e):
     # Log the actual error e
     app.logger.error(f"500 Internal Server Error: {e}", exc_info=True) # Log stack trace
     db.session.rollback() # Rollback session in case of DB error during request
     return render_template('500.html'), 500 # Create a templates/500.html file


# --- Main Execution ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Create tables if they don't exist based on models
        # You could add code here to create an initial admin user if needed
    # Set debug=False for production
    # Use host='0.0.0.0' to be accessible on your network (e.g., for testing from other devices)
    # Use port=os.environ.get("PORT", 5000) for deployment platforms like Heroku
    app.run(debug=os.environ.get('FLASK_DEBUG', 'True') == 'True',
            host=os.environ.get('FLASK_RUN_HOST', '127.0.0.1'),
            port=int(os.environ.get('FLASK_RUN_PORT', 5000)))# Use debug=False in production, host='0.0.0.0' to make accessible on network