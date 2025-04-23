from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from passlib.hash import bcrypt # For password hashing
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Keep this secret in production
# Use absolute path for the database file
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'banking.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Route name for the login page
login_manager.login_message_category = 'info' # Flash message category for login_required

# --- Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    # Using Numeric for precision with currency is often better than Float
    balance = db.Column(db.Numeric(10, 2), default=10000.00) # Default balance

    def set_password(self, password):
        # Generate hash with default rounds (recommended)
        self.password_hash = bcrypt.hash(password)

    def check_password(self, password):
        # Ensure password_hash is not None before verifying
        if self.password_hash is None:
            return False
        try:
            return bcrypt.verify(password, self.password_hash)
        except (ValueError, TypeError):
            # Handle cases where hash might be malformed or incompatible
            return False

    def __repr__(self):
        return f'<User {self.name} ({self.email})>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes ---
@app.route('/')
def index():
    # Redirect logged-in users to dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Basic Validation
        if not name or not email or not password or not confirm_password:
            flash('All fields are required!', 'danger')
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('signup'))

        # Demo Mode Check (Keep or remove as needed)
        if User.query.first():
            flash('Demo Mode: Only one user account is allowed.', 'warning')
            return redirect(url_for('login'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email address already registered.', 'warning')
            return redirect(url_for('signup'))

        # Create User
        new_user = User(name=name, email=email)
        new_user.set_password(password) # Hash the password

        try:
            db.session.add(new_user)
            db.session.commit()
            flash(f'Account created successfully for {name}! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error creating user: {e}") # Log the error
            flash('An error occurred during signup. Please try again.', 'danger')
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash('Please enter both email and password.', 'danger')
            return redirect(url_for('login'))

        user = User.query.filter_by(email=email).first()

        # Use the check_password method
        if user and user.check_password(password):
            login_user(user) # Handles session management
            flash(f'Welcome back, {user.name}!', 'success')
            # Redirect to intended page or dashboard
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid email or password. Please try again.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/dashboard')
@login_required # Protects this route
def dashboard():
    # Pass the current user object to the template
    return render_template('dashboard.html', user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user() # Clears the user session
    flash('You have been successfully logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/transfer', methods=['POST'])
@login_required
def transfer():
    recipient_email = request.form.get('recipient_email')
    amount_str = request.form.get('amount')

    # --- Input Validation ---
    if not recipient_email or not amount_str:
        flash('Please enter recipient email and amount.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        amount = float(amount_str) # Use float or Decimal depending on precision needs
    except ValueError:
        flash('Invalid amount entered. Please enter a number.', 'danger')
        return redirect(url_for('dashboard'))

    if amount <= 0:
        flash('Transfer amount must be positive.', 'danger')
        return redirect(url_for('dashboard'))

    # Format amount for comparison and display (optional but good)
    amount = round(amount, 2)

    # --- Recipient Check ---
    recipient = User.query.filter(User.email == recipient_email, User.id != current_user.id).first()
    # Alternate way to check self-transfer:
    # recipient = User.query.filter_by(email=recipient_email).first()
    # if recipient and recipient.id == current_user.id:
    #     flash('You cannot transfer money to yourself.', 'warning')
    #     return redirect(url_for('dashboard'))

    if not recipient:
        # Check if email exists but belongs to the current user
        if User.query.filter_by(email=recipient_email).first():
             flash('You cannot transfer money to yourself.', 'warning')
        else:
             flash('Recipient email address not found.', 'danger')
        return redirect(url_for('dashboard'))


    # --- Balance Check ---
    # Explicitly cast balance to float for comparison if needed (if using Numeric/Decimal)
    if float(current_user.balance) < amount:
        flash('Insufficient balance to complete the transfer.', 'danger')
        return redirect(url_for('dashboard'))

    # --- Perform Transfer (Transaction) ---
    try:
        # Important: Perform updates within the same transaction
        current_user.balance -= amount
        recipient.balance += amount
        db.session.commit() # Commit both changes together
        flash(f'Successfully transferred ₹{amount:.2f} to {recipient.name} ({recipient.email}).', 'success')
    except Exception as e:
        db.session.rollback() # Rollback if any error occurs
        app.logger.error(f"Error during transfer: {e}")
        flash('An error occurred during the transfer. Please try again.', 'danger')

    return redirect(url_for('dashboard'))

# --- Utility ---
def create_db():
    """Creates database tables if they don't exist."""
    with app.app_context():
        print("Creating database tables...")
        db.create_all()
        print("Database tables created (if they didn't exist).")

if __name__ == '__main__':
    create_db() # Create tables before running the app
    app.run(debug=True) # Enable debug mode for development
