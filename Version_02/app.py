import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# --- Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'executive-secure-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///executive_todos.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Extensions ---
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- Database Models ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    # Relationship: One user has many todos
    todos = db.relationship('Todo', backref='author', lazy=True)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    is_complete = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --- Loader ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Auth Routes ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user_exists = User.query.filter_by(username=username).first()
        if user_exists:
            flash('Username already exists.', 'danger')
        elif not username or not password:
            flash('Please fill out all fields.', 'warning')
        else:
            hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, password_hash=hashed_pw)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created! Please login.', 'success')
            return redirect(url_for('login'))
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Login successful.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials.', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# --- Application Routes ---

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        
        if not title:
            flash('Task title is required.', 'warning')
        else:
            new_todo = Todo(title=title, description=description, author=current_user)
            db.session.add(new_todo)
            db.session.commit()
            flash('Task added successfully.', 'success')
            return redirect(url_for('dashboard'))

    # Sort by creation date (newest first)
    todos = Todo.query.filter_by(user_id=current_user.id).order_by(Todo.created_at.desc()).all()
    return render_template('dashboard.html', todos=todos)

@app.route('/toggle/<int:id>')
@login_required
def toggle_todo(id):
    todo = Todo.query.get_or_404(id)
    if todo.author != current_user:
        abort(403)
        
    todo.is_complete = not todo.is_complete
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/delete/<int:id>')
@login_required
def delete_todo(id):
    todo = Todo.query.get_or_404(id)
    if todo.author != current_user:
        abort(403)
        
    db.session.delete(todo)
    db.session.commit()
    flash('Task deleted.', 'info')
    return redirect(url_for('dashboard'))

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_todo(id):
    todo = Todo.query.get_or_404(id)
    if todo.author != current_user:
        abort(403)
    
    if request.method == 'POST':
        todo.title = request.form.get('title')
        todo.description = request.form.get('description')
        db.session.commit()
        flash('Task updated.', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('edit_todo.html', todo=todo)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)