"""
This is a Flask application for managing a server inventory.
"""
import os
import pandas as pd
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_bcrypt import Bcrypt
from DB import User, db  # Import from DB.py
from werkzeug.security import generate_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads/'

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
migrate = Migrate(app, db)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Database Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(15), nullable=False)
    operating_system = db.Column(db.String(50), nullable=False)
    owner = db.Column(db.String(50), nullable=False)

# Forms
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('User Name', validators=[DataRequired(), Email()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class ServerForm(FlaskForm):
    name = StringField('Server Name', validators=[DataRequired()])
    ip_address = StringField('IP Address', validators=[DataRequired()])
    operating_system = StringField('Operating System', validators=[DataRequired()])
    owner = StringField('Owner', validators=[DataRequired()])
    submit = SubmitField('Submit')

# Routes
@app.route('/')
@login_required
def index():
    servers = Server.query.all()
    return render_template('index.html', servers=servers)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            flash('Login successful!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)

from DB import User, db  # Import from DB.py
from werkzeug.security import generate_password_hash

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])  # Hash password

        # Check if user exists (using your DB.py model)
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username/email already exists!', 'error')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registered successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/bulk_upload', methods=['GET', 'POST'])
@login_required
def bulk_upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        if file and file.filename.endswith('.csv'):
            filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(filename)
            
            # Process CSV file
            df = pd.read_csv(filename)
            for _, row in df.iterrows():
                new_server = Server(
                    name=row['name'],
                    ip_address=row['ip_address'],
                    operating_system=row['operating_system'],
                    owner=row['owner']
                )
                db.session.add(new_server)
            db.session.commit()
            
            flash('File successfully uploaded and data inserted.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid file format. Please upload a CSV file.', 'danger')
            return redirect(request.url)
    return render_template('upload.html')

@app.route('/add_server', methods=['GET', 'POST'])
@login_required
def add_server():
    form = ServerForm()
    if form.validate_on_submit():
        new_server = Server(
            name=form.name.data,
            ip_address=form.ip_address.data,
            operating_system=form.operating_system.data,
            owner=form.owner.data
        )
        db.session.add(new_server)
        db.session.commit()
        flash('Server added successfully!','success')
        return redirect(url_for('index'))
    return render_template('add_server.html', form=form)

@app.route('/edit_server/<int:server_id>', methods=['GET', 'POST'])
@login_required
def edit_server(server_id):
    server = Server.query.get_or_404(server_id)
    form = ServerForm(obj=server)
    if form.validate_on_submit():
        server.name = form.name.data
        server.ip_address = form.ip_address.data
        server.operating_system = form.operating_system.data
        server.owner = form.owner.data
        db.session.commit()
        flash('Server details updated successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('edit_server.html', form=form)

@app.route('/delete_server/<int:server_id>', methods=['POST'])
@login_required
def delete_server(server_id):
    server = Server.query.get_or_404(server_id)
    db.session.delete(server)
    db.session.commit()
    flash('Server deleted successfully!', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
