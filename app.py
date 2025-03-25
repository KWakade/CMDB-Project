"""
Flask application for managing a server inventory - Optimized Version
"""
import os
import pandas as pd
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename

# Import models and db from DB.py
from DB import db, User, Server

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads/'

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)

# Initialize db with app
db.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Forms
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('User Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', 
                                   validators=[DataRequired(), EqualTo('password')])
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
        if user and user.check_password(form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            flash('Login successful!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        flash('Login unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        if User.query.filter((User.username == form.username.data) | 
                           (User.email == form.email.data)).first():
            flash('Username/email already exists!', 'danger')
            return redirect(url_for('register'))
        
        new_user = User(username=form.username.data, email=form.email.data)
        new_user.set_password(form.password.data)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

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
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            try:
                df = pd.read_csv(filepath)
                for _, row in df.iterrows():
                    server = Server(
                        name=row['name'],
                        ip_address=row['ip_address'],
                        operating_system=row['operating_system'],
                        owner=row['owner']
                    )
                    db.session.add(server)
                db.session.commit()
                flash('File uploaded and processed successfully!', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'Error processing file: {str(e)}', 'danger')
            finally:
                if os.path.exists(filepath):
                    os.remove(filepath)
                    
            return redirect(url_for('index'))
            
        flash('Invalid file format. Please upload a CSV file.', 'danger')
    return render_template('upload.html')

@app.route('/add_server', methods=['GET', 'POST'])
@login_required
def add_server():
    form = ServerForm()
    if form.validate_on_submit():
        server = Server(
            name=form.name.data,
            ip_address=form.ip_address.data,
            operating_system=form.operating_system.data,
            owner=form.owner.data
        )
        db.session.add(server)
        db.session.commit()
        flash('Server added successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('add_server.html', form=form)

@app.route('/edit_server/<int:server_id>', methods=['GET', 'POST'])
@login_required
def edit_server(server_id):
    server = Server.query.get_or_404(server_id)
    form = ServerForm(obj=server)
    if form.validate_on_submit():
        form.populate_obj(server)
        db.session.commit()
        flash('Server updated successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('edit_server.html', form=form, server=server)

@app.route('/delete_server/<int:server_id>', methods=['POST'])
@login_required
def delete_server(server_id):
    server = Server.query.get_or_404(server_id)
    db.session.delete(server)
    db.session.commit()
    flash('Server deleted successfully!', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)