# app.py

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_bcrypt import Bcrypt
import jwt
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Guru@123'  # Change this to a random secret key
bcrypt = Bcrypt()

# Sample user storage (replace with a database in production)
users = []

class SignUpForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Create Account')

class SignInForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class User:
    def __init__(self, username, password):
        self.username = username
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

def generate_token(user):
    payload = {
        'exp': datetime.utcnow() + timedelta(days=1),
        'iat': datetime.utcnow(),
        'sub': user.username
    }
    token = jwt.encode(payload, 'your_jwt_secret', algorithm='HS256')
    return token

def verify_token(token):
    try:
        payload = jwt.decode(token, 'your_jwt_secret', algorithms=['HS256'])
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return 'Token has expired. Please sign in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please sign in again.'

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUpForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        if any(user.username == username for user in users):
            flash('Username already exists. Choose a different one.', 'danger')
        else:
            new_user = User(username, password)
            users.append(new_user)
            flash('Account created successfully. Please sign in.', 'success')
            return redirect(url_for('signin'))

    return render_template('signup.html', form=form)

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    form = SignInForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = next((user for user in users if user.username == username), None)

        if user and bcrypt.check_password_hash(user.password, password):
            token = generate_token(user)
            flash('Welcome! You have successfully signed in.', 'success')
            return render_template('welcome.html', token=token)
        else:
            flash('Invalid username or password. Please try again.', 'danger')

    return render_template('signin.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)
