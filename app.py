from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from wtforms import Form, StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_file}')"

class Orphanage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f"Orphanage('{self.name}', '{self.location}')"

class Orphan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text, nullable=False)
    orphanage_id = db.Column(db.Integer, db.ForeignKey('orphanage.id'), nullable=True)

    def __repr__(self):
        return f"Orphan('{self.name}', '{self.age}')"

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class OrphanageForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    location = StringField('Location', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    submit = SubmitField('Add Orphanage')

class OrphanForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    age = StringField('Age', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    submit = SubmitField('Add Orphan')

class SearchForm(FlaskForm):
    location = StringField('Location', validators=[DataRequired()])
    submit = SubmitField('Search')

@app.route('/')
@app.route('/home', methods=['GET', 'POST'])
def home():
    form = SearchForm()
    orphanages = Orphanage.query.all()
    if form.validate_on_submit():
        orphanages = Orphanage.query.filter(Orphanage.location.contains(form.location.data)).all()
    return render_template('home.html', form=form, orphanages=orphanages)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/orphanages', methods=['GET', 'POST'])
@login_required
def orphanages():
    form = OrphanageForm()
    if form.validate_on_submit():
        orphanage = Orphanage(name=form.name.data, location=form.location.data, description=form.description.data)
        db.session.add(orphanage)
        db.session.commit()
        flash('Orphanage has been added!', 'success')
        return redirect(url_for('home'))
    orphanages = Orphanage.query.all()
    return render_template('add_orphanage.html', title='Orphanages', form=form, orphanages=orphanages)

@app.route('/orphans', methods=['GET', 'POST'])
@login_required
def orphans():
    form = OrphanForm()
    if form.validate_on_submit():
        orphan = Orphan(name=form.name.data, age=form.age.data, description=form.description.data)
        db.session.add(orphan)
        db.session.commit()
        flash('Orphan has been added!', 'success')
        return redirect(url_for('home'))
    orphans = Orphan.query.all()
    return render_template('orphan.html', title='Orphans', form=form, orphans=orphans)

@app.route('/search', methods=['GET', 'POST'])
def search():
    form = SearchForm()
    orphanages = []
    if form.validate_on_submit():
        orphanages = Orphanage.query.filter(Orphanage.location.contains(form.location.data)).all()
    return render_template('search.html', title='Search', form=form, orphanages=orphanages)

if __name__ == '__main__':
    app.run(debug=True)
