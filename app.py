from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from datetime import datetime
from flask_migrate import Migrate
from flask_login import UserMixin
from flask import render_template, url_for, flash, redirect, request
from flask_login import login_user, current_user, logout_user, login_required


app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:ashish210901@127.0.0.1/users'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'ibm_db_sa://rfs19780:D2Ky156OxjrASE8s@2f3279a5-73d1-4859-88f0-a6c3e6b4b907.c3n41cmd0nqnrk39u98g.databases.appdomain.cloud.com:30756/bludb'

db = SQLAlchemy(app)
bcrypt=Bcrypt(app)
migrate=Migrate(app,db)
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
    image_file = db.Column(db.String(20), default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    details= db.relationship('detail',backref='admin',lazy=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_file}')"

class detail(db.Model, UserMixin):
	id=db.Column(db.Integer,primary_key=True)
	weight=db.Column(db.Integer,nullable=False)
	height=db.Column(db.Integer,nullable=False)
	user_id=db.Column(db.Integer, db.ForeignKey('user.id'),nullable=False)

	def __repr__(self):
		return f"details('{self.weight}', '{self.height}')"

class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
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
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


@app.route("/")
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    return render_template('home.html', form=form)

@app.route("/register", methods=['GET', 'POST'])
def register():
	form=RegistrationForm()
	if form.validate_on_submit():
		hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
		user=User(username=form.username.data, email=form.email.data, password=hashed_password)
		db.session.add(user)
		db.session.commit
		flash("User added Successfully")
		return redirect(url_for('login'))
	return render_template("register.html",form=form)
    
	

@app.route("/dashboard")
def dashboard():
	return render_template('dashboard.html')

if __name__=='__main__':
    app.run(debug=True)