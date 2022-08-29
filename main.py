import os
from flask_wtf import FlaskForm
from flask import Flask, request, render_template, flash, redirect, url_for
from wtforms import form, PasswordField, IntegerField, StringField, SubmitField, EmailField
from wtforms.validators import DataRequired, InputRequired
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc
from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
uri = os.getenv("DATABASE_URL")  # or other relevant config var
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('sqlite:///Newcafes.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)

##CONNECT TO DB


@login_manager.user_loader
def load_user(user_id):
    return CoffeeUser.query.get(int(user_id))


class Cafe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    map_url = db.Column(db.String(120), nullable=False)
    image_url = db.Column(db.String(120), nullable=False)
    location = db.Column(db.String(120), nullable=False)
    has_socket = db.Column(db.String(120), nullable=False)
    has_toilet = db.Column(db.String(120), nullable=False)
    has_wifi = db.Column(db.String(120), nullable=False)
    can_take_calls = db.Column(db.String(120), nullable=False)
    seats = db.Column(db.String(120), nullable=False)
    coffee_price = db.Column(db.String(120), nullable=False)

class CoffeeUser(UserMixin, db.Model):
    __tablename__ = "users_details"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(180), nullable=True)
    user_email = db.Column(db.String(100), nullable=True)
    user_password = db.Column(db.String(100))
# db.create_all()

class MyForm(FlaskForm):
    name = StringField('Name of coffee shop', validators=[DataRequired()])
    map_url = StringField('Google map location', validators=[InputRequired()])
    image_url = StringField(' Image url ', validators=[InputRequired(message='Please enter an image url ')])
    location = StringField('Location of the shop', validators=[DataRequired()])
    has_socket = IntegerField('Enter number of sockets', validators=[InputRequired()])
    has_toilet = IntegerField('Enter "1" for availability and zero for none ', validators=[DataRequired()])
    has_wifi = IntegerField('Enter "1" for availability', validators=[InputRequired()])
    can_take_calls = IntegerField('Enter "1" for availability', validators=[InputRequired()])
    seats = IntegerField('Enter "1" for availability',
                         validators=[InputRequired(message='Enter "1" if seats are available ')])
    coffee_price = StringField("Enter price", validators=[InputRequired(message='Enter price')])
    submit = SubmitField('Add cafe', validators=[DataRequired(message='Please click submit')])


class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), InputRequired()])
    email_address = EmailField('Email Address', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired(), DataRequired()])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = EmailField('Email Address', validators=[DataRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Submit')

@app.route("/", methods=['POST', 'GET'])
def home():
    if request.method == "GET":
        data = Cafe.query.all()
        return render_template("index.html", cafes=data, client=current_user.is_authenticated)


@app.route("/addcafe", methods=['POST', 'GET'])
@login_required
def add():
    forms = MyForm()
    if request.method == 'GET':
        return render_template("addcafes.html", form=forms)
    elif request.method == 'POST':
        cafe_1 = Cafe(
            name=forms.name.data,
            map_url=forms.map_url.data,
            image_url=forms.image_url.data,
            location=forms.location.data,
            has_socket=forms.has_socket.data,
            has_toilet=forms.has_toilet.data,
            has_wifi=forms.has_wifi.data,
            can_take_calls=forms.can_take_calls.data,
            seats=forms.seats.data,
            coffee_price=forms.coffee_price.data
        )
        try:
            db.session.add(cafe_1)
            db.session.commit()
            flash(message='cafe is added')
            return redirect(url_for('home'))
        except exc.IntegrityError:
            db.session.rollback()
            flash(message=" This cafe is already in the database. ")
            return redirect(url_for('home'))


@app.route("/user_login", methods=["GET", "POST"])
def login():
    login_details = LoginForm()
    if request.method == "GET":
        return render_template('login.html', form=login_details)
    else:
        email = login_details.email.data
        password = login_details.password.data
        # # check here the criteria for searching the database.
        logged_in_user = CoffeeUser.query.filter_by(user_email=email).first()
        if not logged_in_user:
            flash(" This email doesnt exist!!! ")
            return redirect(url_for('login'))
        elif not check_password_hash(pwash=logged_in_user.user_password, password=password):
            flash(" You have entered a wrong password ")
            return redirect(url_for('login'))
        else:
            login_user(logged_in_user)
            return redirect(url_for('home'))

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/register", methods=['GET', 'POST'])
def register():
    forms = RegistrationForm()
    if request.method == 'GET':
        return render_template('registration.html', form=forms)
    elif request.method == 'POST':
        e_address = forms.email_address.data
        username = forms.name.data
        hash_and_salted_password = generate_password_hash(forms.password.data, method='pbkdf2:sha256', salt_length=8)
        try:
            new_user = CoffeeUser(
                name=username,
                user_email=e_address,
                user_password=hash_and_salted_password
            )
            db.session.add(new_user)
            db.session.commit()
            flash("You have been registered")
            return redirect( url_for("home"))
        except:    
            return redirect(url_for('register'))
        
if __name__ == "__main__":
    app.run(debug=True)
