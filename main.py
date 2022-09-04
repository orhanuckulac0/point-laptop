from functools import wraps
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import os

# from flask_wtf.csrf import CSRFProtect


app = Flask(__name__)
SECRET_KEY = os.urandom(30)
app.secret_key = SECRET_KEY
Bootstrap(app)
# csrf = CSRFProtect(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cafes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# Create the cafes table
class Antalya(db.Model):
    __tablename__ = "Antalya_Cafes"
    id = db.Column(db.Integer, primary_key=True)
    cafe_name = db.Column(db.String(250), nullable=False)
    cafe_address = db.Column(db.String(250), nullable=False)
    hours = db.Column(db.Integer, nullable=False)
    avg_price = db.Column(db.Integer, nullable=False)
    address_link = db.Column(db.String(500), nullable=False)
    image_link = db.Column(db.String(500), nullable=False)


# Create cafe suggestions table
class Cafe_Suggestions(db.Model):
    __tablename__ = "Antalya_Cafe_Suggestions"
    id = db.Column(db.Integer, primary_key=True)
    cafe_name = db.Column(db.String(250), nullable=False)
    cafe_address = db.Column(db.String(250), nullable=False)
    hours = db.Column(db.Integer, nullable=False)
    avg_price = db.Column(db.Integer, nullable=False)
    address_link = db.Column(db.String(500), nullable=False)
    image_link = db.Column(db.String(500), nullable=False)


# Create user table
class User(UserMixin, db.Model):
    __tablename__ = "Users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))


# Create all the tables in the database
# db.create_all()

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If user current user isn't authenticated or id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email")
        name = request.form.get('name')
        pwd = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            flash("You've already signed up with that email, sign up instead!")
            return redirect(url_for("login"))
        elif email == '' and name == '' and pwd == '':
            flash("All fields required!")
            return redirect(url_for("register"))
        elif email == '':
            flash('Email required!')
            return redirect(url_for("register"))
        elif name == '':
            flash('Name required!')
            return redirect(url_for("register"))
        elif pwd == '':
            flash('Password required!')
            return redirect(url_for("register"))
        elif len(pwd) < 5:
            flash('Password is too weak!')
            return redirect(url_for("register"))
        else:
            hashed_and_salted_pw = generate_password_hash(
                password=pwd,
                method="pbkdf2:sha256",
                salt_length=8)
            new_user = User(
                email=email,
                name=name,
                password=hashed_and_salted_pw
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            print("new user")
            return redirect(url_for("home"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    # form = LoginForm()
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()

        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for("home"))
            else:
                flash('Password incorrect, please try again.')
        else:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))

    return render_template("login.html")


@app.route("/cafes")
def cafes():
    all_cafes = Antalya.query.all()
    return render_template("cafes.html", displayed_cafes=all_cafes)


# this allows users to suggest a cafe place.
# suggestion info goes to Cafe_Suggestions db and waits there for admin confirmation
@app.route("/suggest_cafe", methods=["GET", "POST"])
@login_required
def suggest_cafe():
    if request.method == "POST":
        cafe_name = request.form.get("cafe_name")
        cafe_address = request.form.get("cafe_address")
        hours = request.form.get("hours")
        avg_price = request.form.get("avg_price")
        address_link = request.form.get("address_link")
        image_link = request.form.get("image_link")

        if cafe_name == '':
            flash('Cafe name required!')
            return redirect(url_for('suggest_cafe'))
        elif cafe_address == '':
            flash('Cafe address required!')
            return redirect(url_for('suggest_cafe'))
        elif hours == '':
            flash('Hours required!')
            return redirect(url_for('suggest_cafe'))
        elif avg_price == '':
            flash('Average price required!')
            return redirect(url_for('suggest_cafe'))
        elif address_link == '':
            flash('Address link required!')
            return redirect(url_for('suggest_cafe'))
        elif image_link == '':
            flash('Image link required!')
            return redirect(url_for('suggest_cafe'))
        else:
            new_cafe = Cafe_Suggestions(
            cafe_name=cafe_name,
            cafe_address=cafe_address,
            hours=hours,
            avg_price=avg_price,
            address_link=address_link,
            image_link=image_link
        )
        db.session.add(new_cafe)
        db.session.commit()
        return redirect(url_for("cafes"))
    return render_template("suggest_cafe.html")


# This shows the pending cafe suggestions page
@app.route("/suggestions_admin", methods=["GET", "POST"])
@login_required
@admin_only
def suggestions_admin():
    suggestions = Cafe_Suggestions.query.all()
    return render_template("suggestions_admin.html", suggestion_list=suggestions)


# this allows admin to delete the suggested cafe from suggestions db
@app.route("/suggestions_admin/<id>", methods=["GET", "POST"])
@login_required
@admin_only
def delete_suggestion(id):
    suggested_cafe = Cafe_Suggestions.query.filter_by(id=id).first()
    if suggested_cafe:
        Cafe_Suggestions.query.filter_by(id=suggested_cafe.id).delete()
        db.session.commit()
        return redirect(url_for("suggestions_admin"))


# adds the suggested cafe information to main db
# deletes this cafe information from the previous db
@app.route("/added_by_suggestions/<id>", methods=["GET", "POST"])
@admin_only
@login_required
def add_suggestions_to_db(id):
    suggested_cafe = Cafe_Suggestions.query.filter_by(id=id).first()
    if suggested_cafe:
        new_cafe = Antalya(
            cafe_name=suggested_cafe.cafe_name,
            cafe_address=suggested_cafe.cafe_address,
            hours=suggested_cafe.hours,
            avg_price=suggested_cafe.avg_price,
            address_link=suggested_cafe.address_link,
            image_link=suggested_cafe.image_link
        )
        db.session.add(new_cafe)
        db.session.commit()

        Cafe_Suggestions.query.filter_by(id=suggested_cafe.id).delete()
        db.session.commit()


    return redirect(url_for("cafes"))

# this deletes the specified café from the explore cafe section
@app.route('/delete/<cafe_id>')
@login_required
@admin_only
def delete(cafe_id):
    specified_cafe = Antalya.query.get(cafe_id)
    db.session.delete(specified_cafe)
    db.session.commit()
    flash(message='Cafe deleted successfully')
    return redirect(url_for('cafes'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)
