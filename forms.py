from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, IntegerField
from wtforms.validators import DataRequired, URL


# WTForm
class AddCafeForm(FlaskForm):
    cafe_name = StringField("Cafe Name", validators=[DataRequired()])
    cafe_address = StringField("Cafe Address", validators=[DataRequired()])
    hours = StringField("Hours", validators=[DataRequired()])  # there as URL() too
    avg_price = StringField("Avg Coffee Price", validators=[DataRequired()])
    address_link = StringField("Caffe Address Link", validators=[DataRequired(), URL()])
    image_link = StringField("Caffe Image Link", validators=[DataRequired(), URL()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField()


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField()

