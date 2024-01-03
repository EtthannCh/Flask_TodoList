from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    login_required,
    current_user,
    login_user,
    logout_user,
    UserMixin,
)
from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship

app = Flask(__name__, static_folder="static")
app.config["SECRET_KEY"] = "asfiiwe ASPDJAOW P1P231P 2"
Bootstrap5(app)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///todo.db"
db = SQLAlchemy()
db.init_app(app=app)


class Todo(db.Model):
    __tablename__ = "todos"
    id = db.Column(db.Integer, primary_key=True)
    task = db.Column(db.Text, unique=True, nullable=False)
    checked = db.Column(db.Boolean, nullable=False)
    date = db.Column(db.Date, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.user_id"))

    author = relationship("User", back_populates="tasks")


class User(UserMixin, db.Model):
    __tablename__ = "users"
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.Text, unique=True, nullable=False)
    password = db.Column(db.String(200))
    tasks = db.relationship("Todo", back_populates="author")

    def get_id(self):
        return self.user_id


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    email = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


def Toggle(Bool):
    if Bool == True:
        Bool = False
    elif Bool == False:
        Bool = True
    return Bool


login_manager = LoginManager()
login_manager.init_app(app=app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


with app.app_context():
    db.create_all()


@app.route("/")
def home():
    todoList = None
    if current_user.is_authenticated:
        result = db.session.execute(
            db.select(Todo).where(Todo.author_id == current_user.user_id)
        )
        todoList = result.scalars().all()
        return render_template("index.html", todoList=todoList)
    return render_template("index.html", todoList=todoList)


@app.route("/add", methods=["POST"])
@login_required
def add():
    todo_input = request.form.get("todo_input")
    checked = False
    current_date = date.today()

    new_todo = Todo(
        task=todo_input,
        checked=checked,
        date=current_date,
        author_id=current_user.user_id,
    )
    db.session.add(new_todo)
    db.session.commit()
    return redirect(url_for("home"))


@app.route("/delete/<int:id>", methods=["POST"])
@login_required
def delete(id):
    result = db.get_or_404(Todo, id)
    result.checked = Toggle(result.checked)
    db.session.commit()
    return redirect(url_for("home"))


@app.route("/direct", methods=["POST"])
@login_required
def direct():
    nav_type = request.form.get("nav_type")
    if nav_type == "upcoming":
        result = db.session.execute(
            db.select(Todo).where(
                Todo.author_id == current_user.user_id, Todo.checked == False
            )
        )
        todoList = result.scalars().all()
        return render_template("index.html", todoList=todoList)
    elif nav_type == "completed":
        result = db.session.execute(
            db.select(Todo).where(
                Todo.author_id == current_user.user_id, Todo.checked == True
            )
        )
        todoList = result.scalars().all()
        return render_template("index.html", todoList=todoList, complete=nav_type)
    return redirect(url_for("home"))


@app.route("/remove/<int:id>")
@login_required
def removeFromDb(id):
    result = db.get_or_404(Todo, id)
    db.session.delete(result)
    db.session.commit()
    return redirect(url_for("home"))


@app.route("/register", methods=["GET", "POST"])
def register():
    reg_form = RegisterForm()
    if reg_form.validate_on_submit():
        username = reg_form.username.data
        email = reg_form.email.data
        password = reg_form.password.data
        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password=password),
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("home"))
    return render_template("register.html", form=reg_form)


@app.route("/login", methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        password = login_form.password.data
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()
        if not user:
            error = "User does not exists.. Please try again"
            return render_template("login.html", error=error, form=login_form)
        isAuthenticated = check_password_hash(user.password, password)
        if user and isAuthenticated:
            login_user(user)
            return redirect(url_for("home"))
        elif not isAuthenticated:
            return redirect(url_for("login"))
    return render_template("login.html", form=login_form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True, port=5001)
