import sqlalchemy
from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug import Response
from werkzeug.exceptions import abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar



app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
Base = declarative_base()
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)



##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates = "posts")

    blog_c = relationship("Comment", back_populates = "comment")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)

    posts = relationship("BlogPost", back_populates = "author")

    comments = relationship("Comment", back_populates = "user")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    user = relationship("User", back_populates = "comments")

    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    comment = relationship("BlogPost", back_populates = "blog_c")

    text = db.Column(db.Text, nullable = False)

db.create_all()



ADMIN = User.query.first()



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)



@app.route('/')
def get_all_posts():
    admin = False
    if current_user == ADMIN:
        admin = True
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, admin = admin)


@app.route('/register', methods=["POST", "GET"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(password=form.password.data,
                                                 method="pbkdf2:sha256",
                                                 salt_length=8)
        new_user = User(name=form.name.data,
                        email=form.email.data,
                        password=hashed_password
                        )
        try:
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)

            return redirect(url_for("get_all_posts"))
        except sqlalchemy.exc.IntegrityError:
            flash("This email is already registered, try to log-in")
            return redirect("login")

    return render_template("register.html", form = form)


@app.route('/login', methods = ["POST", "GET"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        c_user = User.query.filter_by(email = form.email.data).first()

        if c_user and check_password_hash(c_user.password, form.password.data):
            login_user(c_user)
            return redirect(url_for("get_all_posts"))
        elif not c_user:
            flash("Such email is not registered")
            return redirect(url_for("login"))
        elif not check_password_hash(c_user.password, form.password.data):
            flash("Wrong password")
            return redirect(url_for("login"))
    return render_template("login.html", form = form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods = ["POST", "GET"])
def show_post(post_id):
    form = CommentForm()
    admin = False
    requested_post = BlogPost.query.get(post_id)

    if current_user == ADMIN:
        admin = True

    if form.validate_on_submit():
        new_comment = Comment(text = form.comment.data,
                              user = current_user,
                              comment = requested_post
                              )

        db.session.add(new_comment)
        db.session.commit()

    return render_template("post.html", post = requested_post, admin = admin, form = form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods = ["POST", "GET"])
def add_new_post():
    form = CreatePostForm()

    if current_user == ADMIN:

        if form.validate_on_submit():
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                body=form.body.data,
                img_url=form.img_url.data,
                author=current_user,
                date=date.today().strftime("%B %d, %Y")
            )
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
        return render_template("make-post.html", form=form)

    else:
        abort(403)
        abort(Response('Hello World'))


@app.route("/edit-post/<int:post_id>")
def edit_post(post_id):

    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )

    if current_user == ADMIN:

        if edit_form.validate_on_submit():
            post.title = edit_form.title.data
            post.subtitle = edit_form.subtitle.data
            post.img_url = edit_form.img_url.data
            post.author = edit_form.author.data
            post.body = edit_form.body.data
            db.session.commit()
            return redirect(url_for("show_post", post_id=post.id))
        return render_template("make-post.html", form=edit_form)

    else:
        abort(403)
        abort(Response('Hello World'))


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    if current_user == ADMIN:
        post_to_delete = BlogPost.query.get(post_id)
        db.session.delete(post_to_delete)
        db.session.commit()
        return redirect(url_for('get_all_posts'))

    else:
        abort(403)
        abort(Response('Hello World'))



if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
