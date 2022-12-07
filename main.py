from flask import Flask, render_template, redirect, url_for, flash, g
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES

#Created the table for User db
class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

    #The children attributes of the parent class
    # and represents the list of child objects in BlogPost related to parent(User)
    posts = relationship('BlogPost', back_populates="author")
    #This represents the list of child objects in Comment related to parent(User)
    comments = relationship('Comment', back_populates="comment_author")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    #This foreign key specifies the relationship between the parent and the children.
    #Allow sqlachemy to determine which records in the many side of the table are related to the record in the one side.
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    #Child of User.posts
    author = relationship("User", back_populates="posts")


    #child attribute in parent and is linked to the child object
    comments = relationship('Comment', back_populates="parent_post")


    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

class Comment(db.Model):
    __tablename__ ="comments"
    id = db.Column(db.Integer, primary_key=True)
    #create parent id to determine which records in this child object are related to the record in user (parent) object
    comment_author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    #child of User.comments
    comment_author = relationship("User", back_populates="comments")

    #create id to link parent post to comments in parent object BlogPost
    parent_post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    #Child of BlogPost.comments
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)



#db.create_all()

#
# with app.app_context():
#       db.create_all()
#       db.session.commit()

#Create instance of LoginManager()
login_manager = LoginManager()
login_manager.init_app(app)

#create user loader to reload the user object from the user ID stored in the session
@login_manager.user_loader
def load_user(user_id):
    #the int exist because load_user returns object as a str
    return User.query.get(int(user_id))

def admin_only(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403, description="Forbidden")
        else:
            return function(*args, **kwargs)
    return decorated_function

#Initialize with flask application and default parameters
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email =  form.email.data
        if User.query.filter_by(email=email).first():
            flash("You have already signed up with that Email. Log in instead!")
            return redirect(url_for('login'))
        else:
            new_user = User()
            new_user.email = email
            new_user.password = generate_password_hash(form.password.data,
                                                   method='pbkdf2:sha256',
                                                   salt_length=8)
            new_user.name = form.name.data
            db.session.add(new_user)
            db.session.commit()
            #log in user
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user:
            flash("That email does not exist. Please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, form.password.data):
            flash("Password incorrect. Try again.")
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=(['GET', 'POST']))
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You have to log in before you can comment.")
            return redirect(url_for('login'))
        else:
            user_comment = Comment()
            user_comment.text = form.comment.data
            user_comment.comment_author = current_user
            user_comment.parent_post = requested_post
            db.session.add(user_comment)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
    return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
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


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
