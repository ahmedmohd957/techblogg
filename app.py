from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required

app = Flask(__name__)
app.config['SECRET_KEY'] = 'A0Zr98j/3yX R~XHH!jmN]LWX/,?RT'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///techblogg.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    articles = db.relationship('Article', backref='author', lazy=True)

    def __repr__(self):
        return f"{self.username}, {self.email}"

class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"{self.title}, {self.content}, {self.created_date}, {self.author_id}"


@app.route('/')
@app.route('/index')
def index():
    articles = Article.query.all()
    return render_template('index.html', articles=articles)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    error = None
    if request.method == "POST":
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_pass = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=hashed_pass)

        email_exists = User.query.filter_by(email=user.email).first()
        username_exists = User.query.filter_by(username=user.username).first()

        if email_exists:
            print('Email already exists')
            error = "Email already exists"
        elif username_exists:
            print('Username already exists')
            error = 'Username already exists'
        else:
            db.session.add(user)
            db.session.commit()
            print(User.query.all())
            return redirect(url_for('index'))
    return render_template('signup.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    error = None
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user, remember=True)
            return redirect(url_for('index'))
        else:
            print('Your email or password is invalid')
            error = 'Your email or password is invalid'

    return render_template('login.html', error=error)

@app.route('/new-article', methods=['GET', 'POST'])
@login_required
def newArticle():
    if request.method == "POST":
        title = request.form['title']
        content = request.form['content']

        article = Article(title=title, content=content, author=current_user)
        db.session.add(article)
        db.session.commit()

        return redirect(url_for('index'))
    return render_template('new_article.html')

@app.route('/article/<int:article_id>')
def article(article_id):
    article = Article.query.get_or_404(article_id)
    return render_template('article.html', article=article)

@app.route('/article/<int:article_id>/update', methods=['GET', 'POST'])
@login_required
def update_article(article_id):
    article = Article.query.get_or_404(article_id)
    if article.author != current_user:
        abort(403)

    if request.method == "POST":
        article.title = request.form['title']
        article.content = request.form['content']
        db.session.commit()
        return redirect(url_for('article', article_id=article.id))
    return render_template('new_article.html', isNew=False, article=article)

@app.route('/article/<int:article_id>/delete', methods=['GET', 'POST'])
@login_required
def delete_article(article_id):
    article = Article.query.get_or_404(article_id)
    if article.author != current_user:
        abort(403)

    Article.query.filter_by(id=article_id).delete()
    db.session.commit()
    return redirect(url_for('index'))

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
