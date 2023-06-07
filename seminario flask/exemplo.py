# ---- Importações ----
from flask import Flask, request, render_template, redirect, url_for, jsonify, abort

# ---- Wrappers/Funcionalidades Extras ----
from flask_wtf import FlaskForm  # Protege contra ataques Cross Site Request Forgery (CSRF) e Cross-Site Scripting (XSS)
from flask_marshmallow import Marshmallow  # validação, serialização e desserialização de dados
from flask_sqlalchemy import SQLAlchemy  # Flask-PyMongo ou Flask-MongoEngine
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user  # Grenc usuários

# ---- Web Server Gateway Interface ----
from waitress import serve  # Gunicorn ou uWSGI
from werkzeug.security import generate_password_hash, check_password_hash

# ---- Manipulação de forms ----
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired

# ---- Misc ----
from os import path
import logging


# ---- Configurações do aplicativo Flask ----
app = Flask(__name__)


# ---- Configurações do banco de dados ----
basedir = path.abspath(path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + path.join(basedir, 'tmp\\exemplo.db')  # Caminho Absoluto
app.config['SECRET_KEY'] = 'senha_exemplo'
db = SQLAlchemy(app)


# ---- Inicialização do Marshmallow ----
ma = Marshmallow(app)


# ---- Definição do modelo de dados ----
class Message(db.Model):  # Nossa tabela de Mensagens
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(120), nullable=False)


class User(UserMixin, db.Model):  # Nossa tabela de Usuários
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# ---- Definição de Formulários ----
class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')


class MessageForm(FlaskForm):
    content = StringField('Content', validators=[DataRequired()])
    submit = SubmitField('Submit')


# ---- Definição de Esquemas para o Marshmallow ----
class MessageSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Message
        load_instance = True


message_schema = MessageSchema()
messages_schema = MessageSchema(many=True)


# ---- Inicialização do Login Manager ----
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader  # Flask-Login requer este callback
def load_user(user_id):
    return User.query.get(int(user_id))


# ---- Rotas de autenticação ----
@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and check_password_hash(user.password_hash, request.form.get('password')):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid username or password.")
    return render_template('login.html')


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('dashboard'))


@app.route("/signup", methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        user = User(username=form.username.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)


# ---- API ----
@app.route("/api/messages", methods=['POST'])
def create_message_api():
    content = request.json.get('content')
    if not content:
        return jsonify({"error": "Content is required"}), 400
    message = Message(content=content)
    db.session.add(message)
    db.session.commit()
    return message_schema.jsonify(message), 201


@app.route("/api/messages", methods=['GET'])
def get_messages_api():
    messages = Message.query.all()
    return messages_schema.jsonify(messages), 200


@app.route("/message/<int:message_id>", methods=['GET'])
@login_required
def get_message(message_id):
    message = Message.query.get_or_404(message_id)
    return render_template('message.html', message=message)


# ---- Rotas Web ----
@app.route("/")
@app.route("/dashboard", methods=['GET', 'POST'])
def dashboard():
    form = MessageForm()
    if form.validate_on_submit():
        message = Message(content=form.content.data)
        db.session.add(message)
        db.session.commit()
        return redirect(url_for('dashboard'))
    messages = Message.query.all()
    return render_template('dashboard.html', form=form, messages=messages)


@app.route("/update/<int:message_id>", methods=['GET', 'POST'])
def update(message_id):
    message = Message.query.get_or_404(message_id)
    form = MessageForm()
    if form.validate_on_submit():
        message.content = form.content.data
        db.session.commit()
        return redirect(url_for('dashboard'))
    form.content.data = message.content
    return render_template('update.html', form=form)


@app.route("/delete/<int:message_id>", methods=['POST'])
def delete(message_id):
    message = Message.query.get_or_404(message_id)
    db.session.delete(message)
    db.session.commit()
    return redirect(url_for('dashboard'))


@app.route('/cause_error')
def cause_error():
    x = 1 / 0  # Isso causará um erro
    return x


# ---- Middleware ----
@app.before_request  # Logo após receber uma requisição
def block_bots():
    user_agent = request.headers.get('User-Agent')
    if 'python' in user_agent.lower():
        abort(403)  # Retorna um status HTTP 403 Forbidden


@app.before_request  # Você pode ter quantos quiser e a ordem de execução será a mesma ordem do código
def require_login():
    # Lista de rotas que não requerem autenticação
    whitelist = ['login', 'static', 'signup']
    if request.endpoint not in whitelist and not current_user.is_authenticated:
        return redirect(url_for('login'))


@app.before_request
def before_request_func():
    pass
    # Logging
    # Começar cronometro
    # Negar acesso
    # Checar autentificação
    # Validar dados
    # Conectar a um cache


@app.after_request  # Antes de enviar a resposta
def after_request_func(response):
    # Logging
    # Alterar reposta (headers/body)
    # Tratamento de erros
    # Análise de uso
    # Desconectar de um cache
    return response  # Retorna 500 caso haja interrompimento


# ---- Logging ----
app.config['SQLALCHEMY_ECHO'] = True
logging.basicConfig()
logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)


# ---- Inicialização do servidor ----
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    # app.run(host="0.0.0.0", port=8080, debug=True)  # Debbuging
    serve(app, host="0.0.0.0", port=8080, threads=4)  # Produção
