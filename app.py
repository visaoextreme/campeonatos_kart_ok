import os
import datetime
import logging
import uuid
import secrets  # Para geração de senha aleatória
import re       # Para manipulação do CPF e WhatsApp
from functools import wraps
from typing import Any, Dict, List

from markupsafe import Markup

from flask import (
    Flask, request, jsonify, session, render_template_string,
    redirect, url_for, flash, get_flashed_messages, send_from_directory
)
import pyotp  # se precisar de MFA
from supabase import create_client, Client
from dotenv import load_dotenv

from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import sendgrid
from sendgrid.helpers.mail import Mail
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# =============================================================================
# DECORADORES PERSONALIZADOS
# =============================================================================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("user_id"):
            flash("Você precisa estar logado para acessar esta página.", "warning")
            return redirect(url_for("login_get"))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("role") != "admin":
            flash("Acesso negado. Esta área é restrita para administradores.", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function

# =============================================================================
# CONFIGURAÇÃO E LOGGING
# =============================================================================
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")

if not SUPABASE_URL or not SUPABASE_ANON_KEY:
    logging.error("Supabase URL e/ou Supabase ANON KEY não configurados. Verifique o .env")
    exit(1)

if SUPABASE_SERVICE_KEY:
    logging.info("Usando SUPABASE_SERVICE_KEY para criar o cliente Supabase.")
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
else:
    logging.warning("SUPABASE_SERVICE_KEY não está configurada. Usando SUPABASE_ANON_KEY.")
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

SECRET_KEY = os.getenv("SECRET_KEY", "CHAVE_SECRETA_FLASK")
app = Flask(__name__)
app.secret_key = SECRET_KEY

# Em produção, você pode definir SESSION_COOKIE_SECURE=True (exige HTTPS)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True  # Ajuste para produção com HTTPS

# Serializer para tokens (para redefinição de senha, exclusão de perfil, etc.)
serializer = URLSafeTimedSerializer(SECRET_KEY)

# Pasta de upload (local). Certifique-se de criar a pasta "uploads" na raiz.
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# =============================================================================
# BEFORE REQUEST – Captura de tenant (kart_id)
# =============================================================================
@app.before_request
def set_tenant():
    kart_id = request.args.get("kart_id")
    if kart_id:
        session["kartodromo_id"] = kart_id

# =============================================================================
# Helper de Multi-Tenancy
# =============================================================================
def apply_tenant_filter(query):
    tenant_id = session.get("kartodromo_id")
    if tenant_id:
        query = query.eq("kartodromo_id", tenant_id)
    return query

def tenant_table(table_name: str):
    return apply_tenant_filter(supabase.table(table_name))

# =============================================================================
# HEADERS DE SEGURANÇA – Exemplo de Content-Security-Policy (CSP)
# =============================================================================
@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com;"
    )
    return response

# =============================================================================
# COMPONENTES VISUAIS – BASE CSS, Navbar, Breadcrumbs, Toasts, Preloader e Loading
# =============================================================================

# Atualizado para utilizar o tema Darkly do Bootswatch com interface azul escuro
FA_CDN = '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">'

PALETA_OPCOES: Dict[str, Dict[str, str]] = {
    "black_azul": {"nome": "Kartódromo MeuKart", "tema_primario": "#0d1b2a", "tema_secundario": "#415a77"},
    "modern": {"nome": "Kartódromo MeuKart", "tema_primario": "#1d3557", "tema_secundario": "#457b9d"},
    "elegant": {"nome": "Kartódromo MeuKart", "tema_primario": "#2d3436", "tema_secundario": "#d63031"},
    "vibrant": {"nome": "Kartódromo MeuKart", "tema_primario": "#00b894", "tema_secundario": "#0984e3"},
}
DEFAULT_TEMA: Dict[str, str] = PALETA_OPCOES["black_azul"].copy()

BASE_CSS = f"""
{FA_CDN}
<link href="https://cdn.jsdelivr.net/npm/bootswatch@5.2.3/dist/darkly/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Montserrat:400,700&display=swap">
<style>
  body {{
      font-family: 'Montserrat', sans-serif;
      background-color: {DEFAULT_TEMA["tema_primario"]};
      color: #f8f9fa;
      margin: 0;
      padding-bottom: 50px;
  }}
  .navbar, .card, .container {{
      border-radius: 10px;
  }}
  .card {{
      background: #1b263b;
      border: none;
      box-shadow: 0 4px 8px rgba(0,0,0,0.2);
      margin-bottom: 20px;
  }}
  .btn-custom {{
      min-width: 200px;
      margin: 5px;
  }}
  .breadcrumb {{
      background: #343a40;
      border-radius: 5px;
  }}
  .password-meter-container {{
      height: 10px;
      background: #495057;
      border-radius: 5px;
      margin-top: 5px;
  }}
  .password-meter-fill {{
      height: 100%;
      width: 0%;
      background: red;
      border-radius: 5px;
      transition: width 0.3s, background 0.3s;
  }}
  .dashboard-section {{
      margin-bottom: 30px;
  }}
  .dashboard-section h3 {{
      border-bottom: 2px solid #dee2e6;
      padding-bottom: 5px;
      margin-bottom: 15px;
  }}
  .dashboard-item {{
      margin-bottom: 15px;
  }}
  .dashboard-item i {{
      margin-right: 8px;
  }}
</style>
"""

NAVBAR_HTML = """
<nav class="navbar navbar-expand-lg navbar-dark bg-dark shadow mb-4">
  <div class="container-fluid">
    <a class="navbar-brand" href="/"><strong>{{ theme_name }}</strong></a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarContent" 
      aria-controls="navbarContent" aria-expanded="false" aria-label="Alternar navegação">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarContent">
      <ul class="navbar-nav me-auto mb-2 mb-lg-0">
        <li class="nav-item"><a class="nav-link" href="/">Início</a></li>
        <li class="nav-item"><a class="nav-link" href="/piloto/interface">Área do Piloto</a></li>
        {% if session.get("role") == "admin" %}
        <li class="nav-item"><a class="nav-link" href="/admin">Área do Admin</a></li>
        {% endif %}
        <li class="nav-item"><a class="nav-link" href="/piloto/dashboard">Dashboard</a></li>
        <li class="nav-item"><a class="nav-link" href="/pontuacoes">Pontuações</a></li>
      </ul>
      <span class="navbar-text">
         {% if session.get("user_id") %}
            Bem-vindo, {{ session.get("user_name") }}! 
            <a href="/logout" class="btn btn-outline-primary btn-sm ms-2">Sair</a>
         {% else %}
            <a href="/login" class="btn btn-outline-primary btn-sm ms-2">Entrar</a>
         {% endif %}
      </span>
    </div>
  </div>
</nav>
"""

TOAST_CONTAINER = """
<div aria-live="polite" aria-atomic="true" class="position-fixed top-0 end-0 p-3" style="z-index: 1050;">
  {% for category, message in get_flashed_messages(with_categories=True) %}
  <div class="toast align-items-center text-white bg-{% if category=='danger' or category=='warning' %}danger{% else %}success{% endif %} border-0 mb-2" role="alert" aria-live="assertive" aria-atomic="true">
    <div class="d-flex">
      <div class="toast-body">
        {{ message }}
      </div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
    </div>
  </div>
  {% endfor %}
</div>
<script>
  var toastElList = [].slice.call(document.querySelectorAll('.toast'));
  var toastList = toastElList.map(function(toastEl) {
    return new bootstrap.Toast(toastEl, { delay: 5000 }).show();
  });
</script>
"""

GLOBAL_LOADING_SCRIPT = """
<script>
document.addEventListener('submit', function(e) {
   var btn = e.target.querySelector("button[type='submit']");
   if(btn) {
       btn.disabled = true;
       btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Aguarde...';
   }
});
</script>
"""

def get_navbar() -> str:
    return render_template_string(NAVBAR_HTML, theme_name=DEFAULT_TEMA["nome"])

def render_breadcrumbs(section: str, page: str) -> str:
    return f"""
    <nav aria-label="breadcrumb">
      <ol class="breadcrumb">
        <li class="breadcrumb-item">{section}</li>
        <li class="breadcrumb-item active" aria-current="page">{page}</li>
      </ol>
    </nav>
    """

# =============================================================================
# TRATAMENTO DE ERROS GLOBAIS (404 e 500)
# =============================================================================
@app.errorhandler(404)
def not_found_error(error):
    return render_template_string("""
      <!DOCTYPE html>
      <html lang="pt">
      <head>
         <meta charset="UTF-8">
         <title>Página Não Encontrada</title>
         <meta name="viewport" content="width=device-width, initial-scale=1">
         <link href="https://cdn.jsdelivr.net/npm/bootswatch@5.2.3/dist/darkly/bootstrap.min.css" rel="stylesheet">
         <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
         <style>
           body {
             font-family: 'Montserrat', sans-serif;
             background-color: #0d1b2a;
             color: #f8f9fa;
             margin: 0;
             padding-bottom: 50px;
           }
           .error-container {
             min-height: 100vh;
             display: flex;
             align-items: center;
             justify-content: center;
             flex-direction: column;
             text-align: center;
           }
           .error-code {
             font-size: 8rem;
             font-weight: bold;
           }
           .card {
             border-radius: 10px;
             background: #1b263b;
             color: #f8f9fa;
             box-shadow: 0 4px 8px rgba(0,0,0,0.2);
           }
         </style>
      </head>
      <body>
         <div class="error-container">
            <div class="error-code">404</div>
            <div class="card text-light mb-3" style="max-width: 500px;">
              <div class="card-body">
                <p class="lead mb-0 text-center">Página não encontrada!</p>
              </div>
            </div>
            <a href="/" class="btn btn-primary">Voltar ao Início</a>
         </div>
      </body>
      </html>
    """), 404

@app.errorhandler(500)
def internal_error(error):
    logging.error(f"Erro interno: {error}")
    return render_template_string("""
      <!DOCTYPE html>
      <html lang="pt">
      <head>
         <meta charset="UTF-8">
         <title>Erro Interno</title>
         <meta name="viewport" content="width=device-width, initial-scale=1">
         <link href="https://cdn.jsdelivr.net/npm/bootswatch@5.2.3/dist/darkly/bootstrap.min.css" rel="stylesheet">
         <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
         <style>
           body {
             font-family: 'Montserrat', sans-serif;
             background-color: #0d1b2a;
             color: #f8f9fa;
             margin: 0;
             padding-bottom: 50px;
           }
           .error-container {
             min-height: 100vh;
             display: flex;
             align-items: center;
             justify-content: center;
             flex-direction: column;
             text-align: center;
           }
           .error-code {
             font-size: 8rem;
             font-weight: bold;
           }
           .card {
             border-radius: 10px;
             background: #1b263b;
             color: #f8f9fa;
             box-shadow: 0 4px 8px rgba(0,0,0,0.2);
           }
         </style>
      </head>
      <body>
         <div class="error-container">
            <div class="error-code">500</div>
            <div class="card text-light mb-3" style="max-width: 500px; margin-top: 20px;">
              <div class="card-body">
                <p class="lead mb-0 text-center">Ops! Algo deu errado. Tente novamente ou contate o suporte.</p>
              </div>
            </div>
            <a href="/" class="btn btn-primary">Voltar ao Início</a>
         </div>
      </body>
      </html>
    """), 500

# =============================================================================
# FUNÇÕES AUXILIARES – Datas, Validações e Formatação
# =============================================================================
def parse_date(date_str: str) -> datetime.datetime:
    if not date_str:
        raise ValueError("Data vazia")
    for fmt in ("%d/%m/%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.datetime.strptime(date_str, fmt)
        except Exception:
            continue
    try:
        return datetime.datetime.fromisoformat(date_str)
    except Exception as e:
        raise ValueError(f"Erro ao converter data: {date_str}") from e

def format_date_br(date_str: str) -> str:
    try:
        dt = parse_date(date_str)
    except Exception:
        return date_str
    return dt.strftime("%d/%m/%Y %H:%M:%S")

def checa_inscricoes_fechadas(campeonato: Dict[str, Any]) -> bool:
    try:
        status_resp = tenant_table("campeonato_inscricoes_status").select("status").eq("campeonato_id", campeonato["id"]).execute()
        if status_resp.data and status_resp.data[0].get("status") == "fechado":
            return True
    except Exception as e:
        logging.warning(f"Erro ao checar status manual: {e}")

    data_fech = campeonato.get("data_fechamento_inscricoes")
    if data_fech:
        try:
            dt_fech = parse_date(data_fech)
            if datetime.datetime.now() >= dt_fech:
                return True
        except Exception as e:
            logging.warning(f"Erro ao converter data de fechamento: {e}")

    try:
        bat_resp = tenant_table("baterias_kart_1").select("data_hora_inicio").eq("campeonato_id", campeonato["id"]).order("data_hora_inicio").execute()
        baterias = bat_resp.data or []
        if baterias:
            primeira_bateria = baterias[0].get("data_hora_inicio")
            if primeira_bateria:
                dt_primeira = parse_date(primeira_bateria)
                if datetime.datetime.now() >= dt_primeira:
                    return True
        # Se já atingiu o número máximo
    except Exception as e:
        logging.warning(f"Erro ao checar baterias: {e}")

    try:
        part_resp = tenant_table("participacoes").select("user_id").eq("campeonato_id", campeonato["id"]).execute()
        inscritos = part_resp.data or []
        if inscritos and len(inscritos) >= campeonato.get("max_participantes", 0):
            return True
    except Exception as e:
        logging.warning(f"Erro ao checar max_participantes: {e}")

    return False

def contar_baterias(campeonato_id: str) -> (int, int):
    try:
        bat_resp = tenant_table("baterias_kart_1").select("status").eq("campeonato_id", campeonato_id).execute()
        baterias = bat_resp.data or []
        feitas = sum(1 for b in baterias if b.get("status") == "finalizada")
        total = len(baterias)
        return (feitas, total - feitas)
    except Exception as e:
        logging.warning(f"Erro ao contar baterias: {e}")
        return (0, 0)

def get_camp_status(campeonato: Dict[str, Any]) -> str:
    now = datetime.datetime.now()
    try:
        dt_inicio = parse_date(campeonato.get("data_inicio"))
    except Exception as e:
        logging.warning(f"Erro ao converter data_inicio: {e}")
        return "Aberto"
    try:
        data_fim_cad = campeonato.get("data_fim")
        if not data_fim_cad:
            return "Em Andamento" if now >= dt_inicio else "Aberto"
        dt_fim = parse_date(data_fim_cad)
    except Exception as e:
        logging.warning(f"Erro ao converter data_fim: {e}")
        return "Em Andamento" if now >= dt_inicio else "Aberto"

    if now < dt_inicio:
        return "Aberto"
    elif dt_inicio <= now < dt_fim:
        return "Em Andamento"
    else:
        return "Terminado"

def atualiza_status_baterias(baterias: List[Dict[str, Any]]) -> None:
    now = datetime.datetime.now()
    for bat in baterias:
        try:
            data_inicio_str = bat.get("data_hora_inicio")
            data_fim_str = bat.get("data_hora_fim")
            if not data_inicio_str or not data_fim_str:
                continue
            dt_inicio = parse_date(data_inicio_str)
            dt_fim = parse_date(data_fim_str)

            if now < dt_inicio:
                new_status = "prevista"
            elif dt_inicio <= now < dt_fim:
                new_status = "em andamento"
            else:
                new_status = "finalizada"

            if bat.get("status") != new_status:
                tenant_table("baterias_kart_1").update({"status": new_status}).eq("id", bat["id"]).execute()
                bat["status"] = new_status
        except Exception as e:
            logging.warning(f"Erro ao atualizar status da bateria {bat.get('id')}: {e}")

def format_cpf(cpf_str: str) -> str:
    digits = re.sub(r'\D', '', cpf_str)
    if len(digits) != 11:
        return cpf_str
    return f"{digits[:3]}.{digits[3:6]}.{digits[6:9]}-{digits[9:]}"

def validate_cpf(cpf: str) -> bool:
    cpf = re.sub(r'\D', '', cpf)
    if len(cpf) != 11:
        return False
    if cpf == cpf[0] * 11:
        return False

    sum_val = sum(int(cpf[i]) * (10 - i) for i in range(9))
    first_check = (sum_val * 10) % 11
    if first_check == 10:
        first_check = 0
    if first_check != int(cpf[9]):
        return False

    sum_val = sum(int(cpf[i]) * (11 - i) for i in range(10))
    second_check = (sum_val * 10) % 11
    if second_check == 10:
        second_check = 0
    if second_check != int(cpf[10]):
        return False
    return True

def format_whatsapp(phone_str: str) -> str:
    digits = re.sub(r'\D', '', phone_str)
    if len(digits) == 11:
        return f"({digits[:2]}) {digits[2:7]}-{digits[7:]}"
    elif len(digits) == 10:
        return f"({digits[:2]}) {digits[2:6]}-{digits[6:]}"
    else:
        return phone_str

# =============================================================================
# VARIÁVEIS DE CONFIGURAÇÃO E TEMA
# =============================================================================
STREAMING_URL = os.getenv("STREAMING_URL", "https://www.youtube.com/channel/SEU_CANAL")
IDIOMAS_SUPORTADOS = ["pt", "en", "es", "fr"]

# =============================================================================
# ROTAS – INDEX
# =============================================================================
@app.route("/", methods=["GET"])
def index():
    return render_template_string(f"""
    <!DOCTYPE html>
    <html lang="pt">
    <head>
      <meta charset="UTF-8">
      <title>Bem-vindo - {DEFAULT_TEMA["nome"]}</title>
      {BASE_CSS}
    </head>
    <body>
      {get_navbar()}
      {TOAST_CONTAINER}
      <div class="container my-5">
        <div class="row justify-content-center">
          <div class="col-12 col-md-8 col-lg-6">
            <div class="card p-4">
              <div class="card-body text-center">
                <h1 class="mb-3">Bem-vindo à Plataforma de Campeonatos de Kart</h1>
                <p>Este é o sistema completo para gerenciamento de Campeonatos de Kart.</p>
                <div class="d-flex flex-wrap justify-content-center gap-3 mt-3">
                  <a href="/login" class="btn btn-primary btn-lg">Fazer Login</a>
                  <a href="/register" class="btn btn-success btn-lg">Cadastrar-se</a>
                  <a href="/piloto/interface" class="btn btn-info btn-lg">Área do Piloto</a>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      {GLOBAL_LOADING_SCRIPT}
      <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    """)

# =============================================================================
# ROTAS – LOGIN, CADASTRO, RECUPERAÇÃO E ALTERAÇÃO DE SENHA
# =============================================================================
login_template = """
<!DOCTYPE html>
<html lang="pt">
<head>
    <meta charset="UTF-8">
    <title>Login - {{ theme_name }}</title>
    {{ base_css|safe }}
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://fonts.googleapis.com;">
</head>
<body>
    {{ navbar|safe }}
    {{ toast_container|safe }}
    <div class="container my-5">
      <div class="row justify-content-center">
        <div class="col-12 col-md-8 col-lg-6">
          <div class="card p-4">
              <div class="card-body">
                  <h1 class="text-center mb-4">Login</h1>
                  <form action="/login" method="POST">
                      <div class="mb-3 text-start">
                          <label for="email" class="form-label">Email:</label>
                          <input type="email" name="email" id="email" class="form-control" required>
                      </div>
                      <div class="mb-3 text-start">
                          <label for="password" class="form-label">Senha:</label>
                          <input type="password" name="password" id="password" class="form-control" required>
                      </div>
                      <button type="submit" class="btn btn-primary btn-lg w-100 btn-submit">Entrar</button>
                  </form>
                  <div class="mt-3 text-center">
                      <a href="/recover_password">Esqueci minha senha</a> | 
                      <a href="/register">Não possui conta? Cadastre-se</a>
                  </div>
                  <div class="mt-3 text-center">
                      <a href="/" class="btn btn-secondary">Voltar</a>
                  </div>
              </div>
          </div>
        </div>
      </div>
    </div>
    {{ global_loading|safe }}
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

@app.route("/login", methods=["GET", "POST"])
def login_get():
    if request.method == "GET":
        return render_template_string(login_template,
                                      theme_name=DEFAULT_TEMA["nome"],
                                      base_css=BASE_CSS,
                                      navbar=get_navbar(),
                                      toast_container=TOAST_CONTAINER,
                                      global_loading=GLOBAL_LOADING_SCRIPT)
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "").strip()

    if not email or not password:
        flash("Email e senha são obrigatórios. Por favor, preencha ambos os campos.", "danger")
        return redirect(url_for("login_get"))

    try:
        profile_resp = tenant_table("profiles").select("*").eq("email", email).execute()
        if not profile_resp.data or len(profile_resp.data) == 0:
            flash("Usuário não encontrado. Verifique seu email ou cadastre-se.", "warning")
            return redirect(url_for("register_route"))
        user = profile_resp.data[0]
        if not check_password_hash(user["password"], password):
            flash("Senha incorreta. Verifique e tente novamente.", "danger")
            return redirect(url_for("login_get"))

        session["user_id"] = user["id"]
        session["role"] = user.get("role", "client")
        session["user_name"] = user.get("nome", "Piloto")
        flash("Login realizado com sucesso!", "success")
        return redirect(url_for("select_role"))
    except Exception as e:
        logging.error(f"Erro durante o login: {e}")
        flash("Ocorreu um erro durante o login. Por favor, tente novamente ou contate o suporte.", "danger")
        return redirect(url_for("login_get"))

@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    flash("Você saiu da sua conta.", "info")
    return redirect(url_for("index"))

@app.route("/select_role", methods=["GET"])
def select_role():
    if session.get("role") == "admin":
        return redirect("/admin")
    else:
        return redirect("/piloto")

@app.route("/recover_password", methods=["GET", "POST"])
def recover_password():
    if request.method == "GET":
        return render_template_string("""
        <!DOCTYPE html>
        <html lang="pt">
        <head>
          <meta charset="UTF-8">
          <title>Recuperar Senha - {{ theme_name }}</title>
          {{ base_css|safe }}
        </head>
        <body>
          {{ navbar|safe }}
          {{ toast_container|safe }}
          <div class="container my-5">
            <div class="row justify-content-center">
              <div class="col-12 col-md-8 col-lg-6">
                <div class="card p-4">
                  <div class="card-body">
                    <h1 class="text-center mb-4">Recuperar Senha</h1>
                    <form action="/recover_password" method="POST">
                      <div class="mb-3 text-start">
                        <label for="email" class="form-label">Digite seu email:</label>
                        <input type="email" name="email" id="email" class="form-control" required>
                      </div>
                      <button type="submit" class="btn btn-primary btn-lg w-100 btn-submit">Solicitar Redefinição</button>
                    </form>
                    <div class="mt-3 text-center">
                      <a href="/login" class="btn btn-secondary">Voltar para Login</a>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
          {{ global_loading|safe }}
          <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
        </body>
        </html>
        """, theme_name=DEFAULT_TEMA["nome"], base_css=BASE_CSS,
           navbar=get_navbar(), toast_container=TOAST_CONTAINER, global_loading=GLOBAL_LOADING_SCRIPT)

    email = request.form.get("email", "").strip().lower()
    if not email:
        flash("Email é obrigatório.", "danger")
        return redirect(request.url)

    try:
        profile_resp = tenant_table("profiles").select("id, nome, email").eq("email", email).execute()
        if not profile_resp.data or len(profile_resp.data) == 0:
            flash("Nenhum usuário encontrado com esse email.", "warning")
            return redirect(request.url)

        user = profile_resp.data[0]
        token = serializer.dumps(user["id"], salt="reset-password")
        reset_link = os.getenv("BASE_URL", "http://127.0.0.1:5000") + "/reset_password/" + token

        sg = sendgrid.SendGridAPIClient(api_key=os.getenv("TWILIO_SENDGRID_API_KEY_CAMPEONATOS", "SUA_SENDGRID_KEY"))
        from_email = os.getenv("FROM_EMAIL", "contato@exemplo.com")
        subject = "Redefinição de Senha - Plataforma de Campeonatos"
        content = (f"Olá {user['nome']},\n\n"
                   "Você solicitou a redefinição de sua senha.\n"
                   f"Por favor, clique no link a seguir para redefinir sua senha:\n{reset_link}\n\n"
                   "O link expirará em 1 hora.\n\n"
                   "Atenciosamente,\n"
                   "Equipe de Campeonatos")

        message = Mail(from_email=from_email, to_emails=email, subject=subject, plain_text_content=content)
        response = sg.send(message)

        logging.info(f"Email de redefinição de senha enviado para {email} (status: {response.status_code}).")
        if response.status_code < 400:
            flash(f"Um email com instruções foi enviado para {email}.", "success")
        else:
            flash("Erro ao enviar email de redefinição. Tente novamente ou contate o suporte.", "danger")

        return redirect(url_for("login_get"))
    except Exception as e:
        logging.error(f"Erro no processo de redefinição de senha: {e}")
        flash("Erro durante a solicitação de redefinição de senha. Por favor, tente novamente.", "danger")
        return redirect(request.url)

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token: str):
    try:
        user_id = serializer.loads(token, salt="reset-password", max_age=3600)
    except SignatureExpired:
        flash("O token de redefinição expirou. Solicite um novo.", "danger")
        return redirect(url_for("recover_password"))
    except BadSignature:
        flash("Token inválido. Tente novamente.", "danger")
        return redirect(url_for("recover_password"))

    if request.method == "GET":
        return render_template_string("""
        <!DOCTYPE html>
        <html lang="pt">
        <head>
          <meta charset="UTF-8">
          <title>Redefinir Senha - {{ theme_name }}</title>
          {{ base_css|safe }}
        </head>
        <body>
          {{ navbar|safe }}
          {{ toast_container|safe }}
          <div class="container my-5">
            <div class="row justify-content-center">
              <div class="col-12 col-md-8 col-lg-6">
                <div class="card p-4">
                  <div class="card-body">
                    <h1 class="text-center mb-4">Redefinir Senha</h1>
                    <form action="/reset_password/{{ token }}" method="POST">
                      <div class="mb-3">
                        <label for="new_password" class="form-label">Nova Senha:</label>
                        <input type="password" name="new_password" id="new_password" class="form-control" required>
                      </div>
                      <div class="mb-3">
                        <label for="confirm_password" class="form-label">Confirmar Nova Senha:</label>
                        <input type="password" name="confirm_password" id="confirm_password" class="form-control" required>
                      </div>
                      <button type="submit" class="btn btn-primary w-100 btn-submit">Redefinir Senha</button>
                    </form>
                    <div class="mt-3 text-center">
                      <a href="/login" class="btn btn-secondary">Voltar</a>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
          {{ global_loading|safe }}
          <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
        </body>
        </html>
        """, theme_name=DEFAULT_TEMA["nome"], base_css=BASE_CSS, navbar=get_navbar(),
           toast_container=TOAST_CONTAINER, global_loading=GLOBAL_LOADING_SCRIPT, token=token)

    new_password = request.form.get("new_password")
    confirm_password = request.form.get("confirm_password")

    if new_password != confirm_password:
        flash("As novas senhas não conferem. Verifique e tente novamente.", "danger")
        return redirect(url_for("reset_password", token=token))
    if len(new_password) < 4 or len(new_password) > 32:
        flash("A nova senha deve ter entre 4 e 32 caracteres.", "danger")
        return redirect(url_for("reset_password", token=token))

    try:
        tenant_table("profiles").update({"password": generate_password_hash(new_password)}).eq("id", user_id).execute()
        flash("Senha redefinida com sucesso! Faça login com sua nova senha.", "success")
        return redirect(url_for("login_get"))
    except Exception as e:
        logging.error(f"Erro ao redefinir senha: {e}")
        flash("Erro ao redefinir senha. Por favor, tente novamente.", "danger")
        return redirect(url_for("reset_password", token=token))

registration_template = """
<!DOCTYPE html>
<html lang="pt">
<head>
  <meta charset="UTF-8">
  <title>Cadastro - {{ theme_name }}</title>
  {{ base_css|safe }}
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://fonts.googleapis.com;">
</head>
<body>
  {{ navbar|safe }}
  {{ toast_container|safe }}
  <div class="container my-5">
    <div class="row justify-content-center">
      <div class="col-12 col-md-8 col-lg-6">
        <div class="card p-4">
          <div class="card-body">
            <h1 class="text-center mb-4">Cadastrar-se</h1>
            <form action="/register" method="POST">
              <div class="mb-3 text-start">
                <label for="nome" class="form-label">Nome Completo:</label>
                <input type="text" name="nome" id="nome" class="form-control" value="{{ nome|default('') }}" required>
              </div>
              <div class="mb-3 text-start">
                <label for="email" class="form-label">Email:</label>
                <input type="email" name="email" id="email" class="form-control" value="{{ email|default('') }}" required>
              </div>
              <div class="mb-3 text-start">
                <label for="cpf" class="form-label">CPF:</label>
                <input type="text" name="cpf" id="cpf" class="form-control" value="{{ cpf|default('') }}" required>
              </div>
              <div class="mb-3 text-start">
                <label for="whatsapp" class="form-label">WhatsApp:</label>
                <input type="text" name="whatsapp" id="whatsapp" class="form-control" placeholder="(XX) XXXXX-XXXX" required>
              </div>
              <div class="mb-3 text-start">
                <label for="password" class="form-label">Senha:</label>
                <input type="password" name="password" id="password" class="form-control" required>
                <div class="password-meter-container">
                    <div id="password-strength-meter" class="password-meter-fill"></div>
                </div>
                <small id="password-strength-text" class="form-text text-muted"></small>
              </div>
              <button type="submit" class="btn btn-primary btn-lg w-100 btn-submit">Cadastrar</button>
            </form>
            <div class="mt-3 text-center">
              <a href="/login">Já possui conta? Faça login</a>
            </div>
            <div class="mt-3 text-center">
              <a href="/" class="btn btn-secondary">Voltar</a>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
  {{ global_loading|safe }}
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    function formatCPF(value) {
      value = value.replace(/\\D/g, '');
      if (value.length > 11) {
        value = value.slice(0,11);
      }
      value = value.replace(/(\\d{3})(\\d)/, '$1.$2');
      value = value.replace(/(\\d{3})(\\d)/, '$1.$2');
      value = value.replace(/(\\d{3})(\\d{1,2})$/, '$1-$2');
      return value;
    }
    function formatWhatsapp(value) {
      value = value.replace(/\\D/g, '');
      if(value.length === 11) {
        return "(" + value.slice(0,2) + ") " + value.slice(2,7) + "-" + value.slice(7);
      } else if(value.length === 10) {
        return "(" + value.slice(0,2) + ") " + value.slice(2,6) + "-" + value.slice(6);
      }
      return value;
    }
    document.getElementById('cpf').addEventListener('input', function(e) {
      e.target.value = formatCPF(e.target.value);
    });
    document.getElementById('whatsapp').addEventListener('input', function(e) {
      e.target.value = formatWhatsapp(e.target.value);
    });
    function checkPasswordStrength(password) {
        var strength = 0;
        if (password.length >= 4) strength++;
        if (password.length >= 8) strength++;
        if (/[A-Z]/.test(password)) strength++;
        if (/[0-9]/.test(password)) strength++;
        if (/[^A-Za-z0-9]/.test(password)) strength++;
        return strength;
    }
    document.addEventListener('DOMContentLoaded', function(){
        var passwordInput = document.getElementById('password');
        var strengthMeter = document.getElementById('password-strength-meter');
        var strengthText = document.getElementById('password-strength-text');
        if(passwordInput) {
            passwordInput.addEventListener('input', function(){
                var val = passwordInput.value;
                var strength = checkPasswordStrength(val);
                var meterPercentage = (strength / 5) * 100;
                strengthMeter.style.width = meterPercentage + '%';

                if (strength <= 2) {
                    strengthMeter.style.backgroundColor = 'red';
                    strengthText.textContent = 'Fraca';
                } else if (strength <= 4) {
                    strengthMeter.style.backgroundColor = 'orange';
                    strengthText.textContent = 'Mediana';
                } else {
                    strengthMeter.style.backgroundColor = 'green';
                    strengthText.textContent = 'Forte';
                }
            });
        }
    });
  </script>
</body>
</html>
"""

@app.route("/register", methods=["GET", "POST"])
def register_route() -> Any:
    if request.method == "GET":
        return render_template_string(registration_template,
                                      theme_name=DEFAULT_TEMA["nome"],
                                      base_css=BASE_CSS,
                                      navbar=get_navbar(),
                                      toast_container=TOAST_CONTAINER,
                                      global_loading=GLOBAL_LOADING_SCRIPT,
                                      nome="",
                                      email="",
                                      cpf="")

    nome = request.form.get("nome", "").strip()
    email = request.form.get("email", "").strip().lower()
    cpf = request.form.get("cpf", "").strip()
    whatsapp = request.form.get("whatsapp", "").strip()

    cpf_formatado = format_cpf(cpf)
    formatted_whatsapp = format_whatsapp(whatsapp)

    if not validate_cpf(cpf):
        flash("CPF inválido. Certifique-se de que o CPF informado seja válido.", "danger")
        return render_template_string(registration_template,
                                      theme_name=DEFAULT_TEMA["nome"],
                                      base_css=BASE_CSS,
                                      navbar=get_navbar(),
                                      toast_container=TOAST_CONTAINER,
                                      global_loading=GLOBAL_LOADING_SCRIPT,
                                      nome=nome,
                                      email=email,
                                      cpf="")

    digits_whatsapp = re.sub(r'\D', '', whatsapp)
    if len(digits_whatsapp) not in (10, 11):
        flash("WhatsApp inválido. Utilize um número com 10 ou 11 dígitos, ex: (11) 91234-5678.", "danger")
        return render_template_string(registration_template,
                                      theme_name=DEFAULT_TEMA["nome"],
                                      base_css=BASE_CSS,
                                      navbar=get_navbar(),
                                      toast_container=TOAST_CONTAINER,
                                      global_loading=GLOBAL_LOADING_SCRIPT,
                                      nome=nome,
                                      email=email,
                                      cpf="")

    password = request.form.get("password", "").strip()
    if len(password) < 4 or len(password) > 32:
        flash("A senha deve ter entre 4 e 32 caracteres.", "danger")
        return redirect(request.url)

    if not email or not password or not cpf or not nome or not whatsapp:
        flash("Todos os campos são obrigatórios.", "danger")
        return redirect(request.url)

    try:
        existing = tenant_table("profiles").select("*").eq("email", email).execute()
        if existing.data and len(existing.data) > 0:
            flash("Email já cadastrado. Faça login ou recupere sua senha.", "warning")
            return redirect(url_for("login_get"))

        existing_cpf = tenant_table("profiles").select("*").eq("cpf", cpf_formatado).execute()
        if existing_cpf.data and len(existing_cpf.data) > 0:
            flash(Markup(f"CPF já cadastrado. Se esqueceu seu email? <a href='/recover_email?cpf={cpf_formatado}'>Clique aqui</a>"), "warning")
            return redirect(url_for("register_route"))

        user_id = str(uuid.uuid4())
        count_resp = tenant_table("profiles").select("id", count="exact").eq("role", "client").execute()
        pilot_count = count_resp.count if hasattr(count_resp, "count") and count_resp.count is not None else len(count_resp.data or [])
        display_id = f"#{pilot_count + 1:02d}"

        profile_data = {
            "id": user_id,
            "display_id": display_id,
            "email": email,
            "password": generate_password_hash(password),
            "nome": nome,
            "cpf": cpf_formatado,
            "role": "client",
            "telefone": formatted_whatsapp,
            "idade": None,
            "descricao": "",
            "nivel": "Iniciante",
            "pontos": 0,
            "kartodromo_id": session.get("kartodromo_id")
        }

        result = tenant_table("profiles").insert(profile_data).execute()
        if not result.data:
            flash("Não foi possível criar o usuário. Por favor, tente novamente.", "danger")
            return redirect(request.url)

        flash("Cadastro realizado com sucesso! Por favor, faça login.", "success")
        return redirect(url_for("login_get"))
    except Exception as e:
        logging.error(f"Erro durante o cadastro: {e}")
        flash("Ocorreu um erro durante o cadastro. Verifique os dados informados ou contate o suporte.", "danger")
        return redirect(request.url)

@app.route("/recover_email", methods=["GET", "POST"])
def recover_email():
    if request.method == "GET":
        cpf = request.args.get("cpf")
        if cpf:
            cpf = cpf.strip()
            cpf_formatted = format_cpf(cpf)
            try:
                profile_resp = tenant_table("profiles").select("email").eq("cpf", cpf_formatted).execute()
                if profile_resp.data and len(profile_resp.data) > 0:
                    full_email = profile_resp.data[0]["email"]
                    parts = full_email.split("@")
                    username = parts[0]
                    num_to_mask = max(1, int(round(len(username) * 0.15)))
                    start_index = (len(username) - num_to_mask) // 2
                    masked_username = username[:start_index] + "*" * num_to_mask + username[start_index+num_to_mask:]
                    masked_email = masked_username + "@" + parts[1]
                    return render_template_string("""
                    <!DOCTYPE html>
                    <html lang="pt">
                    <head>
                      <meta charset="UTF-8">
                      <title>Email Recuperado - {{ theme_name }}</title>
                      {{ base_css|safe }}
                    </head>
                    <body>
                      {{ navbar|safe }}
                      {{ toast_container|safe }}
                      <div class="container my-5">
                        <div class="row justify-content-center">
                          <div class="col-12 col-md-8 col-lg-6">
                            <div class="card p-4 text-center">
                              <div class="card-body">
                                <h1>Email Recuperado</h1>
                                <p>O seu email cadastrado é: <strong>{{ masked_email }}</strong></p>
                                <a href="/login" class="btn btn-primary btn-submit">Voltar para Login</a>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                      {{ global_loading|safe }}
                      <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
                    </body>
                    </html>
                    """, theme_name=DEFAULT_TEMA["nome"], base_css=BASE_CSS,
                       navbar=get_navbar(), toast_container=TOAST_CONTAINER,
                       masked_email=masked_email, global_loading=GLOBAL_LOADING_SCRIPT)
                else:
                    flash("Nenhum usuário encontrado com esse CPF.", "warning")
                    return redirect(url_for("recover_email"))
            except Exception as e:
                flash("Erro ao recuperar email. Por favor, tente novamente.", "danger")
                return redirect(url_for("recover_email"))
        else:
            return render_template_string("""
            <!DOCTYPE html>
            <html lang="pt">
            <head>
              <meta charset="UTF-8">
              <title>Recuperar Email - {{ theme_name }}</title>
              {{ base_css|safe }}
            </head>
            <body>
              {{ navbar|safe }}
              {{ toast_container|safe }}
              <div class="container my-5">
                <div class="row justify-content-center">
                  <div class="col-12 col-md-8 col-lg-6">
                    <div class="card p-4">
                      <div class="card-body">
                        <h1 class="text-center mb-4">Recuperar Email</h1>
                        <form action="/recover_email" method="POST">
                          <div class="mb-3 text-start">
                            <label for="cpf" class="form-label">Digite seu CPF:</label>
                            <input type="text" name="cpf" id="cpf" class="form-control" required>
                          </div>
                          <button type="submit" class="btn btn-primary btn-lg btn-submit">Recuperar Email</button>
                        </form>
                        <div class="mt-3 text-center">
                          <a href="/login" class="btn btn-secondary">Voltar para Login</a>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              {{ global_loading|safe }}
              <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
            </body>
            </html>
            """, theme_name=DEFAULT_TEMA["nome"], base_css=BASE_CSS,
               navbar=get_navbar(), toast_container=TOAST_CONTAINER, global_loading=GLOBAL_LOADING_SCRIPT)
    else:
        cpf = request.form.get("cpf", "").strip()
        if not cpf:
            flash("CPF é obrigatório.", "danger")
            return redirect(request.url)
        try:
            profile_resp = tenant_table("profiles").select("email").eq("cpf", format_cpf(cpf)).execute()
            if not profile_resp.data or len(profile_resp.data) == 0:
                flash("Nenhum usuário encontrado com esse CPF.", "warning")
                return redirect(request.url)

            full_email = profile_resp.data[0]["email"]
            parts = full_email.split("@")
            masked = parts[0][0] + "*" * (len(parts[0]) - 1) if len(parts[0]) > 1 else parts[0]
            masked_email = masked + "@" + parts[1]

            flash(f"O email cadastrado é: {masked_email}", "success")
            return redirect(url_for("login_get"))
        except Exception as e:
            flash("Erro ao recuperar email. Por favor, tente novamente.", "danger")
            return redirect(request.url)

@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login_get"))

    if request.method == "GET":
        return render_template_string("""
         <!DOCTYPE html>
         <html lang="pt">
         <head>
            <meta charset="UTF-8">
            <title>Alterar Senha - {{ theme_name }}</title>
            {{ base_css|safe }}
            <style>
              .password-meter-container {
                  height: 10px;
                  background: #495057;
                  border-radius: 5px;
                  margin-top: 5px;
              }
              .password-meter-fill {
                  height: 100%;
                  width: 0%;
                  background: red;
                  border-radius: 5px;
                  transition: width 0.3s, background 0.3s;
              }
            </style>
         </head>
         <body>
            {{ navbar|safe }}
            {{ toast_container|safe }}
            <div class="container my-5">
              <div class="row justify-content-center">
                <div class="col-12 col-md-8 col-lg-6">
                  <h1 class="text-center mb-4">Alterar Senha</h1>
                  <form method="POST">
                     <div class="mb-3">
                       <label for="current_password" class="form-label">Senha Atual:</label>
                       <input type="password" name="current_password" id="current_password" class="form-control" required>
                     </div>
                     <div class="mb-3">
                       <label for="new_password" class="form-label">Nova Senha:</label>
                       <input type="password" name="new_password" id="new_password" class="form-control" required>
                       <div class="password-meter-container">
                            <div id="new-password-meter" class="password-meter-fill"></div>
                       </div>
                       <small id="new-password-strength-text" class="form-text text-muted"></small>
                     </div>
                     <div class="mb-3">
                       <label for="confirm_password" class="form-label">Confirmar Nova Senha:</label>
                       <input type="password" name="confirm_password" id="confirm_password" class="form-control" required>
                     </div>
                     <button type="submit" class="btn btn-primary w-100 btn-submit">Alterar Senha</button>
                  </form>
                  <div class="mt-3 text-center">
                    <a href="/piloto/dashboard" class="btn btn-secondary w-100">Voltar</a>
                  </div>
                </div>
              </div>
            </div>
            {{ global_loading|safe }}
            <script>
              function checkPasswordStrength(password) {
                  var strength = 0;
                  if (password.length >= 4) strength++;
                  if (password.length >= 8) strength++;
                  if (/[A-Z]/.test(password)) strength++;
                  if (/[0-9]/.test(password)) strength++;
                  if (/[^A-Za-z0-9]/.test(password)) strength++;
                  return strength;
              }
              document.addEventListener('DOMContentLoaded', function(){
                  var newPasswordInput = document.getElementById('new_password');
                  var meter = document.getElementById('new-password-meter');
                  var strengthText = document.getElementById('new-password-strength-text');

                  if(newPasswordInput) {
                      newPasswordInput.addEventListener('input', function(){
                          var val = newPasswordInput.value;
                          var strength = checkPasswordStrength(val);
                          var meterPercentage = (strength / 5) * 100;
                          meter.style.width = meterPercentage + '%';

                          if (strength <= 2) {
                              meter.style.backgroundColor = 'red';
                              strengthText.textContent = 'Fraca';
                          } else if (strength <= 4) {
                              meter.style.backgroundColor = 'orange';
                              strengthText.textContent = 'Mediana';
                          } else {
                              meter.style.backgroundColor = 'green';
                              strengthText.textContent = 'Forte';
                          }
                      });
                  }
              });
            </script>
            {{ global_loading|safe }}
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
         </body>
         </html>
         """, theme_name=DEFAULT_TEMA["nome"], base_css=BASE_CSS,
           navbar=get_navbar(), toast_container=TOAST_CONTAINER, global_loading=GLOBAL_LOADING_SCRIPT)

    current_password = request.form.get("current_password")
    new_password = request.form.get("new_password")
    confirm_password = request.form.get("confirm_password")

    if new_password != confirm_password:
        flash("As novas senhas não conferem.", "danger")
        return redirect(url_for("change_password"))
    if len(new_password) < 4 or len(new_password) > 32:
        flash("A nova senha deve ter entre 4 e 32 caracteres.", "danger")
        return redirect(url_for("change_password"))

    try:
        profile_resp = tenant_table("profiles").select("password").eq("id", user_id).execute()
        if not profile_resp.data or not check_password_hash(profile_resp.data[0]["password"], current_password):
            flash("Senha atual incorreta.", "danger")
            return redirect(url_for("change_password"))

        tenant_table("profiles").update({"password": generate_password_hash(new_password)}).eq("id", user_id).execute()
        flash("Senha alterada com sucesso!", "success")
        return redirect(url_for("dashboard_full"))
    except Exception as e:
        logging.error(f"Erro ao alterar senha: {e}")
        flash("Erro ao alterar senha. Por favor, tente novamente.", "danger")
        return redirect(url_for("change_password"))

def generate_delete_token(user_id: str) -> str:
    return serializer.dumps(user_id, salt='delete-profile')

def confirm_delete_token(token: str, expiration=3600):
    try:
        user_id = serializer.loads(token, salt='delete-profile', max_age=expiration)
        return user_id, None
    except SignatureExpired:
        return None, "Token expirado."
    except BadSignature:
        return None, "Token inválido."

def send_delete_confirmation_email(to_email: str, token: str, user_name: str):
    try:
        BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:5000")
        confirmation_link = f"{BASE_URL}/confirm_delete/{token}"

        sg = sendgrid.SendGridAPIClient(api_key=os.getenv("TWILIO_SENDGRID_API_KEY_CAMPEONATOS", "SUA_SENDGRID_KEY"))
        from_email = os.getenv("FROM_EMAIL", "contato@exemplo.com")
        subject = "Confirmação de Exclusão de Perfil"
        content = (f"Olá {user_name},\n\n"
                   "Você solicitou a exclusão do seu perfil. ATENÇÃO: Esta ação é irreversível.\n"
                   f"Por favor, confirme sua solicitação clicando no link abaixo:\n{confirmation_link}\n\n"
                   "Se você não solicitou essa ação, ignore este email.\n\n"
                   "Atenciosamente,\n"
                   "Equipe Campeonatos")

        message = Mail(from_email=from_email, to_emails=to_email, subject=subject, plain_text_content=content)
        response = sg.send(message)
        logging.info(f"Email de exclusão enviado para {to_email} (status: {response.status_code}).")
        if response.status_code >= 400:
            raise Exception("Erro ao enviar email de confirmação de exclusão")
        return response
    except Exception as e:
        logging.error(f"Erro ao enviar email de exclusão: {e}")
        raise

@app.route("/delete_profile", methods=["GET", "POST"])
@login_required
def delete_profile():
    user_id = session.get("user_id")
    try:
        profile_resp = tenant_table("profiles").select("nome, email").eq("id", user_id).execute()
        if not profile_resp.data:
            flash("Perfil não encontrado.", "warning")
            return redirect(url_for("piloto_perfil"))
        user_profile = profile_resp.data[0]
    except Exception as e:
        logging.error(f"Erro ao buscar perfil para exclusão: {e}")
        flash("Erro ao buscar perfil.", "danger")
        return redirect(url_for("piloto_perfil"))

    if request.method == "GET":
        html = f"""
        <!DOCTYPE html>
        <html lang="pt">
        <head>
            <meta charset="UTF-8">
            <title>Excluir Perfil - {DEFAULT_TEMA["nome"]}</title>
            {BASE_CSS}
        </head>
        <body>
            {get_navbar()}
            {{ toast_container|safe }}
            <div class="container my-5" style="max-width: 500px;">
                <div class="card p-4 text-center">
                    <div class="card-body">
                        <h1 class="mb-4">Excluir Perfil</h1>
                        <p>Você realmente deseja deletar seu perfil? <span class="text-danger">Esta ação é irreversível!</span></p>
                        <button type="button" class="btn btn-danger btn-lg" data-bs-toggle="modal" data-bs-target="#confirmDeleteModal">
                          Confirmar Exclusão
                        </button>
                        <a href="/piloto/perfil" class="btn btn-secondary btn-lg mt-3">Cancelar</a>
                    </div>
                </div>
            </div>
            <div class="modal fade" id="confirmDeleteModal" tabindex="-1" aria-labelledby="confirmDeleteModalLabel" aria-hidden="true">
              <div class="modal-dialog modal-dialog-centered">
                <div class="modal-content">
                  <div class="modal-header">
                    <h5 class="modal-title" id="confirmDeleteModalLabel">Confirmação de Exclusão</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Fechar"></button>
                  </div>
                  <div class="modal-body">
                    Tem certeza de que deseja excluir seu perfil? Esta ação não pode ser desfeita.
                  </div>
                  <div class="modal-footer">
                    <form method="POST">
                      <button type="submit" class="btn btn-danger btn-submit">Sim, excluir meu perfil</button>
                    </form>
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                  </div>
                </div>
              </div>
            </div>
            {{ global_loading|safe }}
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
        </body>
        </html>
        """
        return render_template_string(html, theme_name=DEFAULT_TEMA["nome"],
                                      toast_container=TOAST_CONTAINER,
                                      global_loading=GLOBAL_LOADING_SCRIPT)

    else:
        try:
            token = generate_delete_token(user_id)
            send_delete_confirmation_email(user_profile["email"], token, user_profile["nome"])
            flash("Email de confirmação enviado. Verifique seu email para confirmar a exclusão do perfil.", "success")
        except Exception as e:
            logging.error(f"Erro ao enviar email de confirmação para exclusão: {e}")
            flash("Erro ao enviar email de confirmação. Por favor, tente novamente.", "danger")

        return redirect(url_for("piloto_perfil"))

@app.route("/confirm_delete/<token>", methods=["GET"])
def confirm_delete(token: str):
    user_id, error = confirm_delete_token(token)
    if error:
        flash(f"Erro na confirmação: {error}", "danger")
        return redirect(url_for("select_role"))

    try:
        tenant_table("profiles").delete().eq("id", user_id).execute()
        session.clear()
        flash("Seu perfil foi excluído com sucesso.", "success")
    except Exception as e:
        logging.error(f"Erro ao excluir perfil: {e}")
        flash("Erro ao excluir perfil. Por favor, tente novamente.", "danger")
        return redirect(url_for("piloto_perfil"))

    return redirect(url_for("select_role"))

def calculate_battery_points(pos: int) -> int:
    mapping = {1: 20, 2: 16, 3: 12, 4: 10, 5: 8, 6: 6, 7: 4, 8: 3, 9: 2, 10: 1}
    return mapping.get(pos, 0)

def atualizar_pontos_piloto(user_id: str):
    try:
        resp = tenant_table("battery_registrations").select("posicao").eq("user_id", user_id).execute()
        regs = resp.data or []
        total = 0
        for reg in regs:
            pos = reg.get("posicao")
            if pos is not None:
                total += calculate_battery_points(pos)
        tenant_table("profiles").update({"pontos": total}).eq("id", user_id).execute()
    except Exception as e:
        logging.error(f"Erro ao atualizar pontos do piloto: {e}")

@app.route("/inscrever", methods=["POST"])
def inscrever_piloto() -> Any:
    data = request.json
    user_id = data.get("user_id")
    campeonato_id = data.get("campeonato_id")
    team_name = data.get("team_name", "")

    if not user_id or not campeonato_id:
        return jsonify({"error": "Dados incompletos para inscrição."}), 400

    try:
        camp_resp = tenant_table("campeonatos_kart_1").select("*").eq("id", campeonato_id).execute()
        if not camp_resp.data:
            return jsonify({"error": "Campeonato não encontrado."}), 404
        campeonato = camp_resp.data[0]
    except Exception:
        return jsonify({"error": "Erro ao verificar campeonato."}), 400

    if checa_inscricoes_fechadas(campeonato):
        return jsonify({"error": "Inscrições encerradas para este campeonato."}), 400

    try:
        part_resp = tenant_table("participacoes").select("*").eq("campeonato_id", campeonato_id).eq("user_id", user_id).execute()
        if part_resp.data:
            return jsonify({"error": "Você já está inscrito neste campeonato."}), 400
    except Exception:
        pass

    try:
        part_count_resp = tenant_table("participacoes").select("*", count="exact").eq("campeonato_id", campeonato_id).execute()
        inscritos_count = len(part_count_resp.data) if part_count_resp.data else 0
        if inscritos_count >= campeonato.get("max_participantes", 0):
            return jsonify({"error": "Não há vagas disponíveis neste campeonato."}), 400
    except Exception:
        pass

    try:
        participacao_data = {
            "campeonato_id": campeonato_id,
            "user_id": user_id,
            "team_name": team_name,
            "kartodromo_id": session.get("kartodromo_id")
        }
        tenant_table("participacoes").insert(participacao_data).execute()
        return jsonify({"message": "Inscrição realizada com sucesso!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/piloto/bateria_inscrever", methods=["POST"])
@login_required
def piloto_inscrever_bateria():
    user_id = session.get("user_id")
    data = request.json or {}
    bateria_id = data.get("bateria_id")
    posicao = data.get("posicao")

    if not bateria_id:
        return jsonify({"error": "bateria_id é obrigatório"}), 400

    try:
        bat_resp = tenant_table("baterias_kart_1").select("*").eq("id", bateria_id).execute()
        if not bat_resp.data:
            return jsonify({"error": "Bateria não encontrada"}), 404
    except Exception as e:
        return jsonify({"error": f"Erro ao checar bateria: {e}"}), 400

    try:
        reg_resp = tenant_table("battery_registrations").select("*").eq("bateria_id", bateria_id).eq("user_id", user_id).execute()
        if reg_resp.data:
            return jsonify({"error": "Você já está registrado nessa bateria"}), 400
    except Exception:
        pass

    try:
        insert_data = {
            "user_id": user_id,
            "bateria_id": bateria_id,
            "kartodromo_id": session.get("kartodromo_id")
        }
        if posicao is not None:
            insert_data["posicao"] = posicao

        tenant_table("battery_registrations").insert(insert_data).execute()
        atualizar_pontos_piloto(user_id)
        return jsonify({"message": "Inscrição na bateria realizada com sucesso!"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/feedback", methods=["POST"])
def feedback_route() -> Any:
    data = request.json
    try:
        data["kartodromo_id"] = session.get("kartodromo_id")
        tenant_table("feedbacks").insert(data).execute()
        return jsonify({"message": "Feedback enviado com sucesso!"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/estatisticas", methods=["GET"])
def estatisticas_route() -> Any:
    cpf = request.args.get("cpf")
    if not cpf:
        return jsonify({"error": "CPF é obrigatório para consulta de estatísticas."}), 400

    try:
        perfil_resp = tenant_table("profiles").select("id, nome, cpf, pontos").eq("cpf", cpf).execute()
        if not perfil_resp.data:
            return jsonify({"error": "Nenhum piloto encontrado para este CPF."}), 404

        pilot_info = perfil_resp.data[0]
        estat = {
            "total_corridas": 25,
            "vitórias": 10,
            "pódios": 15,
            "nome_utilizado": pilot_info["nome"],
            "pontos_atualizados": pilot_info["pontos"]
        }
        return jsonify(estat), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/streaming", methods=["GET"])
def streaming_route() -> Any:
    return jsonify({"streaming_url": STREAMING_URL}), 200

@app.route("/compartilhar", methods=["GET"])
def compartilhar_route() -> Any:
    base_url = os.getenv("BASE_URL", "http://127.0.0.1:5000")
    links = {
        "facebook": f"https://www.facebook.com/sharer/sharer.php?u={base_url}",
        "twitter": f"https://twitter.com/intent/tweet?url={base_url}",
        "whatsapp": f"https://api.whatsapp.com/send?text={base_url}"
    }
    return jsonify(links), 200

@app.route("/regras", methods=["POST"])
@admin_required
def regras_route() -> Any:
    user_id = session.get("user_id")
    try:
        profile_resp = tenant_table("profiles").select("role").eq("id", user_id).execute()
        if not profile_resp.data:
            return jsonify({"error": "Profile não encontrado"}), 404

        data = request.json
        tenant_table("regras").upsert(data).execute()
        return jsonify({"message": "Regras atualizadas com sucesso!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/config/idiomas", methods=["GET"])
def idiomas_route() -> Any:
    return jsonify({"idiomas": IDIOMAS_SUPORTADOS}), 200

@app.route("/config/streaming", methods=["POST"])
@admin_required
def streaming_config_route() -> Any:
    try:
        data = request.json
        global STREAMING_URL
        STREAMING_URL = data.get("streaming_url", STREAMING_URL)
        return jsonify({"message": "Link de streaming atualizado com sucesso!", "streaming_url": STREAMING_URL}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/admin-only", methods=["GET"])
def admin_only_route() -> Any:
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Não autenticado"}), 401

    try:
        if session.get("role") == "admin":
            return jsonify({"message": "Bem-vindo, Admin!"}), 200

        profile_resp = tenant_table("profiles").select("*").eq("id", user_id).execute()
        if not profile_resp.data:
            return jsonify({"error": "Profile não encontrado"}), 404

        prof_data = profile_resp.data[0]
        if prof_data.get("role") != "admin":
            return jsonify({"error": "Acesso negado: não é admin"}), 403

        return jsonify({"message": "Bem-vindo, Admin!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/piloto/dashboard", methods=["GET"])
@login_required
def dashboard_full() -> str:
    user_id = session.get("user_id")

    try:
        bat_resp = tenant_table("baterias_kart_1").select("*").execute()
        if bat_resp.data:
            atualiza_status_baterias(bat_resp.data)
    except Exception as e:
        logging.warning(f"Erro ao atualizar baterias no dashboard: {e}")

    try:
        campeonatos_resp = tenant_table("campeonatos_kart_1").select("id, nome, data_inicio, data_fim").execute()
        baterias_resp = tenant_table("baterias_kart_1").select("id, status").execute()
        participacoes_resp = tenant_table("participacoes").select("id").execute()
        feedbacks_resp = tenant_table("feedbacks").select("id").execute()
    except Exception as e:
        return f"<p>Erro ao coletar dados para o dashboard: {e}</p>"

    total_campeonatos = len(campeonatos_resp.data or [])
    total_baterias = len(baterias_resp.data or [])
    total_participacoes = len(participacoes_resp.data or [])
    total_feedbacks = len(feedbacks_resp.data or [])

    try:
        participacoes_piloto = tenant_table("participacoes").select("id").eq("user_id", user_id).execute()
        total_campeonatos_piloto = len(participacoes_piloto.data or [])

        baterias_piloto = tenant_table("battery_registrations").select("id, posicao").eq("user_id", user_id).execute()
        vitorias_baterias = sum(1 for reg in (baterias_piloto.data or []) if reg.get("posicao") == 1)

        campeonatos_vencidos = tenant_table("campeonatos_kart_1").select("id").eq("campeao", user_id).execute()
        vitorias_campeonatos = len(campeonatos_vencidos.data or [])

        vitorias_equipes = 3
        derrotas_equipes = 1
    except Exception as e:
        total_campeonatos_piloto = 0
        vitorias_baterias = 0
        vitorias_campeonatos = 0
        vitorias_equipes = 0
        derrotas_equipes = 0

    stats = {
        "Total de Campeonatos do Sistema": total_campeonatos,
        "Total de Baterias do Sistema": total_baterias,
        "Total de Inscrições do Sistema": total_participacoes,
        "Total de Feedbacks do Sistema": total_feedbacks,
        "Campeonatos em que Participei": total_campeonatos_piloto,
        "Vitórias em Baterias": vitorias_baterias,
        "Vitórias em Campeonatos": vitorias_campeonatos,
        "Vitórias em Equipes": vitorias_equipes,
        "Derrotas em Equipes": derrotas_equipes
    }
    labels = list(stats.keys())
    values = list(stats.values())

    stats_list_html = "".join([
        f'<li class="list-group-item d-flex justify-content-between align-items-center">\
{label}<span class="badge bg-primary rounded-pill">{value}</span></li>' for label, value in stats.items()
    ])

    breadcrumbs = render_breadcrumbs("Dashboard", "Visão Geral")

    dashboard_nav = """
    <div class="dashboard-section">
      <h3><i class="fas fa-tachometer-alt"></i> Visão Geral</h3>
      <ul class="list-unstyled">
         <li class="dashboard-item"><i class="fas fa-trophy"></i> Campeonatos</li>
         <li class="dashboard-item"><i class="fas fa-flag-checkered"></i> Baterias</li>
         <li class="dashboard-item"><i class="fas fa-users"></i> Participações</li>
         <li class="dashboard-item"><i class="fas fa-comments"></i> Feedbacks</li>
      </ul>
    </div>
    """

    html = f"""
    <!DOCTYPE html>
    <html lang="pt">
    <head>
      <meta charset="UTF-8">
      <title>Dashboard do Piloto - {DEFAULT_TEMA["nome"]}</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      {BASE_CSS}
      <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
      <style>
        .chart-container {{
            position: relative;
            margin: auto;
            height: 400px;
            width: 80%;
        }}
      </style>
    </head>
    <body>
      {get_navbar()}
      {{ toast_container|safe }}
      <div class="container my-5">
         {breadcrumbs}
         {dashboard_nav}
         <div class="card p-3 mb-4 text-center">
           <div class="card-body">
             <h1 class="mb-0">Dashboard do Piloto</h1>
           </div>
         </div>
         <div class="row">
            <div class="col-md-6">
                <ul class="list-group">
                  {stats_list_html}
                </ul>
            </div>
            <div class="col-md-6">
                <div class="chart-container">
                    <canvas id="dashboardChart"></canvas>
                </div>
            </div>
         </div>
         <div class="text-center mt-4">
            <a href="/" class="btn btn-secondary btn-lg">Voltar ao Início</a>
         </div>
      </div>
      {{ global_loading|safe }}
      <script>
         var ctx = document.getElementById('dashboardChart').getContext('2d');
         var dashboardChart = new Chart(ctx, {{
             type: 'bar',
             data: {{
                 labels: {labels},
                 datasets: [{{
                     label: 'Estatísticas',
                     data: {values},
                     backgroundColor: 'rgba(54, 162, 235, 0.6)',
                     borderColor: 'rgba(54, 162, 235, 1)',
                     borderWidth: 1
                 }}]
             }},
             options: {{
                 scales: {{
                     y: {{
                         beginAtZero: true
                     }}
                 }}
             }}
         }});
      </script>
      <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    """
    return render_template_string(html, theme_name=DEFAULT_TEMA["nome"],
                                  toast_container=TOAST_CONTAINER, global_loading=GLOBAL_LOADING_SCRIPT)

@app.route("/piloto/campeonatos", methods=["GET"])
@login_required
def piloto_campeonatos() -> str:
    try:
        resp = tenant_table("campeonatos_kart_1").select("*").execute()
        campeonatos = resp.data or []
    except Exception:
        campeonatos = []

    breadcrumbs = render_breadcrumbs("Área do Piloto", "Campeonatos")
    cards_html = ""

    for camp in campeonatos:
        camp_name = camp.get("nome", "Campeonato")
        data_inicio = camp.get("data_inicio", "")
        camp_id = camp.get("id", "")
        status = get_camp_status(camp)
        tipo = camp.get("tipo_campeonato", "solo").title()

        if status == "Aberto":
            btn_text = "Inscrever-se"
            border_color = "#28a745"
        elif status == "Em Andamento":
            btn_text = "Ver"
            border_color = "#fd7e14"
        else:
            btn_text = "Ver Resultados"
            border_color = "#dc3545"

        cards_html += f"""
        <div class="col">
          <a href="/admin/campeonato/{camp_id}" style="text-decoration: none;">
            <div class="p-3 text-center" style="border-left: 5px solid {border_color}; background: #1b263b; border-radius: 10px; box-shadow: 0 4px 8px rgba(0,0,0,0.2);">
              <h5 style="margin: 0; font-size: 1.5rem;"><i class="fas fa-medal"></i> {camp_name}</h5>
              <p style="margin: 10px 0 0;">Início: {data_inicio} <br>Tipo: {tipo}</p>
              <button class="btn btn-primary mt-2">{btn_text}</button>
            </div>
          </a>
        </div>
        """

    html = f"""
    <!DOCTYPE html>
    <html lang="pt">
    <head>
       <meta charset="UTF-8">
       <title>Campeonatos Disponíveis - {DEFAULT_TEMA["nome"]}</title>
       <meta name="viewport" content="width=device-width, initial-scale=1">
       {BASE_CSS}
    </head>
    <body>
       {get_navbar()}
       {{ toast_container|safe }}
       <div class="container my-5">
         {breadcrumbs}
         <div class="card p-3 mb-4 text-center">
           <div class="card-body">
             <h1 class="mb-0">Campeonatos Disponíveis</h1>
           </div>
         </div>
         <div class="row row-cols-1 row-cols-md-2 row-cols-lg-3 g-4">
           {cards_html if cards_html.strip() else "<p class='text-center'>Nenhum campeonato disponível.</p>"}
         </div>
         <div class="text-center mt-4">
           <a href="/piloto" class="btn btn-secondary btn-lg">Voltar</a>
         </div>
       </div>
       {{ global_loading|safe }}
       <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    """
    return render_template_string(html, theme_name=DEFAULT_TEMA["nome"],
                                  toast_container=TOAST_CONTAINER, global_loading=GLOBAL_LOADING_SCRIPT)

@app.route('/piloto', methods=["GET"])
@login_required
def pilot_interface() -> str:
    html = f"""
    <!DOCTYPE html>
    <html lang="pt">
    <head>
       <meta charset="UTF-8">
       <title>Área do Piloto - Dashboard</title>
       <meta name="viewport" content="width=device-width, initial-scale=1">
       {BASE_CSS}
    </head>
    <body>
       {get_navbar()}
       {{ toast_container|safe }}
       <div class="container my-5">
          <div class="card p-3 text-center mb-4">
            <div class="card-body">
              <h1 class="mb-0">Área do Piloto</h1>
            </div>
          </div>
          <div class="row row-cols-1 row-cols-md-2 row-cols-lg-3 g-4">
             <div class="col">
               <div class="card p-3 text-center">
                  <div class="card-body">
                    <h3><i class="fas fa-trophy"></i> Campeonatos</h3>
                    <p>Veja os campeonatos disponíveis e participe.</p>
                    <a href="/piloto/campeonatos" class="btn btn-primary btn-custom">Ver Campeonatos</a>
                  </div>
               </div>
             </div>
             <div class="col">
               <div class="card p-3 text-center">
                  <div class="card-body">
                    <h3><i class="fas fa-chart-line"></i> Meu Dashboard</h3>
                    <p>Acompanhe seu desempenho e histórico de corridas.</p>
                    <a href="/piloto/dashboard" class="btn btn-primary btn-custom">Ver Dashboard</a>
                  </div>
               </div>
             </div>
             <div class="col">
               <div class="card p-3 text-center">
                  <div class="card-body">
                    <h3><i class="fas fa-medal"></i> Rankings</h3>
                    <p>Confira sua posição e conquistas.</p>
                    <a href="/piloto/rankings" class="btn btn-primary btn-custom">Ver Rankings</a>
                  </div>
               </div>
             </div>
             <div class="col">
               <div class="card p-3 text-center">
                  <div class="card-body">
                    <h3><i class="fas fa-edit"></i> Conteúdo</h3>
                    <p>Compartilhe posts e veja publicações.</p>
                    <a href="/piloto/conteudo" class="btn btn-primary btn-custom">Ver Conteúdo</a>
                  </div>
               </div>
             </div>
             <div class="col">
               <div class="card p-3 text-center">
                  <div class="card-body">
                    <h3><i class="fas fa-layer-group"></i> Interface Completa</h3>
                    <p>Acesse todos os recursos em um só lugar.</p>
                    <a href="/piloto/interface" class="btn btn-primary btn-custom">Ver Interface</a>
                  </div>
               </div>
             </div>
             <div class="col">
               <div class="card p-3 text-center">
                  <div class="card-body">
                    <h3><i class="fas fa-comments"></i> Comunidade</h3>
                    <p>Acesse a Comunidade de Pilotos (Chat, Amigos, Clubes etc.).</p>
                    <a href="/piloto/comunidade" class="btn btn-primary btn-custom">Ver Comunidade</a>
                  </div>
               </div>
             </div>
          </div>
          <div class="text-center mt-4">
            <a href="/piloto/perfil" class="btn btn-info btn-lg">Editar Meu Perfil</a>
          </div>
       </div>
       {{ global_loading|safe }}
       <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    """
    return render_template_string(html, theme_name=DEFAULT_TEMA["nome"],
                                  toast_container=TOAST_CONTAINER, global_loading=GLOBAL_LOADING_SCRIPT)

@app.route("/piloto/perfil", methods=["GET", "POST"])
@login_required
def piloto_perfil():
    user_id = session.get("user_id")

    if request.method == "POST":
        nome = request.form.get("nome")
        email = request.form.get("email")
        telefone = request.form.get("telefone")
        idade = request.form.get("idade")
        descricao = request.form.get("descricao")

        update_data = {"nome": nome, "email": email, "telefone": telefone, "idade": idade, "descricao": descricao}
        try:
            tenant_table("profiles").update(update_data).eq("id", user_id).execute()
            session["user_name"] = nome
            flash("Perfil atualizado com sucesso!", "success")
        except Exception as e:
            logging.error(f"Erro ao atualizar perfil: {e}")
            flash("Erro ao atualizar perfil. Tente novamente ou contate o suporte.", "danger")

        return redirect(url_for("piloto_perfil"))

    try:
        profile_resp = tenant_table("profiles").select("*").eq("id", user_id).execute()
        profile = profile_resp.data[0] if profile_resp.data else {}
    except Exception as e:
        logging.error(f"Erro ao buscar perfil: {e}")
        flash("Erro ao buscar perfil.", "danger")
        profile = {}

    html = f"""
    <!DOCTYPE html>
    <html lang="pt">
    <head>
       <meta charset="UTF-8">
       <title>Editar Perfil - {DEFAULT_TEMA["nome"]}</title>
       {BASE_CSS}
    </head>
    <body>
       {get_navbar()}
       {{ toast_container|safe }}
       <div class="container my-5">
         <div class="row justify-content-center">
           <div class="col-12 col-md-8 col-lg-6">
             <h1 class="mb-4 text-center">Editar Perfil</h1>
             <form method="POST">
               <div class="mb-3">
                 <label for="nome" class="form-label">Nome:</label>
                 <input type="text" name="nome" id="nome" class="form-control" value="{profile.get("nome", "")}" required>
               </div>
               <div class="mb-3">
                 <label for="email" class="form-label">Email:</label>
                 <input type="email" name="email" id="email" class="form-control" value="{profile.get("email", "")}" required>
               </div>
               <div class="mb-3">
                 <label for="telefone" class="form-label">WhatsApp:</label>
                 <input type="text" name="telefone" id="telefone" class="form-control" value="{profile.get("telefone", "")}" placeholder="(XX) XXXXX-XXXX">
               </div>
               <div class="mb-3">
                 <label for="idade" class="form-label">Idade:</label>
                 <input type="number" name="idade" id="idade" class="form-control" value="{profile.get("idade", "")}">
               </div>
               <div class="mb-3">
                 <label for="descricao" class="form-label">Descrição:</label>
                 <textarea name="descricao" id="descricao" class="form-control" rows="3">{profile.get("descricao", "")}</textarea>
               </div>
               <button type="submit" class="btn btn-primary btn-submit w-100">Salvar Alterações</button>
             </form>
             <a href="/delete_profile" class="btn btn-danger mt-3 w-100">Deletar Meu Perfil</a>
             <a href="/piloto" class="btn btn-secondary mt-3 w-100">Voltar</a>
           </div>
         </div>
       </div>
       {{ global_loading|safe }}
       <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    """
    return render_template_string(html, theme_name=DEFAULT_TEMA["nome"],
                                  toast_container=TOAST_CONTAINER, global_loading=GLOBAL_LOADING_SCRIPT)

@app.route("/piloto/conteudo", methods=["GET", "POST"])
@login_required
def piloto_conteudo_endpoint() -> str:
    if request.method == "POST":
        post_title = request.form.get("post_title")
        post_content = request.form.get("post_content")
        media_file = request.files.get("media")

        filename_saved = None
        if media_file and media_file.filename:
            filename_saved = secure_filename(media_file.filename)
            media_file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename_saved))

        user_id = session.get("user_id")
        content_data = {
            "user_id": user_id,
            "post_title": post_title,
            "post_content": post_content,
            "media_filename": filename_saved if filename_saved else None,
            "kartodromo_id": session.get("kartodromo_id")
        }
        try:
            tenant_table("conteudos").insert(content_data).execute()
            flash("Conteúdo publicado com sucesso!", "success")
        except Exception as e:
            logging.error(f"Erro ao publicar conteúdo: {e}")
            flash("Erro ao salvar conteúdo. Tente novamente mais tarde.", "danger")

        return redirect(url_for("piloto_conteudo_endpoint"))

    breadcrumbs = render_breadcrumbs("Área do Piloto", "Conteúdo")
    html = f"""
    <!DOCTYPE html>
    <html lang="pt">
    <head>
       <meta charset="UTF-8">
       <title>Conteúdo dos Pilotos - {DEFAULT_TEMA["nome"]}</title>
       {BASE_CSS}
    </head>
    <body>
       {get_navbar()}
       {{ toast_container|safe }}
       <div class="container my-5">
         <div class="row justify-content-center">
           <div class="col-12 col-md-8 col-lg-6">
             {breadcrumbs}
             <div class="card p-3 mb-4 text-center">
               <div class="card-body">
                 <h1 class="mb-0">Compartilhe Seu Conteúdo</h1>
               </div>
             </div>
             <form method="POST" enctype="multipart/form-data">
                 <div class="mb-3 text-start">
                   <label for="post_title" class="form-label">Título do Post:</label>
                   <input type="text" class="form-control" id="post_title" name="post_title" required>
                 </div>
                 <div class="mb-3 text-start">
                   <label for="post_content" class="form-label">Conteúdo:</label>
                   <textarea class="form-control" id="post_content" name="post_content" rows="4" required></textarea>
                 </div>
                 <div class="mb-3 text-start">
                   <label for="media" class="form-label">Upload de Mídia:</label>
                   <input type="file" class="form-control" id="media" name="media">
                 </div>
                 <div class="d-grid gap-2">
                   <button type="submit" class="btn btn-primary btn-lg btn-submit">Publicar</button>
                 </div>
             </form>
             <a href="/piloto" class="btn btn-secondary btn-lg mt-3">Voltar</a>
           </div>
         </div>
       </div>
       {{ global_loading|safe }}
       <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    """
    return render_template_string(html, theme_name=DEFAULT_TEMA["nome"],
                                  toast_container=TOAST_CONTAINER, global_loading=GLOBAL_LOADING_SCRIPT)

@app.route("/piloto/interface", methods=["GET"])
@login_required
def piloto_interface_full() -> str:
    breadcrumbs = render_breadcrumbs("Área do Piloto", "Interface Completa")
    html = f"""
    <!DOCTYPE html>
    <html lang="pt">
    <head>
       <meta charset="UTF-8">
       <title>Área do Piloto - Interface Completa - {DEFAULT_TEMA["nome"]}</title>
       <meta name="viewport" content="width=device-width, initial-scale=1">
       {BASE_CSS}
       <style>
         .card {{
           transition: transform 0.2s;
         }}
         .card:hover {{
           transform: scale(1.02);
         }}
       </style>
    </head>
    <body>
      {get_navbar()}
      {{ toast_container|safe }}
      <div class="container my-5">
         {breadcrumbs}
         <div class="card p-3 mb-4 text-center">
           <div class="card-body">
             <h1 class="mb-0">Bem-vindo à Área do Piloto</h1>
           </div>
         </div>
         <div class="row row-cols-1 row-cols-md-2 g-4">
           <div class="col">
             <div class="card p-3 text-center">
               <div class="card-body">
                  <h5 class="card-title"><i class="fas fa-tachometer-alt"></i> Meu Dashboard</h5>
                  <p class="card-text">Veja seu desempenho e histórico de corridas.</p>
                  <a href="/piloto/dashboard" class="btn btn-primary btn-lg">Ver Dashboard</a>
               </div>
             </div>
           </div>
           <div class="col">
             <div class="card p-3 text-center">
               <div class="card-body">
                  <h5 class="card-title"><i class="fas fa-medal"></i> Rankings e Recompensas</h5>
                  <p class="card-text">Confira a classificação e as recompensas para os melhores pilotos.</p>
                  <a href="/piloto/rankings" class="btn btn-primary btn-lg">Ver Rankings</a>
               </div>
             </div>
           </div>
           <div class="col">
             <div class="card p-3 text-center">
               <div class="card-body">
                  <h5 class="card-title"><i class="fas fa-edit"></i> Conteúdo dos Pilotos</h5>
                  <p class="card-text">Compartilhe posts e mídias com a comunidade.</p>
                  <a href="/piloto/conteudo" class="btn btn-primary btn-lg">Ver Conteúdo</a>
               </div>
             </div>
           </div>
           <div class="col">
             <div class="card p-3 text-center">
               <div class="card-body">
                  <h5 class="card-title"><i class="fas fa-layer-group"></i> Campeonatos</h5>
                  <p class="card-text">Veja os campeonatos disponíveis e participe.</p>
                  <a href="/piloto/campeonatos" class="btn btn-primary btn-lg">Ver Campeonatos</a>
               </div>
             </div>
           </div>
           <div class="col">
             <div class="card p-3 text-center">
               <div class="card-body">
                  <h5 class="card-title"><i class="fas fa-comments"></i> Comunidade</h5>
                  <p class="card-text">Acesse a Comunidade de Pilotos (Chat, Amigos, Clubes etc.).</p>
                  <a href="/piloto/comunidade" class="btn btn-primary btn-lg">Ver Comunidade</a>
               </div>
             </div>
           </div>
         </div>
         <div class="text-center mt-4">
           <a href="/piloto" class="btn btn-secondary btn-lg">Voltar à Área do Piloto</a>
         </div>
      </div>
      {{ global_loading|safe }}
      <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    """
    return render_template_string(html, theme_name=DEFAULT_TEMA["nome"],
                                  toast_container=TOAST_CONTAINER, global_loading=GLOBAL_LOADING_SCRIPT)

@app.route("/piloto/rankings", methods=["GET"])
@login_required
def piloto_rankings():
    try:
        regs_resp = tenant_table("battery_registrations").select("user_id, posicao").execute()
        registros = regs_resp.data if regs_resp.data else []
    except Exception as e:
        return f"<p>Erro ao buscar dados de battery_registrations: {e}</p>"

    pilot_points_map = {}
    for reg in registros:
        uid = reg.get("user_id")
        pos = reg.get("posicao")
        if uid and pos is not None:
            pilot_points_map[uid] = pilot_points_map.get(uid, 0) + calculate_battery_points(pos)

    user_ids = list(pilot_points_map.keys())
    pilot_data = {}

    if user_ids:
        try:
            profiles_resp = tenant_table("profiles").select("id, nome").in_("id", user_ids).execute()
            profiles = profiles_resp.data if profiles_resp.data else []
            for p in profiles:
                pilot_data[p["id"]] = p["nome"]
        except Exception as e:
            return f"<p>Erro ao buscar perfis: {e}</p>"

    ranking_list = []
    for uid, points in pilot_points_map.items():
        pilot_name = pilot_data.get(uid, "Piloto Desconhecido")
        ranking_list.append({
            "user_id": uid,
            "nome": pilot_name,
            "pontos": points
        })

    ranking_list.sort(key=lambda x: x["pontos"], reverse=True)
    for idx, item in enumerate(ranking_list):
        item["posicao_ranking"] = idx + 1

    rows_html = "".join([
        f"""
        <tr>
          <td>{r["posicao_ranking"]}</td>
          <td>{r["nome"]}</td>
          <td>{r["pontos"]}</td>
        </tr>
        """ for r in ranking_list
    ])

    html = f"""
    <!DOCTYPE html>
    <html lang="pt">
    <head>
       <meta charset="UTF-8">
       <title>Rankings de Pilotos - {DEFAULT_TEMA["nome"]}</title>
       <meta name="viewport" content="width=device-width, initial-scale=1">
       {BASE_CSS}
       <style>
         table.table-ranking {{
            background-color: #1b263b;
         }}
         table.table-ranking thead th {{
            background-color: #343a40;
         }}
       </style>
    </head>
    <body>
       {get_navbar()}
       {{ toast_container|safe }}
       <div class="container my-5">
         <div class="card p-3 mb-4 text-center">
           <div class="card-body">
             <h1 class="mb-0">Ranking de Pilotos</h1>
           </div>
         </div>
         <div class="table-responsive">
           <table class="table table-hover table-ranking">
             <thead>
               <tr>
                 <th scope="col">Posição</th>
                 <th scope="col">Piloto</th>
                 <th scope="col">Pontos</th>
               </tr>
             </thead>
             <tbody>
               {rows_html}
             </tbody>
           </table>
         </div>
         <div class="text-center mt-4">
           <a href="/piloto" class="btn btn-secondary btn-lg">Voltar</a>
         </div>
       </div>
       {{ global_loading|safe }}
       <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    """
    return render_template_string(html, theme_name=DEFAULT_TEMA["nome"],
                                  toast_container=TOAST_CONTAINER, global_loading=GLOBAL_LOADING_SCRIPT)

@app.route("/pontuacoes", methods=["GET"])
def pontuacoes():
    html = f"""
    <!DOCTYPE html>
    <html lang="pt">
    <head>
      <meta charset="UTF-8">
      <title>Pontuações - {DEFAULT_TEMA["nome"]}</title>
      {BASE_CSS}
    </head>
    <body>
      {get_navbar()}
      {{ toast_container|safe }}
      <div class="container my-5 text-center">
        <div class="card p-3 mb-4">
          <div class="card-body">
            <h1 class="mb-0">Pontuações</h1>
          </div>
        </div>
        <p>Página de pontuações gerais ou acesso rápido à tabela detalhada.</p>
        <a href="/pontuacoes/tabela" class="btn btn-primary btn-lg">Ver Tabela Completa</a>
        <div class="mt-3">
          <a href="/" class="btn btn-secondary btn-lg">Voltar</a>
        </div>
      </div>
      {{ global_loading|safe }}
    </body>
    </html>
    """
    return render_template_string(html, theme_name=DEFAULT_TEMA["nome"],
                                  toast_container=TOAST_CONTAINER, global_loading=GLOBAL_LOADING_SCRIPT)

@app.route("/pontuacoes/tabela", methods=["GET"])
def pontuacoes_tabela():
    html = f"""
    <!DOCTYPE html>
    <html lang="pt">
    <head>
      <meta charset="UTF-8">
      <title>Tabela de Pontuações - {DEFAULT_TEMA["nome"]}</title>
      {BASE_CSS}
    </head>
    <body>
      {get_navbar()}
      {{ toast_container|safe }}
      <div class="container my-5 text-center">
        <div class="card p-3 mb-4">
          <div class="card-body">
            <h1 class="mb-0">Tabela de Pontuações</h1>
          </div>
        </div>
        <p>Aqui seria exibida a tabela detalhada de pontuações.</p>
        <a href="/pontuacoes" class="btn btn-secondary btn-lg mt-3">Voltar</a>
      </div>
      {{ global_loading|safe }}
    </body>
    </html>
    """
    return render_template_string(html, theme_name=DEFAULT_TEMA["nome"],
                                  toast_container=TOAST_CONTAINER, global_loading=GLOBAL_LOADING_SCRIPT)

@app.route("/piloto/comunidade", methods=["GET"])
@login_required
def piloto_comunidade():
    user_id = session.get("user_id")
    try:
        profile_resp = tenant_table("profiles").select("nome").eq("id", user_id).execute()
        user_name = profile_resp.data[0]["nome"] if profile_resp.data else "Piloto"
    except Exception:
        user_name = "Piloto"

    supabase_url = SUPABASE_URL
    supabase_anon_key = SUPABASE_ANON_KEY

    html = f"""
    <!DOCTYPE html>
    <html lang="pt">
    <head>
       <meta charset="UTF-8">
       <title>Comunidade - Chat Realtime</title>
       {BASE_CSS}
       <script type="module">
         import {{ createClient }} from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js/+esm'
         const supabaseUrl = '{supabase_url}'
         const supabaseAnonKey = '{supabase_anon_key}'
         const supabase = createClient(supabaseUrl, supabaseAnonKey)

         let messages = []

         async function loadMessages() {{
             let {{ data, error }} = await supabase
               .from('chat_messages')
               .select('*')
               .order('created_at', {{ ascending: true }})

             if(error) {{
               console.error('Erro ao carregar mensagens:', error)
               document.getElementById('chat-messages').innerHTML = '<p class="text-danger">Erro ao carregar mensagens. Tente recarregar a página.</p>';
               return
             }}
             messages = data || []
             updateChatUI()
         }}

         function updateChatUI() {{
           const chatDiv = document.getElementById('chat-messages')
           chatDiv.innerHTML = ''
           messages.forEach(msg => {{
             const msgEl = document.createElement('div')
             msgEl.className = 'text-break mb-2'
             const dataFormatada = new Date(msg.created_at).toLocaleString()
             msgEl.textContent = `[${{dataFormatada}}] ${{msg.user_name || 'Piloto'}}: ${{msg.content}}`
             chatDiv.appendChild(msgEl)
           }})
           chatDiv.scrollTop = chatDiv.scrollHeight
         }}

         supabase
           .channel('realtime-chat')
           .on(
             'postgres_changes',
             {{ event: 'INSERT', schema: 'public', table: 'chat_messages' }},
             payload => {{
                console.log('Nova mensagem:', payload.new)
                messages.push(payload.new)
                updateChatUI()
             }}
           )
           .subscribe()

         document.addEventListener('DOMContentLoaded', async () => {{
           await loadMessages()

           const form = document.getElementById('chat-form')
           form.addEventListener('submit', async (e) => {{
              e.preventDefault()
              const input = document.getElementById('chat-input')
              const content = input.value.trim()
              if(!content) return
              input.value = ''
              const user_name = "{user_name}"

              let {{ data, error }} = await supabase
                .from('chat_messages')
                .insert({{ user_name, content, kartodromo_id: "{session.get("kartodromo_id")}" }})
                .select()

              if(error) {{
                console.error('Erro ao inserir mensagem:', error)
                alert('Erro ao enviar mensagem. Tente novamente.')
                return
              }}
              console.log('Mensagem inserida:', data)
           }})
         }})
       </script>
       <style>
         #chat-messages {{
           border: 1px solid #ccc;
           padding: 10px;
           height: 300px;
           overflow-y: auto;
           background-color: #1b263b;
         }}
         .chat-container {{
           max-width: 700px;
           margin: 0 auto;
         }}
       </style>
    </head>
    <body>
       {get_navbar()}
       {{ toast_container|safe }}
       <div class="container my-5 chat-container">
         <h1 class="text-center mb-4">Comunidade (Realtime Chat)</h1>
         <div id="chat-messages" class="mb-3"><p>Carregando mensagens...</p></div>
         <form id="chat-form" class="input-group">
           <input type="text" id="chat-input" class="form-control" placeholder="Digite sua mensagem..." required>
           <button type="submit" class="btn btn-primary btn-submit">Enviar</button>
         </form>
         <div class="mt-4 text-center">
           <a href="/piloto" class="btn btn-secondary btn-lg">Voltar</a>
         </div>
       </div>
       {{ global_loading|safe }}
       <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    """
    return render_template_string(html, theme_name=DEFAULT_TEMA["nome"],
                                  toast_container=TOAST_CONTAINER, global_loading=GLOBAL_LOADING_SCRIPT)

@app.route("/admin", methods=["GET"])
@admin_required
def admin_home():
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="pt">
    <head>
      <meta charset="UTF-8">
      <title>Área do Administrador</title>
      {{ base_css|safe }}
    </head>
    <body>
      {{ navbar|safe }}
      {{ toast_container|safe }}
      <div class="container my-5">
        <div class="card p-4 text-center">
          <div class="card-body">
            <h1>Bem-vindo, Administrador!</h1>
            <p>Gerencie campeonatos, usuários e muito mais!</p>
            <a href="/" class="btn btn-secondary">Voltar ao Início</a>
          </div>
        </div>
      </div>
      {{ global_loading|safe }}
      <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    """, base_css=BASE_CSS, navbar=get_navbar(), toast_container=TOAST_CONTAINER, global_loading=GLOBAL_LOADING_SCRIPT)

@app.route("/admin/campeonato/<camp_id>", methods=["GET", "POST"])
@admin_required
def admin_campeonato_detail(camp_id):
    if request.method == "POST":
        nome = request.form.get("nome")
        data_inicio = request.form.get("data_inicio")
        data_fim = request.form.get("data_fim")
        max_participantes = request.form.get("max_participantes")
        tipo_campeonato = request.form.get("tipo_campeonato")

        update_data = {
            "nome": nome,
            "data_inicio": data_inicio,
            "data_fim": data_fim,
            "max_participantes": int(max_participantes) if max_participantes else None,
            "tipo_campeonato": tipo_campeonato
        }
        try:
            tenant_table("campeonatos_kart_1").update(update_data).eq("id", camp_id).execute()
            flash("Campeonato atualizado com sucesso!", "success")
        except Exception as e:
            logging.error(f"Erro ao atualizar campeonato: {e}")
            flash("Erro ao atualizar campeonato.", "danger")
        return redirect(url_for("admin_campeonato_detail", camp_id=camp_id))

    try:
        camp_resp = tenant_table("campeonatos_kart_1").select("*").eq("id", camp_id).execute()
        if not camp_resp.data:
            flash("Campeonato não encontrado.", "warning")
            return redirect(url_for("admin_home"))
        campeonato = camp_resp.data[0]

        bat_resp = tenant_table("baterias_kart_1").select("*").eq("campeonato_id", camp_id).execute()
        baterias = bat_resp.data or []
    except Exception as e:
        logging.error(f"Erro ao buscar campeonato: {e}")
        flash("Erro ao buscar campeonato.", "danger")
        return redirect(url_for("admin_home"))

    html = """
    <!DOCTYPE html>
    <html lang="pt">
    <head>
      <meta charset="UTF-8">
      <title>Detalhes do Campeonato</title>
      {{ base_css|safe }}
    </head>
    <body>
      {{ navbar|safe }}
      {{ toast_container|safe }}
      <div class="container my-5">
        <h1 class="mb-4">Detalhes do Campeonato: {{ campeonato["nome"] }}</h1>
        <form method="POST">
          <div class="mb-3">
            <label for="nome" class="form-label">Nome:</label>
            <input type="text" class="form-control" name="nome" id="nome" value="{{ campeonato["nome"] }}">
          </div>
          <div class="mb-3">
            <label for="data_inicio" class="form-label">Data Início (AAAA-MM-DD HH:MM:SS):</label>
            <input type="text" class="form-control" name="data_inicio" id="data_inicio" value="{{ campeonato["data_inicio"] }}">
          </div>
          <div class="mb-3">
            <label for="data_fim" class="form-label">Data Fim (AAAA-MM-DD HH:MM:SS):</label>
            <input type="text" class="form-control" name="data_fim" id="data_fim" value="{{ campeonato["data_fim"] }}">
          </div>
          <div class="mb-3">
            <label for="max_participantes" class="form-label">Máx. Participantes:</label>
            <input type="number" class="form-control" name="max_participantes" id="max_participantes" value="{{ campeonato["max_participantes"] if campeonato["max_participantes"] else '' }}">
          </div>
          <div class="mb-3">
            <label for="tipo_campeonato" class="form-label">Tipo de Campeonato:</label>
            <input type="text" class="form-control" name="tipo_campeonato" id="tipo_campeonato" value="{{ campeonato["tipo_campeonato"] if campeonato["tipo_campeonato"] else '' }}">
          </div>
          <button type="submit" class="btn btn-primary">Salvar</button>
          <a href="/admin" class="btn btn-secondary">Voltar</a>
        </form>

        <hr>
        <h3>Baterias relacionadas</h3>
        {% if baterias %}
          <ul class="list-group">
          {% for bat in baterias %}
            <li class="list-group-item mb-2">
              Bateria #{{ bat["id"] }} - Status: {{ bat["status"] }}
              <br>Início: {{ bat["data_hora_inicio"] }} <br>Fim: {{ bat["data_hora_fim"] }}
            </li>
          {% endfor %}
          </ul>
        {% else %}
          <p>Nenhuma bateria cadastrada para este campeonato.</p>
        {% endif %}
      </div>
      {{ global_loading|safe }}
      <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    """
    return render_template_string(html,
                                  campeonato=campeonato,
                                  baterias=baterias,
                                  base_css=BASE_CSS,
                                  navbar=get_navbar(),
                                  toast_container=TOAST_CONTAINER,
                                  global_loading=GLOBAL_LOADING_SCRIPT)

@app.route("/teams", methods=["GET"])
def list_teams():
    try:
        resp = tenant_table("teams").select("*").execute()
        teams = resp.data or []
    except Exception as e:
        logging.error(f"Erro ao buscar teams: {e}")
        teams = []

    html = f"""
    <!DOCTYPE html>
    <html lang="pt">
    <head>
      <meta charset="UTF-8">
      <title>Lista de Times</title>
      {BASE_CSS}
    </head>
    <body>
      {get_navbar()}
      {{ toast_container|safe }}
      <div class="container my-5">
        <h1 class="mb-4">Times</h1>
        <a href="/teams/create" class="btn btn-success mb-3">Criar Novo Time</a>
        <ul class="list-group">
          {"".join(f"<li class='list-group-item'>{t.get('team_name','Sem nome')}</li>" for t in teams)}
        </ul>
        <a href="/" class="btn btn-secondary mt-3">Voltar</a>
      </div>
      {{ global_loading|safe }}
      <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    """
    return render_template_string(html,
                                  toast_container=TOAST_CONTAINER,
                                  global_loading=GLOBAL_LOADING_SCRIPT)

@app.route("/teams/create", methods=["GET", "POST"])
def create_team():
    if request.method == "POST":
        team_name = request.form.get("team_name")
        if not team_name:
            flash("Nome do time é obrigatório!", "danger")
            return redirect(url_for("create_team"))
        try:
            tenant_table("teams").insert({"team_name": team_name, "kartodromo_id": session.get("kartodromo_id")}).execute()
            flash("Time criado com sucesso!", "success")
        except Exception as e:
            logging.error(f"Erro ao criar time: {e}")
            flash("Erro ao criar time.", "danger")
        return redirect(url_for("list_teams"))

    html = f"""
    <!DOCTYPE html>
    <html lang="pt">
    <head>
      <meta charset="UTF-8">
      <title>Criar Time</title>
      {BASE_CSS}
    </head>
    <body>
      {get_navbar()}
      {{ toast_container|safe }}
      <div class="container my-5">
        <h1 class="mb-4">Criar Novo Time</h1>
        <form method="POST">
          <div class="mb-3">
            <label for="team_name" class="form-label">Nome do Time:</label>
            <input type="text" class="form-control" id="team_name" name="team_name" required>
          </div>
          <button type="submit" class="btn btn-primary">Criar</button>
          <a href="/teams" class="btn btn-secondary">Voltar</a>
        </form>
      </div>
      {{ global_loading|safe }}
      <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    """
    return render_template_string(html,
                                  toast_container=TOAST_CONTAINER,
                                  global_loading=GLOBAL_LOADING_SCRIPT)

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
