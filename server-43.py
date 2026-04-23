import os
import jwt
import bcrypt
import cloudinary
import cloudinary.uploader
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client, Client

app = Flask(__name__)
CORS(app, origins="*")

# ── Config ──────────────────────────────────────────────────────────────
SUPABASE_URL  = os.environ.get("SUPABASE_URL")
SUPABASE_KEY  = os.environ.get("SUPABASE_KEY")
JWT_SECRET    = os.environ.get("JWT_SECRET", "graxbooks-secret-change-this")
ADMIN_EMAIL   = os.environ.get("ADMIN_EMAIL", "wesleiiclod@gmail.com")

cloudinary.config(
    cloud_name = os.environ.get("CLOUDINARY_CLOUD_NAME"),
    api_key    = os.environ.get("CLOUDINARY_API_KEY"),
    api_secret = os.environ.get("CLOUDINARY_API_SECRET"),
)

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


# ── Helpers JWT ──────────────────────────────────────────────────────────
def gerar_token(user_id: str, email: str, is_admin: bool) -> str:
    payload = {
        "sub":      user_id,
        "email":    email,
        "admin":    is_admin,
        "exp":      datetime.utcnow() + timedelta(days=30),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def verificar_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])


# ── Decorators ───────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"erro": "Token ausente"}), 401
        try:
            payload = verificar_token(auth.split(" ")[1])
            request.user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({"erro": "Sessão expirada, faça login novamente"}), 401
        except Exception:
            return jsonify({"erro": "Token inválido"}), 401
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"erro": "Token ausente"}), 401
        try:
            payload = verificar_token(auth.split(" ")[1])
            if not payload.get("admin"):
                return jsonify({"erro": "Acesso restrito ao administrador"}), 403
            request.user = payload
        except Exception:
            return jsonify({"erro": "Token inválido"}), 401
        return f(*args, **kwargs)
    return decorated


# ════════════════════════════════════════════════════════════════════════
#  AUTH
# ════════════════════════════════════════════════════════════════════════

@app.route("/auth/cadastro", methods=["POST"])
def cadastro():
    """Cadastro de novo usuário comum."""
    dados = request.get_json()
    nome  = dados.get("nome", "").strip()
    email = dados.get("email", "").strip().lower()
    senha = dados.get("senha", "")

    if not nome or not email or not senha:
        return jsonify({"erro": "Nome, email e senha são obrigatórios"}), 400
    if len(senha) < 6:
        return jsonify({"erro": "Senha deve ter no mínimo 6 caracteres"}), 400
    if email == ADMIN_EMAIL:
        return jsonify({"erro": "Este email não pode ser usado para cadastro"}), 400

    # Verificar se email já existe
    existe = supabase.table("usuarios").select("id").eq("email", email).execute()
    if existe.data:
        return jsonify({"erro": "Email já cadastrado"}), 409

    hash_senha = bcrypt.hashpw(senha.encode(), bcrypt.gensalt()).decode()

    novo = supabase.table("usuarios").insert({
        "nome":     nome,
        "email":    email,
        "senha":    hash_senha,
        "is_admin": False,
    }).execute()

    u = novo.data[0]
    token = gerar_token(u["id"], u["email"], False)
    return jsonify({"token": token, "usuario": {"id": u["id"], "nome": u["nome"], "email": u["email"], "admin": False}}), 201


@app.route("/auth/login", methods=["POST"])
def login():
    """Login para qualquer usuário (admin ou comum)."""
    dados = request.get_json()
    email = dados.get("email", "").strip().lower()
    senha = dados.get("senha", "")

    if not email or not senha:
        return jsonify({"erro": "Email e senha são obrigatórios"}), 400

    res = supabase.table("usuarios").select("*").eq("email", email).execute()
    if not res.data:
        return jsonify({"erro": "Email ou senha incorretos"}), 401

    u = res.data[0]
    if not bcrypt.checkpw(senha.encode(), u["senha"].encode()):
        return jsonify({"erro": "Email ou senha incorretos"}), 401

    token = gerar_token(u["id"], u["email"], u.get("is_admin", False))
    return jsonify({
        "token": token,
        "usuario": {
            "id":    u["id"],
            "nome":  u["nome"],
            "email": u["email"],
            "admin": u.get("is_admin", False),
        }
    })


@app.route("/auth/eu", methods=["GET"])
@login_required
def eu():
    """Retorna dados do usuário logado."""
    uid = request.user["sub"]
    res = supabase.table("usuarios").select("id, nome, email, is_admin, criado_em").eq("id", uid).execute()
    if not res.data:
        return jsonify({"erro": "Usuário não encontrado"}), 404
    u = res.data[0]
    u["admin"] = u.pop("is_admin", False)
    return jsonify(u)


# ════════════════════════════════════════════════════════════════════════
#  CATEGORIAS  (admin cria/edita/exclui | todos leem)
# ════════════════════════════════════════════════════════════════════════

@app.route("/categorias", methods=["GET"])
@login_required
def listar_categorias():
    res = supabase.table("categorias").select("*").order("nome").execute()
    return jsonify(res.data)


@app.route("/categorias", methods=["POST"])
@admin_required
def criar_categoria():
    d = request.get_json()
    nome  = d.get("nome", "").strip()
    icone = d.get("icone", "📚")
    cor   = d.get("cor", "#E8892A")
    if not nome:
        return jsonify({"erro": "Nome obrigatório"}), 400
    res = supabase.table("categorias").insert({"nome": nome, "icone": icone, "cor": cor}).execute()
    return jsonify(res.data[0]), 201


@app.route("/categorias/<int:cat_id>", methods=["PUT"])
@admin_required
def editar_categoria(cat_id):
    d = request.get_json()
    campos = {k: v for k, v in d.items() if k in ("nome", "icone", "cor")}
    res = supabase.table("categorias").update(campos).eq("id", cat_id).execute()
    return jsonify(res.data[0])


@app.route("/categorias/<int:cat_id>", methods=["DELETE"])
@admin_required
def excluir_categoria(cat_id):
    supabase.table("livros").update({"categoria_id": None}).eq("categoria_id", cat_id).execute()
    supabase.table("categorias").delete().eq("id", cat_id).execute()
    return jsonify({"ok": True})


# ════════════════════════════════════════════════════════════════════════
#  LIVROS  (admin gerencia | todos leem)
# ════════════════════════════════════════════════════════════════════════

@app.route("/livros", methods=["GET"])
@login_required
def listar_livros():
    categoria = request.args.get("categoria")
    busca     = request.args.get("busca", "").strip()

    query = supabase.table("livros").select(
        "id, titulo, autor, genero, tipo, categoria_id, capa_url, paginas, criado_em, categorias(nome, icone, cor)"
    ).order("criado_em", desc=True)

    if categoria:
        query = query.eq("categoria_id", categoria)

    res = query.execute()
    livros = res.data

    if busca:
        b = busca.lower()
        livros = [l for l in livros if b in l["titulo"].lower() or b in l["autor"].lower()]

    return jsonify(livros)


@app.route("/livros/<int:livro_id>", methods=["GET"])
@login_required
def obter_livro(livro_id):
    res = supabase.table("livros").select("*").eq("id", livro_id).execute()
    if not res.data:
        return jsonify({"erro": "Livro não encontrado"}), 404
    return jsonify(res.data[0])


@app.route("/livros", methods=["POST"])
@admin_required
def criar_livro():
    """Admin cria livro com capa (imagem) e PDF enviados como multipart."""
    titulo     = request.form.get("titulo", "").strip()
    autor      = request.form.get("autor", "").strip()
    genero     = request.form.get("genero", "Outro")
    tipo       = request.form.get("tipo", "public")       # public | owned
    categoria  = request.form.get("categoria_id") or None

    if not titulo or not autor:
        return jsonify({"erro": "Título e autor são obrigatórios"}), 400

    capa_url = None
    pdf_url  = None
    paginas  = 0

    # Upload capa
    if "capa" in request.files:
        capa = request.files["capa"]
        up = cloudinary.uploader.upload(capa, folder="graxbooks/capas", resource_type="image")
        capa_url = up["secure_url"]

    # Upload PDF
    if "pdf" in request.files:
        pdf = request.files["pdf"]
        up = cloudinary.uploader.upload(pdf, folder="graxbooks/pdfs", resource_type="raw")
        pdf_url = up["secure_url"]

    novo = supabase.table("livros").insert({
        "titulo":       titulo,
        "autor":        autor,
        "genero":       genero,
        "tipo":         tipo,
        "categoria_id": int(categoria) if categoria else None,
        "capa_url":     capa_url,
        "pdf_url":      pdf_url,
        "paginas":      paginas,
    }).execute()

    return jsonify(novo.data[0]), 201


@app.route("/livros/<int:livro_id>", methods=["PUT"])
@admin_required
def editar_livro(livro_id):
    """Admin edita metadados do livro."""
    d = request.get_json()
    campos = {k: v for k, v in d.items() if k in ("titulo", "autor", "genero", "tipo", "categoria_id")}
    res = supabase.table("livros").update(campos).eq("id", livro_id).execute()
    return jsonify(res.data[0])


@app.route("/livros/<int:livro_id>", methods=["DELETE"])
@admin_required
def excluir_livro(livro_id):
    supabase.table("progresso").delete().eq("livro_id", livro_id).execute()
    supabase.table("favoritos").delete().eq("livro_id", livro_id).execute()
    supabase.table("livros").delete().eq("id", livro_id).execute()
    return jsonify({"ok": True})


@app.route("/livros/<int:livro_id>/capitulos", methods=["GET"])
@login_required
def listar_capitulos(livro_id):
    res = supabase.table("capitulos").select("id, numero, titulo").eq("livro_id", livro_id).order("numero").execute()
    return jsonify(res.data)


@app.route("/livros/<int:livro_id>/capitulos/<int:cap_num>", methods=["GET"])
@login_required
def ler_capitulo(livro_id, cap_num):
    res = supabase.table("capitulos").select("*").eq("livro_id", livro_id).eq("numero", cap_num).execute()
    if not res.data:
        return jsonify({"erro": "Capítulo não encontrado"}), 404
    return jsonify(res.data[0])


# ════════════════════════════════════════════════════════════════════════
#  PROGRESSO DE LEITURA
# ════════════════════════════════════════════════════════════════════════

@app.route("/progresso/<int:livro_id>", methods=["GET"])
@login_required
def obter_progresso(livro_id):
    uid = request.user["sub"]
    res = supabase.table("progresso").select("*").eq("usuario_id", uid).eq("livro_id", livro_id).execute()
    if not res.data:
        return jsonify({"capitulo_atual": 1, "percentual": 0, "livro_id": livro_id})
    return jsonify(res.data[0])


@app.route("/progresso/<int:livro_id>", methods=["POST"])
@login_required
def salvar_progresso(livro_id):
    uid = request.user["sub"]
    d   = request.get_json()
    cap = d.get("capitulo_atual", 1)
    pct = d.get("percentual", 0)

    # Upsert
    existe = supabase.table("progresso").select("id").eq("usuario_id", uid).eq("livro_id", livro_id).execute()
    if existe.data:
        supabase.table("progresso").update({
            "capitulo_atual": cap,
            "percentual":     pct,
            "atualizado_em":  datetime.utcnow().isoformat(),
        }).eq("id", existe.data[0]["id"]).execute()
    else:
        supabase.table("progresso").insert({
            "usuario_id":     uid,
            "livro_id":       livro_id,
            "capitulo_atual": cap,
            "percentual":     pct,
        }).execute()

    return jsonify({"ok": True})


@app.route("/progresso", methods=["GET"])
@login_required
def meu_progresso():
    """Retorna progresso de todos os livros do usuário."""
    uid = request.user["sub"]
    res = supabase.table("progresso").select(
        "livro_id, capitulo_atual, percentual, atualizado_em"
    ).eq("usuario_id", uid).order("atualizado_em", desc=True).execute()
    return jsonify(res.data)


# ════════════════════════════════════════════════════════════════════════
#  FAVORITOS
# ════════════════════════════════════════════════════════════════════════

@app.route("/favoritos", methods=["GET"])
@login_required
def meus_favoritos():
    uid = request.user["sub"]
    res = supabase.table("favoritos").select(
        "livro_id, livros(id, titulo, autor, capa_url, genero)"
    ).eq("usuario_id", uid).execute()
    return jsonify(res.data)


@app.route("/favoritos/<int:livro_id>", methods=["POST"])
@login_required
def favoritar(livro_id):
    uid = request.user["sub"]
    existe = supabase.table("favoritos").select("id").eq("usuario_id", uid).eq("livro_id", livro_id).execute()
    if existe.data:
        return jsonify({"favorito": True, "msg": "Já é favorito"})
    supabase.table("favoritos").insert({"usuario_id": uid, "livro_id": livro_id}).execute()
    return jsonify({"favorito": True}), 201


@app.route("/favoritos/<int:livro_id>", methods=["DELETE"])
@login_required
def desfavoritar(livro_id):
    uid = request.user["sub"]
    supabase.table("favoritos").delete().eq("usuario_id", uid).eq("livro_id", livro_id).execute()
    return jsonify({"favorito": False})


# ════════════════════════════════════════════════════════════════════════
#  AVALIAÇÕES / NOTAS
# ════════════════════════════════════════════════════════════════════════

@app.route("/livros/<int:livro_id>/avaliacoes", methods=["GET"])
@login_required
def listar_avaliacoes(livro_id):
    """Lista todas as avaliações de um livro com nome do usuário."""
    res = supabase.table("avaliacoes").select(
        "id, nota, comentario, criado_em, usuarios(nome)"
    ).eq("livro_id", livro_id).order("criado_em", desc=True).execute()

    # Calcular média
    notas = [a["nota"] for a in res.data]
    media = round(sum(notas) / len(notas), 1) if notas else 0

    return jsonify({
        "avaliacoes": res.data,
        "media":      media,
        "total":      len(notas),
    })


@app.route("/livros/<int:livro_id>/avaliacoes/minha", methods=["GET"])
@login_required
def minha_avaliacao(livro_id):
    """Retorna a avaliação do usuário logado para um livro."""
    uid = request.user["sub"]
    res = supabase.table("avaliacoes").select("*").eq("usuario_id", uid).eq("livro_id", livro_id).execute()
    if not res.data:
        return jsonify(None)
    return jsonify(res.data[0])


@app.route("/livros/<int:livro_id>/avaliacoes", methods=["POST"])
@login_required
def avaliar_livro(livro_id):
    """Usuário avalia um livro (1-5 estrelas + comentário opcional)."""
    uid  = request.user["sub"]
    d    = request.get_json()
    nota = d.get("nota")
    comentario = d.get("comentario", "").strip()

    if nota not in [1, 2, 3, 4, 5]:
        return jsonify({"erro": "Nota deve ser entre 1 e 5"}), 400

    # Upsert — só uma avaliação por usuário por livro
    existe = supabase.table("avaliacoes").select("id").eq("usuario_id", uid).eq("livro_id", livro_id).execute()
    if existe.data:
        res = supabase.table("avaliacoes").update({
            "nota":        nota,
            "comentario":  comentario,
            "atualizado_em": datetime.utcnow().isoformat(),
        }).eq("id", existe.data[0]["id"]).execute()
    else:
        res = supabase.table("avaliacoes").insert({
            "usuario_id":  uid,
            "livro_id":    livro_id,
            "nota":        nota,
            "comentario":  comentario,
        }).execute()

    return jsonify(res.data[0]), 201


@app.route("/livros/<int:livro_id>/avaliacoes", methods=["DELETE"])
@login_required
def remover_avaliacao(livro_id):
    """Usuário remove sua própria avaliação."""
    uid = request.user["sub"]
    supabase.table("avaliacoes").delete().eq("usuario_id", uid).eq("livro_id", livro_id).execute()
    return jsonify({"ok": True})




@app.route("/admin/stats", methods=["GET"])
@admin_required
def admin_stats():
    total_livros  = supabase.table("livros").select("id", count="exact").execute().count
    total_users   = supabase.table("usuarios").select("id", count="exact").eq("is_admin", False).execute().count
    total_leituras = supabase.table("progresso").select("id", count="exact").execute().count
    total_cats    = supabase.table("categorias").select("id", count="exact").execute().count
    return jsonify({
        "livros":     total_livros,
        "usuarios":   total_users,
        "leituras":   total_leituras,
        "categorias": total_cats,
    })


@app.route("/admin/usuarios", methods=["GET"])
@admin_required
def admin_usuarios():
    res = supabase.table("usuarios").select("id, nome, email, criado_em").eq("is_admin", False).order("criado_em", desc=True).execute()
    return jsonify(res.data)


# ════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
