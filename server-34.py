import os
import io
import re
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
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
JWT_SECRET   = os.environ.get("JWT_SECRET", "graxbooks-secret")
ADMIN_EMAIL  = os.environ.get("ADMIN_EMAIL", "wesleiiclod@gmail.com")

cloudinary.config(
    cloud_name = os.environ.get("CLOUDINARY_CLOUD_NAME"),
    api_key    = os.environ.get("CLOUDINARY_API_KEY"),
    api_secret = os.environ.get("CLOUDINARY_API_SECRET"),
)

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


# ── JWT ─────────────────────────────────────────────────────────────────
def gerar_token(user_id, email, is_admin):
    return jwt.encode({
        "sub": user_id, "email": email, "admin": is_admin,
        "exp": datetime.utcnow() + timedelta(days=90),
    }, JWT_SECRET, algorithm="HS256")

def verificar_token(token):
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])


# ── Decorators ──────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"erro": "Token ausente"}), 401
        try:
            request.user = verificar_token(auth.split(" ")[1])
        except jwt.ExpiredSignatureError:
            return jsonify({"erro": "Sessão expirada"}), 401
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


# ── Health check ─────────────────────────────────────────────────────────
@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok", "app": "Grax Books API"})


# ════════════════════════════════════════════════════════════════════════
#  AUTH
# ════════════════════════════════════════════════════════════════════════
@app.route("/auth/cadastro", methods=["POST"])
def cadastro():
    d = request.get_json() or {}
    nome  = d.get("nome", "").strip()
    email = d.get("email", "").strip().lower()
    senha = d.get("senha", "")
    if not nome or not email or not senha:
        return jsonify({"erro": "Nome, email e senha obrigatórios"}), 400
    if len(senha) < 6:
        return jsonify({"erro": "Senha mínimo 6 caracteres"}), 400
    if email == ADMIN_EMAIL:
        return jsonify({"erro": "Email não permitido para cadastro"}), 400
    existe = supabase.table("usuarios").select("id").eq("email", email).execute()
    if existe.data:
        return jsonify({"erro": "Email já cadastrado"}), 409
    h = bcrypt.hashpw(senha.encode(), bcrypt.gensalt()).decode()
    u = supabase.table("usuarios").insert({"nome": nome, "email": email, "senha": h, "is_admin": False}).execute().data[0]
    return jsonify({"token": gerar_token(u["id"], u["email"], False), "usuario": {"id": u["id"], "nome": u["nome"], "email": u["email"], "admin": False}}), 201


@app.route("/auth/login", methods=["POST"])
def login():
    d = request.get_json() or {}
    email = d.get("email", "").strip().lower()
    senha = d.get("senha", "")
    if not email or not senha:
        return jsonify({"erro": "Email e senha obrigatórios"}), 400
    res = supabase.table("usuarios").select("*").eq("email", email).execute()
    if not res.data:
        return jsonify({"erro": "Email ou senha incorretos"}), 401
    u = res.data[0]
    if not bcrypt.checkpw(senha.encode(), u["senha"].encode()):
        return jsonify({"erro": "Email ou senha incorretos"}), 401
    return jsonify({
        "token": gerar_token(u["id"], u["email"], u.get("is_admin", False)),
        "usuario": {"id": u["id"], "nome": u["nome"], "email": u["email"], "admin": u.get("is_admin", False)}
    })


@app.route("/auth/eu", methods=["GET"])
@login_required
def eu():
    res = supabase.table("usuarios").select("id,nome,email,is_admin,criado_em").eq("id", request.user["sub"]).execute()
    if not res.data:
        return jsonify({"erro": "Usuário não encontrado"}), 404
    u = res.data[0]; u["admin"] = u.pop("is_admin", False)
    return jsonify(u)


# ════════════════════════════════════════════════════════════════════════
#  CATEGORIAS
# ════════════════════════════════════════════════════════════════════════
@app.route("/categorias", methods=["GET"])
@login_required
def listar_categorias():
    return jsonify(supabase.table("categorias").select("*").order("nome").execute().data)

@app.route("/categorias", methods=["POST"])
@admin_required
def criar_categoria():
    d = request.get_json() or {}
    nome = d.get("nome", "").strip()
    if not nome:
        return jsonify({"erro": "Nome obrigatório"}), 400
    res = supabase.table("categorias").insert({"nome": nome, "icone": d.get("icone","📚"), "cor": d.get("cor","#E8892A")}).execute()
    return jsonify(res.data[0]), 201

@app.route("/categorias/<int:cat_id>", methods=["PUT"])
@admin_required
def editar_categoria(cat_id):
    d = request.get_json() or {}
    campos = {k: v for k, v in d.items() if k in ("nome","icone","cor")}
    return jsonify(supabase.table("categorias").update(campos).eq("id", cat_id).execute().data[0])

@app.route("/categorias/<int:cat_id>", methods=["DELETE"])
@admin_required
def excluir_categoria(cat_id):
    supabase.table("livros").update({"categoria_id": None}).eq("categoria_id", cat_id).execute()
    supabase.table("categorias").delete().eq("id", cat_id).execute()
    return jsonify({"ok": True})


# ════════════════════════════════════════════════════════════════════════
#  LIVROS
# ════════════════════════════════════════════════════════════════════════
@app.route("/livros", methods=["GET"])
@login_required
def listar_livros():
    query = supabase.table("livros").select(
        "id,titulo,autor,genero,tipo,categoria_id,capa_url,pdf_url,paginas,criado_em"
    ).order("criado_em", desc=True)
    busca = request.args.get("busca","").strip()
    cat   = request.args.get("categoria")
    if cat:
        query = query.eq("categoria_id", cat)
    res = query.execute().data
    if busca:
        b = busca.lower()
        res = [l for l in res if b in l["titulo"].lower() or b in l["autor"].lower()]
    return jsonify(res)

@app.route("/livros/<int:livro_id>", methods=["GET"])
@login_required
def obter_livro(livro_id):
    res = supabase.table("livros").select("*").eq("id", livro_id).execute()
    if not res.data:
        return jsonify({"erro": "Não encontrado"}), 404
    return jsonify(res.data[0])

@app.route("/livros", methods=["POST"])
@admin_required
def criar_livro():
    titulo    = request.form.get("titulo","").strip()
    autor     = request.form.get("autor","").strip()
    genero    = request.form.get("genero","Outro")
    tipo      = request.form.get("tipo","public")
    categoria = request.form.get("categoria_id") or None
    if not titulo or not autor:
        return jsonify({"erro": "Título e autor obrigatórios"}), 400

    capa_url = None
    pdf_url  = None
    paginas  = 0
    capitulos = []

    # Upload capa
    if "capa" in request.files:
        try:
            up = cloudinary.uploader.upload(request.files["capa"], folder="graxbooks/capas", resource_type="image")
            capa_url = up["secure_url"]
        except Exception as e:
            print(f"Erro capa: {e}")

    # Upload PDF + extração
    if "pdf" in request.files:
        try:
            pdf_bytes = request.files["pdf"].read()
            # Upload Cloudinary
            up = cloudinary.uploader.upload(
                io.BytesIO(pdf_bytes),
                folder="graxbooks/pdfs",
                resource_type="raw",
                use_filename=True,
                unique_filename=True,
            )
            pdf_url = up["secure_url"]

            # Extrair texto com PyMuPDF com formatação inteligente
            try:
                import fitz

                doc = fitz.open(stream=pdf_bytes, filetype="pdf")
                paginas = len(doc)

                def formatar_bloco(txt):
                    """Detecta o tipo do bloco e retorna HTML formatado."""
                    txt = txt.strip()
                    if not txt or len(txt) < 3:
                        return ''

                    # Corrigir hifenização de fim de linha
                    txt = re.sub(r'-\n(\w)', r'\1', txt)
                    # Substituir quebras de linha simples por espaço
                    txt = re.sub(r'(?<!\n)\n(?!\n)', ' ', txt)
                    # Limpar espaços múltiplos
                    txt = re.sub(r' {2,}', ' ', txt).strip()

                    if len(txt) < 3:
                        return ''

                    # Detectar título de capítulo
                    # Ex: "Capítulo 1", "CAPÍTULO UM", "Chapter 1", "PARTE I"
                    eh_capitulo = bool(re.match(
                        r'^(?:cap[ií]tulo|chapter|parte|part|se[cç][aã]o|livro|book)\s*[\dIVXLCDMivxlcdm]+',
                        txt, re.IGNORECASE
                    ))

                    # Detectar linha toda em maiúsculas e curta (título)
                    eh_titulo_maiusculo = (
                        txt == txt.upper() and
                        len(txt) < 80 and
                        len(txt.split()) >= 1 and
                        not txt.isdigit()
                    )

                    # Detectar linha curta que parece título (sem ponto final, poucas palavras)
                    eh_subtitulo = (
                        len(txt) < 60 and
                        not txt.endswith('.') and
                        not txt.endswith(',') and
                        len(txt.split()) <= 8 and
                        len(txt.split()) >= 2 and
                        txt[0].isupper()
                    )

                    if eh_capitulo or eh_titulo_maiusculo:
                        # Formatar como título de capítulo
                        return f'<h2 class="cap-title">{txt}</h2>'
                    elif eh_subtitulo and not eh_titulo_maiusculo:
                        # Formatar como subtítulo apenas se realmente parecer um
                        return f'<h3 class="cap-subtitle">{txt}</h3>'
                    else:
                        # Parágrafo normal
                        return f'<p>{txt}</p>'

                # Extrair blocos por página
                paginas_html = []
                for page in doc:
                    blocos = page.get_text("blocks")
                    html_pagina = []
                    for bloco in sorted(blocos, key=lambda b: (b[1], b[0])):  # ordenar por posição y, x
                        if bloco[6] == 0:  # tipo texto
                            txt = bloco[4]
                            html = formatar_bloco(txt)
                            if html:
                                html_pagina.append(html)
                    if html_pagina:
                        paginas_html.append(html_pagina)
                doc.close()

                # Agrupar páginas em seções de leitura (10 páginas por seção)
                PAGINAS_POR_CAP = 10
                num_cap = 1
                for i in range(0, len(paginas_html), PAGINAS_POR_CAP):
                    grupo = paginas_html[i:i+PAGINAS_POR_CAP]
                    html_parts = []
                    for blocos_pagina in grupo:
                        html_parts.extend(blocos_pagina)

                    html = ''.join(html_parts)
                    if html:
                        # Detectar título do capítulo a partir do primeiro h2 encontrado
                        titulo_match = re.search(r'<h2[^>]*>([^<]+)</h2>', html)
                        titulo_cap = titulo_match.group(1).strip() if titulo_match else f"Seção {num_cap}"
                        capitulos.append({
                            "numero": num_cap,
                            "titulo": titulo_cap[:80],  # limitar tamanho do título
                            "conteudo": html
                        })
                        num_cap += 1

            except ImportError:
                capitulos = [{"numero":1,"titulo":"Conteúdo","conteudo":"<p>PyMuPDF não instalado.</p>"}]
            except Exception as e:
                capitulos = [{"numero":1,"titulo":"Conteúdo","conteudo":f"<p>Erro: {str(e)[:200]}</p>"}]
        except Exception as e:
            print(f"Erro PDF: {e}")

    # Salvar livro
    novo = supabase.table("livros").insert({
        "titulo": titulo, "autor": autor, "genero": genero, "tipo": tipo,
        "categoria_id": int(categoria) if categoria else None,
        "capa_url": capa_url, "pdf_url": pdf_url, "paginas": paginas,
    }).execute()
    livro_id = novo.data[0]["id"]

    # Salvar capítulos em lotes
    if capitulos:
        for i in range(0, len(capitulos), 50):
            lote = [{"livro_id": livro_id, "numero": c["numero"], "titulo": c["titulo"], "conteudo": c["conteudo"]} for c in capitulos[i:i+50]]
            supabase.table("capitulos").insert(lote).execute()

    resultado = novo.data[0]
    resultado["total_capitulos"] = len(capitulos)
    return jsonify(resultado), 201

@app.route("/livros/<int:livro_id>", methods=["PUT"])
@admin_required
def editar_livro(livro_id):
    d = request.get_json() or {}
    campos = {k: v for k, v in d.items() if k in ("titulo","autor","genero","tipo","categoria_id")}
    return jsonify(supabase.table("livros").update(campos).eq("id", livro_id).execute().data[0])

@app.route("/livros/<int:livro_id>", methods=["DELETE"])
@admin_required
def excluir_livro(livro_id):
    supabase.table("progresso").delete().eq("livro_id", livro_id).execute()
    supabase.table("favoritos").delete().eq("livro_id", livro_id).execute()
    supabase.table("capitulos").delete().eq("livro_id", livro_id).execute()
    supabase.table("avaliacoes").delete().eq("livro_id", livro_id).execute()
    supabase.table("livros").delete().eq("id", livro_id).execute()
    return jsonify({"ok": True})

@app.route("/livros/<int:livro_id>/capitulos", methods=["GET"])
@login_required
def listar_capitulos(livro_id):
    res = supabase.table("capitulos").select("id,numero,titulo").eq("livro_id", livro_id).order("numero").execute()
    return jsonify(res.data)

@app.route("/livros/<int:livro_id>/capitulos/<int:cap_num>", methods=["GET"])
@login_required
def ler_capitulo(livro_id, cap_num):
    res = supabase.table("capitulos").select("*").eq("livro_id", livro_id).eq("numero", cap_num).execute()
    if not res.data:
        return jsonify({"erro": "Capítulo não encontrado"}), 404
    return jsonify(res.data[0])


# ════════════════════════════════════════════════════════════════════════
#  PROGRESSO
# ════════════════════════════════════════════════════════════════════════
@app.route("/progresso/<int:livro_id>", methods=["GET"])
@login_required
def obter_progresso(livro_id):
    uid = request.user["sub"]
    res = supabase.table("progresso").select("*").eq("usuario_id", uid).eq("livro_id", livro_id).execute()
    if not res.data:
        return jsonify({"capitulo_atual": 1, "percentual": 0})
    return jsonify(res.data[0])

@app.route("/progresso/<int:livro_id>", methods=["POST"])
@login_required
def salvar_progresso(livro_id):
    uid = request.user["sub"]
    d   = request.get_json() or {}
    cap = d.get("capitulo_atual", 1)
    pct = d.get("percentual", 0)
    existe = supabase.table("progresso").select("id").eq("usuario_id", uid).eq("livro_id", livro_id).execute()
    if existe.data:
        supabase.table("progresso").update({"capitulo_atual": cap, "percentual": pct, "atualizado_em": datetime.utcnow().isoformat()}).eq("id", existe.data[0]["id"]).execute()
    else:
        supabase.table("progresso").insert({"usuario_id": uid, "livro_id": livro_id, "capitulo_atual": cap, "percentual": pct}).execute()
    return jsonify({"ok": True})

@app.route("/progresso", methods=["GET"])
@login_required
def meu_progresso():
    uid = request.user["sub"]
    res = supabase.table("progresso").select("livro_id,capitulo_atual,percentual,atualizado_em").eq("usuario_id", uid).execute()
    return jsonify(res.data)


# ════════════════════════════════════════════════════════════════════════
#  FAVORITOS
# ════════════════════════════════════════════════════════════════════════
@app.route("/favoritos", methods=["GET"])
@login_required
def meus_favoritos():
    uid = request.user["sub"]
    res = supabase.table("favoritos").select("livro_id,livros(id,titulo,autor,capa_url,genero)").eq("usuario_id", uid).execute()
    return jsonify(res.data)

@app.route("/favoritos/<int:livro_id>", methods=["POST"])
@login_required
def favoritar(livro_id):
    uid = request.user["sub"]
    existe = supabase.table("favoritos").select("id").eq("usuario_id", uid).eq("livro_id", livro_id).execute()
    if not existe.data:
        supabase.table("favoritos").insert({"usuario_id": uid, "livro_id": livro_id}).execute()
    return jsonify({"favorito": True}), 201

@app.route("/favoritos/<int:livro_id>", methods=["DELETE"])
@login_required
def desfavoritar(livro_id):
    uid = request.user["sub"]
    supabase.table("favoritos").delete().eq("usuario_id", uid).eq("livro_id", livro_id).execute()
    return jsonify({"favorito": False})


# ════════════════════════════════════════════════════════════════════════
#  AVALIAÇÕES
# ════════════════════════════════════════════════════════════════════════
@app.route("/livros/<int:livro_id>/avaliacoes", methods=["GET"])
@login_required
def listar_avaliacoes(livro_id):
    res = supabase.table("avaliacoes").select("id,nota,comentario,criado_em,usuarios(nome)").eq("livro_id", livro_id).order("criado_em", desc=True).execute()
    notas = [a["nota"] for a in res.data]
    media = round(sum(notas)/len(notas), 1) if notas else 0
    return jsonify({"avaliacoes": res.data, "media": media, "total": len(notas)})

@app.route("/livros/<int:livro_id>/avaliacoes", methods=["POST"])
@login_required
def avaliar_livro(livro_id):
    uid  = request.user["sub"]
    d    = request.get_json() or {}
    nota = d.get("nota")
    if nota not in [1,2,3,4,5]:
        return jsonify({"erro": "Nota entre 1 e 5"}), 400
    comentario = d.get("comentario","").strip()
    existe = supabase.table("avaliacoes").select("id").eq("usuario_id", uid).eq("livro_id", livro_id).execute()
    if existe.data:
        res = supabase.table("avaliacoes").update({"nota": nota, "comentario": comentario, "atualizado_em": datetime.utcnow().isoformat()}).eq("id", existe.data[0]["id"]).execute()
    else:
        res = supabase.table("avaliacoes").insert({"usuario_id": uid, "livro_id": livro_id, "nota": nota, "comentario": comentario}).execute()
    return jsonify(res.data[0]), 201

@app.route("/livros/<int:livro_id>/avaliacoes", methods=["DELETE"])
@login_required
def remover_avaliacao(livro_id):
    uid = request.user["sub"]
    supabase.table("avaliacoes").delete().eq("usuario_id", uid).eq("livro_id", livro_id).execute()
    return jsonify({"ok": True})


# ════════════════════════════════════════════════════════════════════════
#  ADMIN
# ════════════════════════════════════════════════════════════════════════
@app.route("/admin/stats", methods=["GET"])
@admin_required
def admin_stats():
    return jsonify({
        "livros":     supabase.table("livros").select("id", count="exact").execute().count or 0,
        "usuarios":   supabase.table("usuarios").select("id", count="exact").eq("is_admin", False).execute().count or 0,
        "leituras":   supabase.table("progresso").select("id", count="exact").execute().count or 0,
        "categorias": supabase.table("categorias").select("id", count="exact").execute().count or 0,
    })

@app.route("/admin/usuarios", methods=["GET"])
@admin_required
def admin_usuarios():
    res = supabase.table("usuarios").select("id,nome,email,criado_em").eq("is_admin", False).order("criado_em", desc=True).execute()
    return jsonify(res.data)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
