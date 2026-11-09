import os
import sqlite3
import hashlib
import secrets
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
DB_FILE = BASE_DIR / "nudl.db"

# د عامه سرور له خپرولو مخکې دا Environment Variables حتماً بدل کړئ.
SECRET_KEY = os.getenv("NUDL_SECRET_KEY", "dev-only-change-this-secret-key")
ADMIN_EMAIL = os.getenv("NUDL_ADMIN_EMAIL", "admin@nudl.edu")
ADMIN_PASSWORD = os.getenv("NUDL_ADMIN_PASSWORD", "ChangeMe123!")
TOKEN_EXPIRE_HOURS = int(os.getenv("NUDL_TOKEN_EXPIRE_HOURS", "12"))
MAX_FILE_SIZE = 25 * 1024 * 1024

app = FastAPI(
    title="Nangarhar University Digital Library API",
    description="Backend API for student, teacher and administrator digital library accounts.",
    version="1.0.0"
)

# د پرمختیا لپاره CORS خلاص دی؛ په Production کې یوازې د خپل Frontend domain ولیکئ.
allowed_origins = os.getenv("NUDL_CORS_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if allowed_origins == ["*"] else allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer(auto_error=False)


def connect():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def password_hash(password: str, salt: Optional[str] = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 250_000
    ).hex()
    return f"{salt}${digest}"


def password_matches(password: str, saved: str) -> bool:
    try:
        salt, expected = saved.split("$", 1)
        actual = password_hash(password, salt).split("$", 1)[1]
        return secrets.compare_digest(actual, expected)
    except ValueError:
        return False


def initialize_database():
    with connect() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('student','teacher','admin')),
            department TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1
        )
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS books (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            author TEXT DEFAULT '',
            department TEXT DEFAULT '',
            category TEXT DEFAULT '',
            description TEXT DEFAULT '',
            stored_filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            uploader_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending'
                CHECK(status IN ('pending','approved','rejected')),
            rejection_note TEXT DEFAULT '',
            downloads INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY(uploader_id) REFERENCES users(id)
        )
        """)
        conn.execute("""
        CREATE TABLE IF NOT EXISTS download_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            book_id INTEGER NOT NULL,
            downloaded_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(book_id) REFERENCES books(id)
        )
        """)
        admin = conn.execute(
            "SELECT id FROM users WHERE email = ?", (ADMIN_EMAIL.lower(),)
        ).fetchone()
        if not admin:
            conn.execute("""
                INSERT INTO users(full_name,email,password_hash,role,department,created_at)
                VALUES(?,?,?,?,?,?)
            """, (
                "System Administrator",
                ADMIN_EMAIL.lower(),
                password_hash(ADMIN_PASSWORD),
                "admin",
                "Administration",
                datetime.now(timezone.utc).isoformat()
            ))


initialize_database()


def make_token(user: dict) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user["id"]),
        "role": user["role"],
        "iat": now,
        "exp": now + timedelta(hours=TOKEN_EXPIRE_HOURS)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    if credentials is None:
        raise HTTPException(status_code=401, detail="Login required")
    try:
        payload = jwt.decode(
            credentials.credentials, SECRET_KEY, algorithms=["HS256"]
        )
        user_id = int(payload["sub"])
    except (JWTError, ValueError, KeyError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    with connect() as conn:
        row = conn.execute("""
            SELECT id,full_name,email,role,department,is_active,created_at
            FROM users WHERE id=?
        """, (user_id,)).fetchone()

    if not row or not row["is_active"]:
        raise HTTPException(status_code=401, detail="Account unavailable")
    return dict(row)


def require_admin(user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator permission required")
    return user


def public_user(row):
    return {
        "id": row["id"],
        "full_name": row["full_name"],
        "email": row["email"],
        "role": row["role"],
        "department": row["department"],
        "created_at": row["created_at"]
    }


@app.get("/")
def root():
    return {
        "project": "Nangarhar University Digital Library",
        "api_status": "running",
        "docs": "/docs"
    }


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/auth/register")
def register(
    full_name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    department: str = Form("")
):
    full_name = full_name.strip()
    email = email.strip().lower()
    if len(full_name) < 2:
        raise HTTPException(status_code=400, detail="Full name is too short")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if role not in ("student", "teacher"):
        raise HTTPException(status_code=400, detail="Role must be student or teacher")

    try:
        with connect() as conn:
            cur = conn.execute("""
                INSERT INTO users(full_name,email,password_hash,role,department,created_at)
                VALUES(?,?,?,?,?,?)
            """, (
                full_name, email, password_hash(password), role,
                department.strip(), datetime.now(timezone.utc).isoformat()
            ))
            row = conn.execute(
                "SELECT * FROM users WHERE id=?", (cur.lastrowid,)
            ).fetchone()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="This email is already registered")

    user = public_user(row)
    return {"access_token": make_token(user), "token_type": "bearer", "user": user}


@app.post("/api/auth/login")
def login(email: str = Form(...), password: str = Form(...)):
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE email=?", (email.strip().lower(),)
        ).fetchone()

    if not row or not password_matches(password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    if not row["is_active"]:
        raise HTTPException(status_code=403, detail="This account is disabled")

    user = public_user(row)
    return {"access_token": make_token(user), "token_type": "bearer", "user": user}


@app.get("/api/auth/me")
def my_profile(user=Depends(get_current_user)):
    return user


@app.get("/api/books")
def get_books(
    search: str = Query(default=""),
    category: str = Query(default=""),
    department: str = Query(default=""),
    user=Depends(get_current_user)
):
    sql = """
        SELECT b.id,b.title,b.author,b.department,b.category,b.description,
               b.original_filename,b.uploader_id,b.status,b.rejection_note,
               b.downloads,b.created_at,u.full_name AS uploader_name
        FROM books b JOIN users u ON u.id=b.uploader_id
        WHERE 1=1
    """
    params = []
    if user["role"] != "admin":
        sql += " AND b.status='approved'"
    if search:
        sql += " AND (b.title LIKE ? OR b.author LIKE ? OR b.description LIKE ?)"
        params.extend([f"%{search}%"] * 3)
    if category:
        sql += " AND b.category=?"
        params.append(category)
    if department:
        sql += " AND b.department=?"
        params.append(department)
    sql += " ORDER BY b.id DESC"

    with connect() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/books/{book_id}")
def get_book(book_id: int, user=Depends(get_current_user)):
    with connect() as conn:
        row = conn.execute("""
            SELECT b.id,b.title,b.author,b.department,b.category,b.description,
                   b.original_filename,b.status,b.downloads,b.created_at,
                   u.full_name AS uploader_name
            FROM books b JOIN users u ON u.id=b.uploader_id
            WHERE b.id=?
        """, (book_id,)).fetchone()
    if not row or (row["status"] != "approved" and user["role"] != "admin"):
        raise HTTPException(status_code=404, detail="Book not found")
    return dict(row)


@app.post("/api/books/upload")
async def upload_book(
    title: str = Form(...),
    author: str = Form(""),
    department: str = Form(""),
    category: str = Form(""),
    description: str = Form(""),
    pdf_file: UploadFile = File(...),
    user=Depends(get_current_user)
):
    if not pdf_file.filename or not pdf_file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files are accepted")

    content = await pdf_file.read(MAX_FILE_SIZE + 1)
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="Maximum PDF size is 25 MB")
    if not content.startswith(b"%PDF-"):
        raise HTTPException(status_code=400, detail="The file does not appear to be a valid PDF")

    stored_name = secrets.token_hex(20) + ".pdf"
    (UPLOAD_DIR / stored_name).write_bytes(content)
    status = "approved" if user["role"] == "admin" else "pending"

    try:
        with connect() as conn:
            cur = conn.execute("""
                INSERT INTO books(
                    title,author,department,category,description,
                    stored_filename,original_filename,uploader_id,status,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
            """, (
                title.strip(), author.strip(), department.strip(), category.strip(),
                description.strip(), stored_name, Path(pdf_file.filename).name,
                user["id"], status, datetime.now(timezone.utc).isoformat()
            ))
            book_id = cur.lastrowid
    except Exception:
        (UPLOAD_DIR / stored_name).unlink(missing_ok=True)
        raise

    return {
        "message": "Book uploaded successfully. It is waiting for administrator approval."
                   if status == "pending" else "Book uploaded and published.",
        "book_id": book_id,
        "status": status
    }


@app.get("/api/books/{book_id}/download")
def download_book(book_id: int, user=Depends(get_current_user)):
    with connect() as conn:
        book = conn.execute(
            "SELECT * FROM books WHERE id=?", (book_id,)
        ).fetchone()

        if not book or (book["status"] != "approved" and user["role"] != "admin"):
            raise HTTPException(status_code=404, detail="Book not found")

        file_path = UPLOAD_DIR / book["stored_filename"]
        if not file_path.is_file():
            raise HTTPException(status_code=404, detail="PDF file is missing")

        conn.execute(
            "UPDATE books SET downloads=downloads+1 WHERE id=?", (book_id,)
        )
        conn.execute("""
            INSERT INTO download_logs(user_id,book_id,downloaded_at)
            VALUES(?,?,?)
        """, (user["id"], book_id, datetime.now(timezone.utc).isoformat()))

    return FileResponse(
        path=file_path,
        media_type="application/pdf",
        filename=book["original_filename"]
    )


@app.get("/api/admin/dashboard")
def admin_dashboard(admin=Depends(require_admin)):
    with connect() as conn:
        users = conn.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
        students = conn.execute("SELECT COUNT(*) n FROM users WHERE role='student'").fetchone()["n"]
        teachers = conn.execute("SELECT COUNT(*) n FROM users WHERE role='teacher'").fetchone()["n"]
        books = conn.execute("SELECT COUNT(*) n FROM books").fetchone()["n"]
        approved = conn.execute("SELECT COUNT(*) n FROM books WHERE status='approved'").fetchone()["n"]
        pending = conn.execute("SELECT COUNT(*) n FROM books WHERE status='pending'").fetchone()["n"]
        rejected = conn.execute("SELECT COUNT(*) n FROM books WHERE status='rejected'").fetchone()["n"]
        downloads = conn.execute("SELECT COALESCE(SUM(downloads),0) n FROM books").fetchone()["n"]
    return {
        "total_users": users, "students": students, "teachers": teachers,
        "total_books": books, "approved_books": approved,
        "pending_books": pending, "rejected_books": rejected,
        "total_downloads": downloads
    }


@app.get("/api/admin/books/pending")
def pending_books(admin=Depends(require_admin)):
    with connect() as conn:
        rows = conn.execute("""
            SELECT b.*,u.full_name AS uploader_name,u.role AS uploader_role
            FROM books b JOIN users u ON u.id=b.uploader_id
            WHERE b.status='pending' ORDER BY b.created_at DESC
        """).fetchall()
    return [dict(row) for row in rows]


@app.post("/api/admin/books/{book_id}/approve")
def approve_book(book_id: int, admin=Depends(require_admin)):
    with connect() as conn:
        cur = conn.execute(
            "UPDATE books SET status='approved',rejection_note='' WHERE id=?",
            (book_id,)
        )
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Book not found")
    return {"message": "Book approved"}


@app.post("/api/admin/books/{book_id}/reject")
def reject_book(
    book_id: int,
    note: str = Form(""),
    admin=Depends(require_admin)
):
    with connect() as conn:
        cur = conn.execute(
            "UPDATE books SET status='rejected',rejection_note=? WHERE id=?",
            (note.strip(), book_id)
        )
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Book not found")
    return {"message": "Book rejected"}


@app.delete("/api/admin/books/{book_id}")
def delete_book(book_id: int, admin=Depends(require_admin)):
    with connect() as conn:
        row = conn.execute(
            "SELECT stored_filename FROM books WHERE id=?", (book_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Book not found")
        conn.execute("DELETE FROM download_logs WHERE book_id=?", (book_id,))
        conn.execute("DELETE FROM books WHERE id=?", (book_id,))
    (UPLOAD_DIR / row["stored_filename"]).unlink(missing_ok=True)
    return {"message": "Book deleted"}


@app.get("/api/admin/users")
def list_users(
    role: str = Query(default=""),
    admin=Depends(require_admin)
):
    query = """
        SELECT id,full_name,email,role,department,created_at,is_active
        FROM users WHERE 1=1
    """
    params = []
    if role in ("student", "teacher", "admin"):
        query += " AND role=?"
        params.append(role)
    query += " ORDER BY id DESC"
    with connect() as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]


@app.patch("/api/admin/users/{user_id}/status")
def set_user_status(
    user_id: int,
    active: bool = Form(...),
    admin=Depends(require_admin)
):
    if user_id == admin["id"]:
        raise HTTPException(status_code=400, detail="You cannot disable your own account")
    with connect() as conn:
        cur = conn.execute(
            "UPDATE users SET is_active=? WHERE id=? AND role!='admin'",
            (1 if active else 0, user_id)
        )
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="User not found or cannot be changed")
    return {"message": "User status updated"}


@app.get("/api/admin/reports/top-downloads")
def top_downloads(admin=Depends(require_admin)):
    with connect() as conn:
        rows = conn.execute("""
            SELECT id,title,author,downloads FROM books
            WHERE status='approved' ORDER BY downloads DESC LIMIT 10
        """).fetchall()
    return [dict(row) for row in rows]
