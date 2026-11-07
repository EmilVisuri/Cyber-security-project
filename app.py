from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
from http.cookies import SimpleCookie
from pathlib import Path
import sqlite3
import hashlib
import secrets
import time
from datetime import datetime, timezone

root = Path(__file__).parent
database = root / "notes.db"
session = {}

# fix 4: track logging
# logins = {}


def connect():
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    return connection


def password_hash(password, salt):

    # flaw 2: Cryptographic failures
    return password.encode("utf-8")

    # fiz 2: Hash passwords
    # return hashlib.pbkdf2_hmac(
    #     "sha256",
    #     password.encode("utf-8"),
    #     salt,
    #     200_000
    # )


def init_db():
    with connect() as db:

        db.execute(
            '''create table if not exists notes (
                id integer primary key,
                title text not null,
                body text not null,
                owner text)'''
                )

        db.execute(
            '''create table if not exists users (
                id integer primary key,
                username text unique not null,
                salt blob not null,
                password_hash blob not null)'''
                )

        users = [
            ("pentti", "123"),
            ("matti", "321")
        ]

        for username, password in users:
            user = db.execute(
                "select id from users where username = ?",
                (username,)
            ).fetchone()

            if user is None:
                salt = secrets.token_bytes(16)
                saved_pass = password_hash(password, salt)

                db.execute(
                    "insert into users "
                    "(username, salt, password_hash) "
                    "values (?, ?, ?)",
                    (username, salt, saved_pass)
                )



def page(notes):
    rows = ""
    for row in notes:
        rows += "<article>"
        rows += f'<h2><a href="/note/{row["id"]}">{row["title"]}</a></h2>'
        rows += f'<p>{row["body"]}</p>'
        rows += "</article>"

    template = (root / "templates" / "index.html").read_text(encoding="utf-8")

    return template.replace("<!-- NOTES -->", rows)



class handler(BaseHTTPRequestHandler):

    def token(self):
        cookies = SimpleCookie()
        cookies.load(self.headers.get("Cookie", ""))

        if "session" in cookies:
            return cookies["session"].value

        return None

    def current_user(self):
        return session.get(self.token())


    def redirect(self, location, cookie=None):
        self.send_response(303)
        self.send_header("Location", location)


        if cookie:
            self.send_header("Set-Cookie", cookie)

        self.end_headers()


    def do_GET(self):

        if self.path == "/login":
            html = (
                root / "templates" / "login.html"
            ).read_text(encoding="utf-8")

            return self.respond(html)


        if self.path == "/":
            if not self.current_user():
                return self.redirect("/login")

            with connect() as database:
                items = database.execute(
                    "select id, title, body from notes "
                    "where owner = ? order by id desc",
                    (self.current_user(),)
                ).fetchall()

            return self.respond(page(items))
        
            
        # flaw 3: SQL injection
        if self.path == "/search" or self.path.startswith("/search?"):

            if not self.current_user():
                return self.redirect("/login")

            search = parse_qs(
                self.path.partition("?")[2]
            ).get("q", [""])[0]

            with connect() as database:

                sql = (
                    "select id, title, body from notes "
                    "where owner = ? and title like '%" + search + "%' "
                    "order by id desc"
                )

                items = database.execute(
                    sql, (self.current_user(),)
                ).fetchall()

                # fix 3: fixed SQL query
                # items = database.execute(
                #     "select id, title, body from notes "
                #     "where owner = ? and title like ? "
                #     "order by id desc",
                #     (self.current_user(), f"%{search}%")
                # ).fetchall()

            return self.respond(page(items))
        
        if self.path.startswith("/note/"):

            if not self.current_user():
                return self.redirect("/login")
            
            note_id = int(self.path.split("/")[-1])


            # flaw 1: Broken access control
            with connect() as database:
                note = database.execute(
                    "select title, body from notes where id = ?",
                    (note_id,)
                ).fetchone()
                
                
            # fix 1: check the owner of the note
            # with connect() as database:
            #     note = database.execute(
            #         "select title, body from notes where id = ? and owner = ?",
            #         (note_id, self.current_user())
            #     ).fetchone()


            if note is None:
                return self.send_error(404)

            html = (
                f'<h1>{(note["title"])}</h1>'
                f'<p>{(note["body"])}</p>'
                '<a href="/">back</a>'
            )

            return self.respond(html)

        self.send_error(404)


    def do_POST(self):

        if self.path not in ("/login", "/new", "/logout"):
            return self.send_error(404)

        lenght = int(self.headers.get("Content-Length", "0"))
        fields = parse_qs(self.rfile.read(lenght).decode("utf-8"))

        if self.path == "/login":
            username = fields.get("username", [""])[0]
            password = fields.get("password", [""])[0]

            # flaw 4: Identification and authentication failures

            # fix 4: check logging attemps
            # ip = self.client_address[0]
            # attempts, blocked_until = logins.get(ip, (0, 0))
            
            # if blocked_until > time.monotonic():
            #     return self.send_error(429)
            
            # if blocked_until:
            #     logins.pop(ip, None)

            with connect() as database:
                user = database.execute(
                    "select salt, password_hash "
                    "from users where username = ?",
                    (username,)
                ).fetchone()

            if user and secrets.compare_digest(
                password_hash(password, user["salt"]),
                user["password_hash"]
            ):


                # fix 4: reset attempts
                # logins.pop(ip, None)

                token = secrets.token_urlsafe(32)
                session[token] = username

                return self.redirect(
                    "/",
                    f"session={token}"
                )


            # fix 4: count failed loggings
            # attempts, _ = logins.get(ip, (0, 0))
            # attempts += 1
            
            # if attempts >= 5:
            #     logins[ip] = (
            #         attempts,
            #         time.monotonic() + 60
            #     )
            # else:
            #     logins[ip] = (attempts, 0)


            # flaw 5: Security logging and monitoring failures

            # fix 5: log failed attempst            
            # timestamp = datetime.now(timezone.utc).isoformat()
            
            # with (root / "security.log").open("a", encoding="utf-8") as log:
            #     log.write(f"{timestamp} LOGIN_FAILED user={username!r} ip={self.client_address[0]}\n")
            

            html = (
                root / "templates" / "login.html"
            ).read_text(encoding="utf-8")

            html = html.replace(
                "<!-- ERROR -->",
                "<p>Wrong username or password</p>"
            )

            return self.respond(html, 401)


        if self.path == "/logout":
            session.pop(self.token(), None)

            return self.redirect(
                "/login",
                "session=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/"
            )

        if not self.current_user():
            return self.redirect("/login")

        title = fields.get("title", [""])[0].strip()
        body = fields.get("body", [""])[0].strip()

        if title and body:
            with connect() as database:
                database.execute(
                    "insert into notes (title, body, owner) "
                    "values (?, ?, ?)",
                    (title, body, self.current_user())
                )
                
        return self.redirect("/")

    def respond(self, html, status=200):
        data = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type","text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)



if __name__ == "__main__":
    init_db()

    server = HTTPServer(
        ("127.0.0.1", 8000),
        handler
    )

    server.serve_forever()