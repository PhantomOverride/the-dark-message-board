import os

from model import init_database, Post
from flask import render_template, Flask, send_from_directory, request


init_database()

app = Flask(__name__, static_folder='static')

@app.route('/robots.txt')
def static_from_root():
    return send_from_directory(app.static_folder, request.path[1:])

@app.route("/")
def index():
    return render_template("login.html")


@app.route("/boards/<id>")
def board(id):
    posts = []

    if int(id) == 1:
        posts = Post.select()
    
    return render_template("board.html", posts=posts)


if __name__ == "__main__":
    if os.environ.get("FLASK_DEBUG"):
        app.run(debug=True)
    else:
        app.run()