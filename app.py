from flask import Flask, render_template, request, redirect, url_for, session
import os
import sqlite3
import bcrypt
from flask_session import Session

app = Flask(__name__, static_url_path='/assets', static_folder='assets', template_folder='.')

# Session config
app.secret_key = os.getenv("FLASK_SECRET_KEY", "your-secret-key")
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Initialize DB
def get_db_connection():
    conn = sqlite3.connect("database.db", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

db = get_db_connection()
with db:
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS query_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            query TEXT NOT NULL,
            timestamp TEXT NOT NULL
        );
    """)

# Home Route (serves index.html)
@app.route('/')
def home():
    return render_template('index.html')

# Signup Route
@app.route('/signup', methods=['POST'])
def signup():
    name = request.form.get('signup-name')
    email = request.form.get('signup-email')
    password = request.form.get('signup-password')

    if not (name and email and password):
        return render_template('index.html', error="All fields are required.")

    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            return render_template('index.html', error="Email already exists.")
        
        cursor.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", 
                       (name, email, hashed_pw))
        db.commit()
        return redirect(url_for('home'))
    except Exception as e:
        return render_template('index.html', error=str(e))

# Login Route
@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('login-email')
    password = request.form.get('login-password')

    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()

    if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
        session['user_id'] = user['id']
        session['user_name'] = user['name']
        return redirect(url_for('dashboard'))
    else:
        return render_template('index.html', error="Invalid credentials")

# Dashboard (after login)
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('home'))

    user_id = session['user_id']
    user_name = session['user_name']

    # Placeholder: function list (ideally from parsed codebase)
    function_list = ['init_printer()', 'parse_config()', 'main()']

    # Handle POST (user submitted a query)
    if request.method == 'POST':
        user_query = request.form.get('user-query')

        # --- RAG pipeline placeholder ---
        # In actual implementation, you'd retrieve and generate:
        # retrieved_chunks = vector_db.search(user_query)
        # response = LLM.generate(user_query + retrieved_chunks)
        response = f"Dummy response for: {user_query}"  # Replace with real logic

        # Log query to DB
        try:
            db.execute(
                "INSERT INTO query_logs (user_id, query, timestamp) VALUES (?, ?, datetime('now'))",
                (user_id, user_query)
            )
            db.commit()
        except Exception as e:
            print("DB Log Error:", e)

        # Fetch query history
        logs = db.execute(
            "SELECT query, timestamp FROM query_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10",
            (user_id,)
        ).fetchall()

        # Render with fresh answer
        return render_template(
            'dashboard.html',
            function_list=function_list,
            query_logs=logs,
            answer=response,
            metrics={
                'avg_response_time': 512,
                'hallucination_rate': 3.2,
                'semantic_score': 8.7
            },
            mermaid_diagram='''
            graph TD
            A[Main] --> B[Init]
            B --> C[Config]
            C --> D[Run]
            '''
        )

    # GET method
    logs = db.execute(
        "SELECT query, timestamp FROM query_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10",
        (user_id,)
    ).fetchall()

    return render_template(
        'dashboard.html',
        function_list=function_list,
        query_logs=logs,
        answer=None,
        metrics={
            'avg_response_time': 512,
            'hallucination_rate': 3.2,
            'semantic_score': 8.7
        },
        mermaid_diagram='''
        graph TD
        A[Main] --> B[Init]
        B --> C[Config]
        C --> D[Run]
        '''
    )

# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
