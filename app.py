from flask import Flask, render_template, redirect, session, request
import sqlite3
from flask_bcrypt import Bcrypt
from datetime import timedelta

app = Flask(__name__)
app.secret_key = "jasoncscb20"
app.permanent_session_lifetime = timedelta(minutes=10)
bcrypt = Bcrypt(app)

def get_db_conn():
    conn = sqlite3.connect("assignment3.db")
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/")
def home():
    if 'username' in session:
        if session.get('is_instructor'):
            return render_template('index.html', is_instructor = True, username = session['username'])
        else:
            return render_template('index.html', is_instructor = False, username = session['username'])
    return redirect('/login')

@app.route('/<page_name>')
def render_page(page_name):
    if 'username' not in session:
        return redirect('/login')
    return render_template(f'{page_name}.html')

@app.route('/login', methods = ['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        if user and bcrypt.check_password_hash(user['password'], password):
                session['username'] = user['username']
                session['is_instructor'] = user['instructor'] == 1
                session.permanent = True
                conn.close()
                return redirect('/')
        else:
            conn.close()
            return render_template('login.html', error = 'Wrong username or password, please try again.')
    else:
        return render_template('login.html')


@app.route('/signup', methods = ['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        if 'instructor' in request.form:
            instructor = 1
        else:
            instructor = 0
        if not username or not password:
            return render_template('signup.html', error='Username and password cannot be empty.')
        conn = get_db_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        if cursor.fetchone():
            conn.close()
            return render_template('signup.html', error='Username is already taken by other users, please try another.')
        cursor.execute('INSERT INTO users (username, password, instructor) VALUES (?, ?, ?)', (username, hashed_password, instructor))
        if instructor == 0:
            cursor.execute('INSERT INTO StudentScores (student_name) VALUES (?)', (username,))
        conn.commit()
        conn.close()
        return redirect('/login')
    else:
        return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/grades')
def grades():
    if 'username' in session and session['is_instructor']:
        conn = get_db_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM StudentScores')
        grades_data = cursor.fetchall()
        conn.close()
        conn = get_db_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM users WHERE instructor = 0')
        students = cursor.fetchall()
        conn.close()
        return render_template('grades.html', grades = grades_data, students = students)
    else:
        return redirect('/logout')

@app.route('/grade')
def grade():
    if 'username' in session and not session['is_instructor']:
        student_name = session['username']
        conn = get_db_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM StudentScores WHERE student_name = ?', (student_name,))
        student_grade = cursor.fetchall()
        conn.close()
        return render_template('grade.html', grade = student_grade)
    else:
        return redirect('/logout')

@app.route('/update_grade', methods = ['POST'])
def update_grade():
    if 'username' in session and session['is_instructor']:
        student_name = request.form['stu_name']
        grade_item = request.form['grade_item']
        mark = request.form['mark']
        conn = get_db_conn()
        cursor = conn.cursor()
        cursor.execute('UPDATE StudentScores SET ' + grade_item + '= ? WHERE student_name = ?', (mark, student_name))
        conn.commit()
        conn.close()
        return redirect('/grades')
    else:
        return redirect('/logout')

@app.route('/feedback_student')
def feedback_student():
    if 'username' in session and not session['is_instructor']:
        conn = get_db_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM users WHERE instructor = 1')
        instructors = cursor.fetchall()
        conn.close()
        return render_template('feedback_student.html', instructors=instructors)
    return redirect('/logout')

@app.route('/update_feedback', methods = ['POST'])
def update_feedback():
    if 'username' in session and not session['is_instructor']:
        ins_name = request.form['ins_name']
        feedback_type = request.form['feedback_type']
        feedback = request.form['feedback']
        conn = get_db_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM users WHERE instructor = 1 AND username = ?', (ins_name,))
        check_ins = cursor.fetchone()
        if check_ins:
            cursor.execute('INSERT INTO Feedback (instructor_name, type, content) VALUES (?, ?, ?)', (ins_name, feedback_type, feedback))
            conn.commit()
            conn.close()
            return redirect('/feedback_student')
        else:
            conn.close()
            return render_template('feedback_student.html', error = 'Please enter a valid instructor name')
    else:
        return redirect('/logout')

@app.route('/feedback_instructor')
def view_feedback():
    if 'username' in session and session['is_instructor']:
        ins_name = session['username']
        conn = get_db_conn()
        cursor = conn.cursor()
        cursor.execute('SELECT type AS Type, content AS Feedback FROM Feedback WHERE instructor_name = ? ORDER BY 1', (ins_name,))
        feedbacks = cursor.fetchall()
        conn.close()
        return render_template('feedback_instructor.html', feedbacks = feedbacks)
    else:
        return redirect('/logout')

@app.route('/feedback')
def feedback():
    if 'username' in session and session['is_instructor']:
        return redirect('/feedback_instructor')
    if 'username' in session and not session['is_instructor']:
        return redirect('/feedback_student')
    else:
        return redirect('/logout')

@app.route('/request_regrade', methods=['POST'])
def request_regrade():
    if 'username' in session:
        student_name = session['username']
        assignment = request.form['assignment']
        conn = get_db_conn()
        cursor = conn.cursor()
        cursor.execute(f'SELECT {assignment} FROM StudentScores WHERE student_name = ?', (student_name,))
        current_grade = cursor.fetchone()[0]
        new_grade = f'{current_grade} (Regrade Request)'
        cursor.execute(f'UPDATE StudentScores SET {assignment} = ? WHERE student_name = ?', (new_grade, student_name))
        conn.commit()
        conn.close()
        return redirect('/grade')
    else:
        return redirect('/logout')

if __name__ == "__main__":
    app.run(debug=True)