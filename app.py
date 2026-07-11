from flask import Flask, render_template, request, redirect, session, make_response, send_from_directory, send_file, flash
from flask_mysqldb import MySQL
from PIL import Image
from werkzeug.utils import secure_filename
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from werkzeug.security import check_password_hash, generate_password_hash
from flask import request
import os
import math
import random
import boto3
import traceback

from datetime import datetime, timedelta

app = Flask(__name__)

app.config["PROPAGATE_EXCEPTIONS"] = True
app.debug = True

# Secret Key
app.secret_key = 'supersecretkey'

# Upload Folder
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# MySQL Configuration
app.config['MYSQL_HOST'] = os.environ.get('MYSQL_HOST')
app.config['MYSQL_USER'] = os.environ.get('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.environ.get('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.environ.get('MYSQL_DB')
app.config['MYSQL_PORT'] = int(os.environ.get('MYSQL_PORT', 3306))

mysql = MySQL(app)

# AWS S3 Configuration
s3 = boto3.client(
    's3',
    aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
    region_name=os.environ.get('AWS_REGION')
)

AWS_BUCKET = os.environ.get('AWS_BUCKET_NAME')


# =========================================
# Home Page
# =========================================
@app.route('/')
def home():
    return render_template('index.html')



# =========================================
# DEBUG — check users table (REMOVE AFTER FIX)
# =========================================
@app.route('/debug_login')
def debug_login():
    try:
        cursor = mysql.connection.cursor()
        
        # Check if users table exists
        cursor.execute("SHOW TABLES LIKE 'users'")
        users_table = cursor.fetchone()
        
        if not users_table:
            return "<h2 style='color:red;font-family:sans-serif;padding:30px;'>❌ users table does not exist! Run /setup_security first.</h2>"
        
        # Check users
        cursor.execute("SELECT id, username, role, is_locked, failed_attempts FROM users")
        users = cursor.fetchall()
        cursor.close()
        
        html = "<div style='font-family:sans-serif;padding:30px;max-width:600px;'>"
        html += "<h2>🔍 Debug: Users Table</h2>"
        html += f"<p>Total users: <b>{len(users)}</b></p>"
        html += "<table border='1' cellpadding='8' style='border-collapse:collapse;width:100%;'>"
        html += "<tr style='background:#eee;'><th>ID</th><th>Username</th><th>Role</th><th>Locked</th><th>Fails</th></tr>"
        for u in users:
            html += f"<tr><td>{u[0]}</td><td>{u[1]}</td><td>{u[2]}</td><td>{u[3]}</td><td>{u[4]}</td></tr>"
        html += "</table>"
        html += "<br><p style='color:red;'>⚠️ Delete this route after debugging!</p>"
        html += "</div>"
        return html
        
    except Exception as e:
        return f"<h2 style='color:red;font-family:sans-serif;padding:30px;'>Error: {str(e)}</h2>"
    

# =========================================
# Activity Logger
# =========================================
def log_activity(username, action):

    cursor = mysql.connection.cursor()

    cursor.execute("""
        INSERT INTO activity_log
        (username, action)
        VALUES (%s, %s)
    """, (username, action))

    mysql.connection.commit()
    cursor.close()


# =========================================
# Login
# =========================================
@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        cursor = mysql.connection.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE username=%s",
            (username,)
        )

        user = cursor.fetchone()

        # User not found
        if not user:
            cursor.close()
            return render_template(
                'login.html',
                error="Invalid username or password"
            )

        # Account locked
        if user[4] == 1:

            if user[6] and datetime.now() < user[6]:
                cursor.close()
                return render_template(
                    'login.html',
                    error="Your account is locked. Please contact the administrator."
                )

            # Auto unlock after lock time
            cursor.execute("""
                UPDATE users
                SET
                    is_locked=0,
                    failed_attempts=0,
                    locked_until=NULL
                WHERE id=%s
            """, (user[0],))

            mysql.connection.commit()

            # Reload user
            cursor.execute(
                "SELECT * FROM users WHERE username=%s",
                (username,)
            )

            user = cursor.fetchone()

        # Correct password
        if check_password_hash(user[2], password):

            cursor.execute("""
                UPDATE users
                SET
                    failed_attempts=0,
                    last_login=NOW()
                WHERE id=%s
            """, (user[0],))

            mysql.connection.commit()
            cursor.close()

            session['logged_in'] = True
            session['username'] = user[1]
            session['role'] = user[3]

            log_activity(user[1], "LOGIN_SUCCESS")

            if user[3] == "admin":
                return redirect('/dashboard')
            else:
                return redirect('/student_dashboard')
 

        # Wrong password
        attempts = user[5] + 1

        if attempts >= 5:

            lock_until = datetime.now() + timedelta(minutes=15)

            cursor.execute("""
                UPDATE users
                SET
                    failed_attempts=%s,
                    is_locked=1,
                    locked_until=%s
                WHERE id=%s
            """, (attempts, lock_until, user[0]))

            mysql.connection.commit()
            cursor.close()

            return render_template(
                'login.html',
                error="Account locked for 15 minutes."
            )

        cursor.execute("""
            UPDATE users
            SET failed_attempts=%s
            WHERE id=%s
        """, (attempts, user[0]))

        mysql.connection.commit()
        cursor.close()

        return render_template(
            'login.html',
            error="Invalid username or password"
        )

    return render_template('login.html')

@app.route('/create_table')
def create_table():
    cursor = mysql.connection.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS students (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255),
        email VARCHAR(255),
        course VARCHAR(255),
        filename VARCHAR(255),
        original_size BIGINT,
        compressed_size BIGINT,
        storage_type VARCHAR(100)
    )
    """)

    mysql.connection.commit()
    cursor.close()

    return "Students table created successfully!"


# =========================================
# Dashboard
# =========================================
@app.route('/dashboard')
def dashboard():

    if 'logged_in' not in session:
        return redirect('/login')
    
    if session.get('role') != 'admin':
        return redirect('/student_dashboard')

    cursor = mysql.connection.cursor()

    # Total Students
    cursor.execute("SELECT COUNT(*) FROM students")
    total_students = cursor.fetchone()[0]
    
    # Local Storage Count
    cursor.execute(
    "SELECT COUNT(*) FROM students WHERE storage_type='Local Storage'"
)
    local_files = cursor.fetchone()[0]

# Cloud Storage Count
    cursor.execute(
    "SELECT COUNT(*) FROM students WHERE storage_type='Cloud Storage'"
)
    cloud_files = cursor.fetchone()[0]


    # Total Original Size
    cursor.execute("SELECT SUM(original_size) FROM students")
    original_size = cursor.fetchone()[0]

    if original_size is None:
        original_size = 0

    # Total Compressed Size
    cursor.execute("SELECT SUM(compressed_size) FROM students")
    compressed_size = cursor.fetchone()[0]

    if compressed_size is None:
        compressed_size = 0

    # Storage Saved
    saved = original_size - compressed_size

    # Saved Percentage
    if original_size > 0:

        saved_percentage = round(
            (saved / original_size) * 100,
            2
        )

    else:

        saved_percentage = 0

    # AI Prediction
    future_students = 1000

    if total_students > 0:

        average_storage = compressed_size / total_students

        predicted_storage = math.ceil(
            (average_storage * future_students) / 1024
        )

    else:

        predicted_storage = 0

    cursor.close()

    return render_template(
        'dashboard.html',
        total_students=total_students,
        original_size=original_size,
        compressed_size=compressed_size,
        saved_percentage=saved_percentage,
        predicted_storage=predicted_storage,
        local_files=local_files,
        cloud_files=cloud_files
    )

# =========================================
# Student Dashboard
# =========================================
@app.route('/student_dashboard')
def student_dashboard():

    if 'logged_in' not in session:
        return redirect('/login')

    if session.get('role') != 'student':
        return redirect('/dashboard')
    
    username = session['username']

    cursor = mysql.connection.cursor()

    cursor.execute("""
        SELECT *
        FROM students
        WHERE username=%s
    """, [username])

    student = cursor.fetchone()

    if student:
        files = [student]
    else:
        files = []

    cursor.close()

    return render_template(
        'student_dashboard.html',
        username=username,
        student=student,
        files=files)

# =========================================
# analytics
# =========================================

@app.route('/analytics')
def analytics():

    if 'logged_in' not in session:
        return redirect('/login')
    
    if session.get('role') != 'admin':
        return redirect('/student_dashboard')

    cursor = mysql.connection.cursor()

    # Total Students
    cursor.execute("SELECT COUNT(*) FROM students")
    total_students = cursor.fetchone()[0]

    # Original Size
    cursor.execute("SELECT SUM(original_size) FROM students")
    original_size = cursor.fetchone()[0] or 0

    # Compressed Size
    cursor.execute("SELECT SUM(compressed_size) FROM students")
    compressed_size = cursor.fetchone()[0] or 0

    # Saved Percentage
    if original_size > 0:
        saved_percentage = round(
            ((original_size - compressed_size) / original_size) * 100,
            2
        )
    else:
        saved_percentage = 0

    cursor.close()

    return render_template(
        "analytics.html",
        original_size=original_size,
        compressed_size=compressed_size,
        saved_percentage=saved_percentage,
        total_students=total_students
    )


# =========================================
# Add Student
# =========================================
@app.route('/add_student', methods=['GET', 'POST'])
def add_student():

    if 'logged_in' not in session:
        return redirect('/login')
    
    if session.get('role') != 'admin':
        return redirect('/student_dashboard')

    if request.method == 'POST':

        username = request.form['username']
        name = request.form['name']
        email = request.form['email']
        course = request.form['course']
        student_code = request.form['student_code']
        phone = request.form['phone']
        address = request.form['address']
        dob = request.form['dob']
        gender = request.form['gender']
        guardian_name = request.form['guardian_name']
        batch = request.form['batch']

        # Save to database
        cursor = mysql.connection.cursor()

        cursor.execute("""
            INSERT INTO students
            (username,name,email,course,student_code,phone,address,dob,gender,guardian_name,batch)

            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            username,
            name,
            email,
            course,
            student_code,
            phone,
            address,
            dob,
            gender,
            guardian_name,
            batch
        ))

        mysql.connection.commit()

        cursor.close()

        return redirect('/view_students')

    return render_template('add_student.html')


# =========================================
# View Students + Search
# =========================================
@app.route('/view_students')
def view_students():

    if 'logged_in' not in session:
        return redirect('/login')
    
    if session.get('role') != 'admin':
        return redirect('/student_dashboard')

    search = request.args.get('search')

    cursor = mysql.connection.cursor()

    if search:

        query = """
        SELECT * FROM students
        WHERE name LIKE %s
        OR email LIKE %s
        OR course LIKE %s
        """

        value = "%" + search + "%"

        cursor.execute(
            query,
            (value, value, value)
        )

    else:

        cursor.execute("SELECT * FROM students")

    students = cursor.fetchall()

    cursor.close()

    return render_template(
        'view_students.html',
        students=students
    )


# =========================================
# Edit Student
# =========================================
@app.route('/edit_student/<int:id>', methods=['GET', 'POST'])
def edit_student(id):

    if 'logged_in' not in session:
        return redirect('/login')

    cursor = mysql.connection.cursor()

    # Update Student
    if request.method == 'POST':

        name = request.form['name']
        email = request.form['email']
        course = request.form['course']
        student_code = request.form['student_code']
        phone = request.form['phone']

        print("PHONE =", repr(phone))
        address = request.form['address']
        dob = request.form['dob']
        gender = request.form['gender']
        guardian_name = request.form['guardian_name']
        batch = request.form['batch']

        cursor.execute("""
            UPDATE students
            SET name=%s,
                email=%s,
                course=%s,
                student_code=%s,
                phone=%s,
                address=%s,
                dob=%s,
                gender=%s,
                guardian_name=%s,
                batch=%s       
            WHERE id=%s
        """, (
            name,
            email,
            course,
            student_code,
            phone,
            address,
            dob,
            gender,
            guardian_name,
            batch,
            id
        ))

        mysql.connection.commit()

        cursor.close()

        return redirect('/student_profile/' + str(id))

    # Get Student Data
    cursor.execute(
        "SELECT * FROM students WHERE id=%s",
        [id]
    )

    student = cursor.fetchone()

    cursor.close()

    return render_template(
        'edit_student.html',
        student=student
    )


# =========================================
# Delete Student
# =========================================
@app.route('/delete_student/<int:id>')
def delete_student(id):

    if 'logged_in' not in session:
        return redirect('/login')

    cursor = mysql.connection.cursor()

    cursor.execute(
        "DELETE FROM students WHERE id=%s",
        [id]
    )

    mysql.connection.commit()

    cursor.close()

    return redirect('/view_students')

# =========================================
# Student Profile
# =========================================
@app.route('/student_profile/<int:id>')
def student_profile(id):

    if 'logged_in' not in session:
        return redirect('/login')

    cursor = mysql.connection.cursor()

    cursor.execute(
        "SELECT * FROM students WHERE id=%s",
        [id]
    )

    student = cursor.fetchone()

    cursor.close()

    if not student:
        return "Student Not Found", 404

    return render_template(
        "student_profile.html",
        student=student
    )


# =========================================
# Export PDF
# =========================================
@app.route('/export_pdf')
def export_pdf():

    if 'logged_in' not in session:
        return redirect('/login')

    cursor = mysql.connection.cursor()

    cursor.execute("SELECT * FROM students")

    students = cursor.fetchall()

    cursor.close()

    # PDF File
    pdf_file = "student_report.pdf"

    doc = SimpleDocTemplate(
        pdf_file,
        pagesize=letter
    )

    elements = []

    # Table Data
    data = [
        ['ID', 'Name', 'Email', 'Course']
    ]

    for student in students:

        data.append([
            student[0],
            student[1],
            student[2],
            student[3]
        ])

    # Table
    table = Table(data)

    # Style
    style = TableStyle([

        ('BACKGROUND', (0,0), (-1,0), colors.darkblue),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),

        ('GRID', (0,0), (-1,-1), 1, colors.black),

        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),

        ('BOTTOMPADDING', (0,0), (-1,0), 10),

        ('BACKGROUND', (0,1), (-1,-1), colors.beige)

    ])

    table.setStyle(style)

    elements.append(table)

    doc.build(elements)

    # Download Response
    response = make_response(
        open(pdf_file, 'rb').read()
    )

    response.headers['Content-Type'] = 'application/pdf'

    response.headers['Content-Disposition'] = \
        'attachment; filename=student_report.pdf'

    return response

# =========================================
# Admin Users
# =========================================
@app.route('/admin/users')
def admin_users():

    if 'logged_in' not in session:
        return redirect('/login')
    
    if session.get('role') != 'admin':
        return redirect('/student_dashboard')

    cursor = mysql.connection.cursor()

    cursor.execute("SELECT * FROM users")

    users = cursor.fetchall()

    cursor.close()

    return render_template(
        'admin_users.html',
        users=users
    )

@app.route('/admin/add_user', methods=['POST'])
def add_user():

    if 'logged_in' not in session:
        return redirect('/login')

    username = request.form['username']
    password = request.form['password']
    role = request.form['role']

    cursor = mysql.connection.cursor()

    # Check if username already exists
    cursor.execute(
        "SELECT id FROM users WHERE username=%s",
        [username]
    )

    existing_user = cursor.fetchone()

    if existing_user:
        cursor.close()
        flash("Username already exists.", "danger")
        return redirect('/admin/users')

    password_hash = generate_password_hash(password)

    cursor.execute(
        """
        INSERT INTO users
        (username, password_hash, role)
        VALUES (%s, %s, %s)
        """,
        (username, password_hash, role)
    )

    mysql.connection.commit()
    cursor.close()

    log_activity(session['username'], "ADD_USER")

    flash("User added successfully.", "success")

    return redirect('/admin/users')

@app.route('/admin/delete_user/<int:id>')
def delete_user(id):

    if 'logged_in' not in session:
        return redirect('/login')

    cursor = mysql.connection.cursor()

    # Get user details
    cursor.execute(
        "SELECT username, role FROM users WHERE id=%s",
        [id]
    )

    user = cursor.fetchone()

    if not user:
        cursor.close()
        flash("User not found.", "danger")
        return redirect('/admin/users')
    
    # Prevent deleting the currently logged-in account
    if user[0] == session['username']:
       cursor.close()
       flash("You cannot delete your own account while logged in.", "danger")
       return redirect('/admin/users')

    

    cursor.execute(
        "DELETE FROM users WHERE id=%s",
        [id]
    )

    mysql.connection.commit()
    cursor.close()

    log_activity(session['username'], "DELETE_USER")

    flash("User deleted successfully.", "success")

    return redirect('/admin/users')

@app.route('/admin/reset_password/<int:id>')
def reset_password(id):

    if 'logged_in' not in session:
        return redirect('/login')

    cursor = mysql.connection.cursor()

    # Check user exists
    cursor.execute(
        "SELECT username FROM users WHERE id=%s",
        [id]
    )

    user = cursor.fetchone()

    if not user:
        cursor.close()
        flash("User not found.", "danger")
        return redirect('/admin/users')

    # Reset password to default
    new_hash = generate_password_hash("1234")

    cursor.execute(
        """
        UPDATE users
        SET password_hash=%s,
            failed_attempts=0,
            is_locked=0,
            locked_until=NULL
        WHERE id=%s
        """,
        (new_hash, id)
    )

    mysql.connection.commit()
    cursor.close()

    log_activity(session['username'], "RESET_PASSWORD")

    flash(f"Password for '{user[0]}' has been reset to 1234.", "success")

    return redirect('/admin/users')

@app.route('/admin/unlock_user/<int:id>')
def unlock_user(id):

    if 'logged_in' not in session:
        return redirect('/login')

    cursor = mysql.connection.cursor()

    cursor.execute("""
        UPDATE users
        SET
            is_locked = 0,
            failed_attempts = 0,
            locked_until = NULL
        WHERE id=%s
    """, [id])

    mysql.connection.commit()
    cursor.close()

    flash("User account unlocked successfully.", "success")

    return redirect('/admin/users')

# =========================================
# Activity Log
# =========================================
@app.route('/admin/activity_log')
def activity_log():

    if 'logged_in' not in session:
        return redirect('/login')
    
    if session.get('role') != 'admin':
        return redirect('/student_dashboard')

    cursor = mysql.connection.cursor()

    cursor.execute("""
        SELECT *
        FROM activity_log
        ORDER BY id DESC
        LIMIT 200
    """)

    logs = cursor.fetchall()

    cursor.close()

    return render_template(
        "activity_log.html",
        logs=logs
    )

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():

    print("SESSION =", dict(session))

    if 'logged_in' not in session:
        print("User is NOT logged in")
        return redirect('/login')

    print("User is logged in:", session.get("username"))
    print("Role:", session.get("role"))

    

    if request.method == 'POST':

        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        username = session['username']

        cursor = mysql.connection.cursor()

        cursor.execute(
            "SELECT password_hash FROM users WHERE username=%s",
            [username]
        )

        user = cursor.fetchone()

        if not user:
            cursor.close()
            flash("User not found.", "danger")
            return redirect('/change_password')

        if not check_password_hash(user[0], current_password):
            cursor.close()
            flash("Current password is incorrect.", "danger")
            return redirect('/change_password')

        if new_password != confirm_password:
            cursor.close()
            flash("Passwords do not match.", "danger")
            return redirect('/change_password')

        new_hash = generate_password_hash(new_password)

        cursor.execute(
            "UPDATE users SET password_hash=%s WHERE username=%s",
            (new_hash, username)
        )

        mysql.connection.commit()
        cursor.close()

        log_activity(session['username'], "PASSWORD_CHANGED")

        flash("Password changed successfully.", "success")


        if session.get('role') == 'admin':
            return redirect('/dashboard')
        else:
            return redirect('/student_dashboard')
        
        # GET request
    return render_template("change_password.html")

        

# =========================================
# Logout
# =========================================
@app.route('/logout')
def logout():

    session.clear()

    return redirect('/login')


# Preview File
@app.route('/preview/<filename>')
def preview_file(filename):

    if 'logged_in' not in session:
        return redirect('/login')

    filepath = os.path.join(
        app.config['UPLOAD_FOLDER'],
        filename
    )

    extension = filename.split('.')[-1].lower()

    # PDF Preview
    if extension == 'pdf':

        return send_file(
            filepath,
            mimetype='application/pdf'
        )

    # Image Preview
    elif extension in ['jpg', 'jpeg', 'png']:

        return send_file(filepath)

    # DOCX
    else:

        return '''
        <h2>
            DOCX Preview Not Supported Yet
        </h2>

        <a href="/view_students">
            Back
        </a>
        '''
    
@app.route('/upload_assignment', methods=['POST'])
def upload_assignment():

    if 'logged_in' not in session:
        return redirect('/login')

    username = session['username']

    file = request.files['file']

    if file.filename == "":
        flash("Please select a file.", "danger")
        return redirect('/student_dashboard')

    cursor = mysql.connection.cursor()

    cursor.execute(
        "SELECT * FROM students WHERE username=%s",
        [username]
    )

    student = cursor.fetchone()

    if not student:
        cursor.close()
        flash("Student profile not found.", "danger")
        return redirect('/student_dashboard')

    # =========================================
    # Allowed File Types
    # =========================================

    allowed_extensions = ['png', 'jpg', 'jpeg', 'pdf', 'docx']

    file_extension = file.filename.split('.')[-1].lower()

    if file_extension not in allowed_extensions:

        cursor.close()

        flash("Only JPG, JPEG, PNG, PDF and DOCX files are allowed.", "danger")

        return redirect('/student_dashboard')

    # =========================================
    # Save File
    # =========================================

    filename = secure_filename(file.filename)

    filepath = os.path.join(
        app.config['UPLOAD_FOLDER'],
        filename
    )

    file.save(filepath)

    original_size = os.path.getsize(filepath)

    compressed_size = original_size

    # =========================================
    # Image Compression
    # =========================================

    if file_extension in ['jpg', 'jpeg', 'png']:

        compressed_filename = "compressed_" + filename

        compressed_path = os.path.join(
            app.config['UPLOAD_FOLDER'],
            compressed_filename
        )

        image = Image.open(filepath)

        image.save(
            compressed_path,
            optimize=True,
            quality=30
        )

        compressed_size = os.path.getsize(compressed_path)

    # =========================================
    # PDF / DOCX
    # =========================================

    else:

        compressed_filename = filename

    # =========================================
    # Smart Storage
    # =========================================

    if original_size > 5000000:

        storage_type = "Cloud Storage"

        s3.upload_file(
            filepath,
            AWS_BUCKET,
            filename
        )

    else:

        storage_type = "Local Storage"
        print("Local Storage")

    # =========================================
    # Update Student Record
    # =========================================

    print(filename)
    print(storage_type)
    print(username)

    cursor.execute("""
        UPDATE students
        SET
            filename=%s,
            original_size=%s,
            compressed_size=%s,
            storage_type=%s
        WHERE username=%s
    """, (
        filename,
        str(original_size),
        str(compressed_size),
        storage_type,
        username
    ))

    mysql.connection.commit()
    print("Database Updated Successfully")

    cursor.close()

    log_activity(username, "UPLOAD_ASSIGNMENT")

    flash("Assignment uploaded successfully.", "success")

    return redirect('/student_dashboard')

# Download File
@app.route('/download/<filename>')
def download_file(filename):

        if 'logged_in' not in session:
            return redirect('/login')

        return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        filename,
        as_attachment=True
    )

@app.route("/create_activity_table")
def create_activity_table():

    cursor = mysql.connection.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS activity_log (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(100),
        action VARCHAR(255),
        ip_address VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    mysql.connection.commit()
    cursor.close()

    return "Activity Log Table Created Successfully!"

@app.route("/debug_activity")
def debug_activity():

    cursor = mysql.connection.cursor()

    cursor.execute("SHOW COLUMNS FROM activity_log")

    columns = cursor.fetchall()

    cursor.close()

    return str(columns)

@app.route('/debug_students')
def debug_students():

    cursor = mysql.connection.cursor()

    cursor.execute("SHOW COLUMNS FROM students")

    columns = cursor.fetchall()

    cursor.close()

    return str(columns)

@app.route('/debug_student')
def debug_student():

    cursor = mysql.connection.cursor()

    cursor.execute("SELECT * FROM students LIMIT 1")

    data = cursor.fetchone()

    cursor.close()

    return str(data)

@app.route('/students_columns')
def students_columns():

    cursor = mysql.connection.cursor()

    cursor.execute("SHOW COLUMNS FROM students")

    columns = cursor.fetchall()

    cursor.close()

    return "<br>".join([str(c) for c in columns])

@app.route('/students_data')
def students_data():

    cursor = mysql.connection.cursor()

    cursor.execute("""
        SELECT
            id,
            name,
            phone,
            student_code,
            address,
            batch
        FROM students
    """)

    data = cursor.fetchall()

    cursor.close()

    return "<br>".join([str(row) for row in data])



@app.errorhandler(Exception)
def handle_exception(e):
    return f"<pre>{traceback.format_exc()}</pre>", 500



# =========================================
# Run App
# =========================================
if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)