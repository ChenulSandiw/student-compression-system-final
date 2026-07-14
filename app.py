from flask import Flask, render_template, request, redirect, session, make_response, send_from_directory, send_file, flash, jsonify
from flask_mail import Mail, Message
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
import shutil
import requests

from datetime import datetime, timedelta

app = Flask(__name__)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')

mail = Mail(app)

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
    "SELECT COUNT(*) FROM student_files WHERE storage_type='Local Storage'"
)
    local_files = cursor.fetchone()[0]

# Cloud Storage Count
    cursor.execute(
    "SELECT COUNT(*) FROM student_files WHERE storage_type='Cloud Storage'"
)
    cloud_files = cursor.fetchone()[0]


    # Total Original Size
    cursor.execute("SELECT SUM(original_size) FROM student_files")
    original_size = cursor.fetchone()[0]

    if original_size is None:
        original_size = 0

    # Total Compressed Size
    cursor.execute("SELECT SUM(compressed_size) FROM student_files")
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

    # =========================================
    # Cloud Storage (AWS S3) Usage vs Quota
    # =========================================
    # Note: uploaded_assignment() uploads the ORIGINAL file to S3
    # (compression only happens to the local copy), so original_size
    # is what's actually sitting in the S3 bucket for cloud files.

    cloud_storage_quota_gb = 100

    cloud_storage_quota_bytes = cloud_storage_quota_gb * 1024 * 1024 * 1024

    cursor.execute(
        "SELECT SUM(original_size) FROM student_files WHERE storage_type='Cloud Storage'"
    )
    cloud_storage_used_bytes = cursor.fetchone()[0]

    if cloud_storage_used_bytes is None:
        cloud_storage_used_bytes = 0

    cloud_storage_used_gb = round(cloud_storage_used_bytes / (1024 ** 3), 2)

    cloud_storage_remaining_gb = round(
        (cloud_storage_quota_bytes - cloud_storage_used_bytes) / (1024 ** 3), 2
    )

    if cloud_storage_remaining_gb < 0:
        cloud_storage_remaining_gb = 0

    if cloud_storage_quota_bytes > 0:
        cloud_storage_percent_used = round(
            (cloud_storage_used_bytes / cloud_storage_quota_bytes) * 100, 2
        )
    else:
        cloud_storage_percent_used = 0

    if cloud_storage_percent_used > 100:
        cloud_storage_percent_used = 100

    cursor.close()

    return render_template(
        'dashboard.html',
        total_students=total_students,
        original_size=original_size,
        compressed_size=compressed_size,
        saved_percentage=saved_percentage,
        predicted_storage=predicted_storage,
        local_files=local_files,

        cloud_storage_quota_gb=cloud_storage_quota_gb,
        cloud_storage_used_gb=cloud_storage_used_gb,
        cloud_storage_remaining_gb=cloud_storage_remaining_gb,
        cloud_storage_percent_used=cloud_storage_percent_used,
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

    active_tab = request.args.get('tab', 'profile')


    cursor = mysql.connection.cursor()

    cursor.execute("""
        SELECT *
        FROM students
        WHERE username=%s
    """, [username])

    student = cursor.fetchone()

    # Uploaded Files
    cursor.execute("""
        SELECT *
        FROM student_files
        WHERE username=%s
        ORDER BY uploaded_at DESC
    """, [username])

    files = cursor.fetchall()


    total_files = len(files)

    local_files = 0
    cloud_files = 0

    total_original = 0
    total_compressed = 0
    photo_count = 0

    for f in files:
        filename = f[2]

        if filename.lower().endswith(('.jpg', '.jpeg', '.png')):
            photo_count += 1

        if f[5] == "Local Storage":
            local_files += 1

        elif f[5] == "Cloud Storage":
            cloud_files += 1

        if f[3]:
            total_original += int(f[3])

        if f[4]:
            total_compressed += int(f[4])

            

    saved_bytes = total_original - total_compressed

    total_original_mb = round(total_original / 1024 / 1024, 2)

    total_compressed_mb = round(total_compressed / 1024 / 1024, 2)

    saved_mb = round(saved_bytes / 1024 / 1024, 2)

    if total_original > 0:
        saved_percent = round((saved_bytes / total_original) * 100, 1)
    else:
        saved_percent = 0

    cursor.close()

    auto_download_filename = session.pop('auto_download_file', None)

    disk_total, disk_used, disk_free = shutil.disk_usage(app.config['UPLOAD_FOLDER'])

    disk_percent_used = round((disk_used / disk_total) * 100, 1)

    disk_used_gb = round(disk_used / (1024 ** 3), 2)
    disk_total_gb = round(disk_total / (1024 ** 3), 2)


    return render_template(
        'student_dashboard.html',
        username=username,
        student=student,
        files=files,

        total_files=total_files,
        local_files=local_files,
        cloud_files=cloud_files,

        total_original=total_original,
        total_compressed=total_compressed,
        saved_percent=saved_percent,
        photo_count=photo_count,
        auto_download_filename=auto_download_filename,
        disk_percent_used=disk_percent_used,
        disk_used_gb=disk_used_gb,
        disk_total_gb=disk_total_gb,

        total_original_mb=total_original_mb,
        total_compressed_mb=total_compressed_mb,
        saved_mb=saved_mb,

        active_tab=active_tab
        
    )

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

    if not student:
        cursor.close()
        return "Student Not Found", 404

    # Uploaded Files for this student
    cursor.execute("""
        SELECT *
        FROM student_files
        WHERE username=%s
        ORDER BY uploaded_at DESC
    """, [student[1]])

    files = cursor.fetchall()

    cursor.close()

    local_count = 0
    cloud_count = 0
    total_original = 0
    total_compressed = 0

    for f in files:
        if f[5] == "Local Storage":
            local_count += 1
        elif f[5] == "Cloud Storage":
            cloud_count += 1

        if f[3]:
            total_original += int(f[3])

        if f[4]:
            total_compressed += int(f[4])

    if total_original > 0:
        saved_pct = round(((total_original - total_compressed) / total_original) * 100, 1)
    else:
        saved_pct = 0

    disk_total, disk_used, disk_free = shutil.disk_usage(app.config['UPLOAD_FOLDER'])

    disk_percent_used = round((disk_used / disk_total) * 100, 1)
    disk_used_gb = round(disk_used / (1024 ** 3), 2)
    disk_total_gb = round(disk_total / (1024 ** 3), 2)

    return render_template(
        "student_profile.html",
        student=student,
        files=files,
        local_count=local_count,
        cloud_count=cloud_count,
        saved_pct=saved_pct,
        disk_percent_used=disk_percent_used,
        disk_used_gb=disk_used_gb,
        disk_total_gb=disk_total_gb
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

@app.route('/admin/users_json')
def admin_users_json():

    if 'logged_in' not in session:
        return jsonify({"error": "unauthorized"}), 401

    if session.get('role') != 'admin':
        return jsonify({"error": "forbidden"}), 403

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users")
    rows = cursor.fetchall()
    cursor.close()

    users_list = []
    for row in rows:
        safe_row = []
        for i, value in enumerate(row):
            if i == 2:
                safe_row.append(None)  # never send the password hash to the browser
            elif hasattr(value, 'isoformat'):
                safe_row.append(str(value))
            else:
                safe_row.append(value)
        users_list.append(safe_row)

    return jsonify({"users": users_list})

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
        return jsonify({"success": False, "message": "Username already exists.", "category": "danger"})
    
    # Email address entered in the Add New User form
    student_email = request.form.get('email', '').strip()

    if not student_email:
        cursor.close()
        return jsonify({"success": False, "message": "Please enter the student's email address.", "category": "danger"})

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

    # =========================================
    # Send Account Details Email (via Brevo HTTP API)
    # =========================================
    # Render's free tier blocks outbound SMTP ports (25, 465, 587), so
    # smtplib/Gmail cannot send from here. Brevo's REST API works over
    # normal HTTPS (port 443), which Render does NOT block.

    email_sent = False

    email_body_html = f"""
    <p>Dear Student,</p>
    <p>Your account has been created successfully.</p>
    <hr>
    <p>
        <b>Username:</b> {username}<br>
        <b>Password:</b> {password}<br>
        <b>Role:</b> {role}
    </p>
    <hr>
    <p>
        Login Here:
        <a href="https://student-compression-system.onrender.com/login">
            https://student-compression-system.onrender.com/login
        </a>
    </p>
    <p>Please change your password after your first login.</p>
    <p>Thank you,<br>Smart Student Compression System</p>
    """

    try:
        response = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={
                "api-key": os.environ.get('BREVO_API_KEY'),
                "Content-Type": "application/json",
                "accept": "application/json"
            },
            json={
                "sender": {
                    "name": "Smart Student Compression System",
                    "email": os.environ.get('BREVO_SENDER_EMAIL')
                },
                "to": [{"email": student_email}],
                "subject": "Smart Student Compression System - Your Account",
                "htmlContent": email_body_html
            },
            timeout=10
        )

        if response.status_code in (200, 201):
            email_sent = True
        else:
            print("Brevo Error:", response.status_code, response.text)

    except Exception as e:
        import traceback
        traceback.print_exc()
        print("Email Error:", str(e))

    cursor.close()

    log_activity(session['username'], "ADD_USER")

    if email_sent:
        return jsonify({"success": True, "message": "User added successfully and account email sent.", "category": "success"})
    else:
        return jsonify({"success": True, "message": "User added successfully, but the account email could not be sent.", "category": "warning"})

  


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
        return jsonify({"success": False, "message": "User not found.", "category": "danger"})
    
    # Prevent deleting the currently logged-in account
    if user[0] == session['username']:
       cursor.close()
       return jsonify({"success": False, "message": "You cannot delete your own account while logged in.", "category": "danger"})

    

    cursor.execute(
        "DELETE FROM users WHERE id=%s",
        [id]
    )

    mysql.connection.commit()
    cursor.close()

    log_activity(session['username'], "DELETE_USER")

    return jsonify({"success": True, "message": "User deleted successfully.", "category": "success"})

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
        return jsonify({"success": False, "message": "User not found.", "category": "danger"})

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

    return jsonify({"success": True, "message": f"Password for '{user[0]}' has been reset to 1234.", "category": "success"})

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

    log_activity(session['username'], "UNLOCK_USER")

    return jsonify({"success": True, "message": "User account unlocked successfully.", "category": "success"})

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

    cursor = mysql.connection.cursor()
    cursor.execute(
        "SELECT storage_type FROM student_files WHERE filename=%s ORDER BY uploaded_at DESC LIMIT 1",
        [filename]
    )
    storage_row = cursor.fetchone()
    cursor.close()

    storage_type = storage_row[0] if storage_row else None

    # Cloud Storage — fetch from S3 via a temporary presigned URL
    if storage_type == "Cloud Storage":
        try:
            presigned_url = s3.generate_presigned_url(
                'get_object',
                Params={
                    'Bucket': AWS_BUCKET,
                    'Key': filename,
                    'ResponseContentDisposition': 'inline'
                },
                ExpiresIn=300
            )
            return redirect(presigned_url)
        except Exception as e:
            return f"<h2 style='font-family:sans-serif;'>⚠️ Could not load file from cloud storage.</h2><p>{str(e)}</p>", 500

    filepath = os.path.join(
        app.config['UPLOAD_FOLDER'],
        filename
    )

    if not os.path.exists(filepath):
        return '''
        <div style="font-family:sans-serif;padding:40px;max-width:600px;">
            <h2>⚠️ File No Longer Available</h2>
            <p>This file was stored on the server's local storage, but is no
            longer available (Render's free-tier disk resets on every
            redeploy, so local-storage files don't persist long-term).</p>
            <p><a href="javascript:history.back()">← Go Back</a></p>
        </div>
        ''', 404

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

        session['auto_download_file'] = filename

    # =========================================
    # Update Student Record
    # =========================================

    print(filename)
    print(storage_type)
    print(username)

    cursor.execute("""
        INSERT INTO student_files
        (
            username,
            filename,
            original_size,
            compressed_size,
            storage_type
        )
        VALUES (%s, %s, %s, %s, %s)
    """, (
        username,
        filename,
        original_size,
        compressed_size,
        storage_type
    ))

    mysql.connection.commit()
    print("Database Updated Successfully")

    cursor.close()

    log_activity(username, "UPLOAD_ASSIGNMENT")

    flash("Assignment uploaded successfully.", "success")

    return redirect('/student_dashboard?tab=files')

# Download File
@app.route('/download/<filename>')
def download_file(filename):

        if 'logged_in' not in session:
            return redirect('/login')

        cursor = mysql.connection.cursor()
        cursor.execute(
            "SELECT storage_type FROM student_files WHERE filename=%s ORDER BY uploaded_at DESC LIMIT 1",
            [filename]
        )
        storage_row = cursor.fetchone()
        cursor.close()

        storage_type = storage_row[0] if storage_row else None

        # Cloud Storage — fetch from S3 via a temporary presigned URL
        if storage_type == "Cloud Storage":
            try:
                presigned_url = s3.generate_presigned_url(
                    'get_object',
                    Params={
                        'Bucket': AWS_BUCKET,
                        'Key': filename,
                        'ResponseContentDisposition': f'attachment; filename="{filename}"'
                    },
                    ExpiresIn=300
                )
                return redirect(presigned_url)
            except Exception as e:
                return f"<h2 style='font-family:sans-serif;'>⚠️ Could not load file from cloud storage.</h2><p>{str(e)}</p>", 500

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        if not os.path.exists(filepath):
            return '''
            <div style="font-family:sans-serif;padding:40px;max-width:600px;">
                <h2>⚠️ File No Longer Available</h2>
                <p>This file was stored on the server's local storage, but is
                no longer available (Render's free-tier disk resets on every
                redeploy, so local-storage files don't persist long-term).</p>
                <p><a href="javascript:history.back()">← Go Back</a></p>
            </div>
            ''', 404

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
# Create Student Files Table
# =========================================
@app.route("/create_student_files_table")
def create_student_files_table():

    cursor = mysql.connection.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS student_files (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(100) NOT NULL,
        filename VARCHAR(255) NOT NULL,
        original_size BIGINT,
        compressed_size BIGINT,
        storage_type VARCHAR(50),
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    mysql.connection.commit()
    cursor.close()

    return "Student Files Table Created Successfully!"

@app.route("/mail_test")
def mail_test():

    return f"""
MAIL_USERNAME = {app.config['MAIL_USERNAME']} <br><br>

MAIL_PASSWORD = {app.config['MAIL_PASSWORD']}
"""

@app.route("/mail_send_test")
def mail_send_test():

    try:

        msg = Message(
            subject="Test Email",
            recipients=["chenulsandiw760@gmail.com"]
        )

        msg.body = "Hello from Smart Student System"

        mail.send(msg)

        return "Email Sent Successfully"

    except Exception as e:

        return str(e)


@app.route("/debug_brevo")
def debug_brevo():

    api_key = os.environ.get('BREVO_API_KEY')
    sender_email = os.environ.get('BREVO_SENDER_EMAIL')

    result = "<div style='font-family:sans-serif;padding:30px;max-width:700px;'>"
    result += "<h2>🔍 Brevo Debug</h2>"

    result += f"<p><b>BREVO_API_KEY set?</b> {'Yes, starts with ' + api_key[:10] if api_key else 'NO - missing!'}</p>"
    result += f"<p><b>BREVO_SENDER_EMAIL set?</b> {sender_email if sender_email else 'NO - missing!'}</p>"

    if not api_key or not sender_email:
        result += "<p style='color:red;'>⚠️ One or both environment variables are missing on Render. Add them in Render → Environment tab.</p>"
        result += "</div>"
        return result

    try:
        response = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={
                "api-key": api_key,
                "Content-Type": "application/json",
                "accept": "application/json"
            },
            json={
                "sender": {
                    "name": "Smart Student Compression System",
                    "email": sender_email
                },
                "to": [{"email": sender_email}],
                "subject": "Brevo Debug Test",
                "htmlContent": "<p>This is a test email from /debug_brevo.</p>"
            },
            timeout=10
        )

        result += f"<p><b>Status Code:</b> {response.status_code}</p>"
        result += f"<p><b>Response Body:</b></p><pre style='background:#f0f0f0;padding:15px;border-radius:8px;'>{response.text}</pre>"

    except Exception as e:
        import traceback
        result += f"<p style='color:red;'><b>Exception:</b> {str(e)}</p>"
        result += f"<pre style='background:#fee;padding:15px;border-radius:8px;'>{traceback.format_exc()}</pre>"

    result += "</div>"
    return result



# =========================================
# Run App
# =========================================
if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
