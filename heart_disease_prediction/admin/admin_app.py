from flask import Flask, session, request, redirect, url_for, flash, render_template
import mysql.connector
import bcrypt
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'Suhan@46',
    'database': 'heart_disease_prediction'
}

@app.route('/')
def home():
    return render_template('admin_login.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM admin_users WHERE email = %s", (email,))
            admin = cursor.fetchone()
            cursor.close()
            conn.close()

            if admin and bcrypt.checkpw(password.encode(), admin['password'].encode()):
                session['admin'] = admin  # Store admin details in session
                flash('Admin login successful!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Incorrect email or password.', 'error')
                return redirect(url_for('admin_login'))
        except mysql.connector.Error as e:
            flash(f"Database error: {e}", 'error')
            return redirect(url_for('admin_login'))
    return render_template('admin_login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'admin' not in session:
        flash('Please log in to access the dashboard.', 'error')
        return redirect(url_for('admin_login'))

    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        
        # Fetch only active users
        cursor.execute("SELECT id, email, active FROM users WHERE active = TRUE")
        users = cursor.fetchall()

        # Fetch feedbacks ordered by creation date in descending order
        cursor.execute("SELECT u.email, f.feedback, f.created_at FROM feedback f JOIN users u ON f.user_id = u.id ORDER BY f.created_at DESC")
        feedbacks = cursor.fetchall()

        cursor.close()
        conn.close()

        return render_template('admin_dashboard.html', users=users, feedbacks=feedbacks)
    except mysql.connector.Error as e:
        flash(f"Database error: {e}", 'error')
        return redirect(url_for('admin_login'))

@app.route('/change_password/<int:user_id>', methods=['GET', 'POST'])
def change_password(user_id):
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_new_password')
        
        if not new_password or not confirm_password:
            flash('Passwords cannot be empty.', 'error')
            return redirect(url_for('change_password', user_id=user_id))
        
        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('change_password', user_id=user_id))
        
        hashed_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode('utf-8')

        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_password, user_id))
            conn.commit()
            cursor.close()
            conn.close()
            flash('Password updated successfully!', 'success')
        except mysql.connector.Error as e:
            flash(f"Database error: {e}", 'error')
        return redirect(url_for('admin_dashboard'))
    return render_template('change_password.html', user_id=user_id)

if __name__ == '__main__':
    app.run(debug=True)
