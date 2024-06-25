from flask import Flask, request, session, render_template, redirect, url_for, flash 
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from flask_login import current_user
import mysql.connector
import joblib
import secrets
import bcrypt
import traceback
import logging

app = Flask(__name__)

# Generate a secret key
secret_key = secrets.token_hex(16)

#Configure logging
logging.basicConfig(level=logging.DEBUG)

# Set the secret key
app.secret_key = secret_key

# Load the trained model
model = joblib.load('dataset_and_model/heart.pkl')

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# MySQL database configuration
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'Suhan@46',
    'database': 'heart_disease_prediction'
}

# app.py or config.py

# Gender mapping
gender_map = {0: 'Female', 1: 'Male'}

# Chest Pain Type (cp) mapping
cp_map = {0: 'None', 1: 'low', 2: 'Medium', 3: 'High'}

# Fasting Blood Sugar (fbs) mapping
fbs_map = {0: 'No', 1: 'Yes'}

# Resting ECG (restecg) mapping
restecg_map = {0: 'Normal', 1: 'Abnormality in ST-T wave', 2: 'Showing probable or definite left ventricular hypertrophy'}

# Exercise Induced Angina (exang) mapping
exang_map = {0: 'No', 1: 'Yes'}

# Slope mapping
slope_map = {0: 'Upsloping', 1: 'Flat', 2: 'Downsloping'}

# Thalassemia (thal) mapping
thal_map = {0: 'Normal', 1: 'Mild', 2: 'Morderate', 3: 'Severe'}

# Prediction mapping
prediction_map = {0: 'Negative for Heart Disease', 1: 'Positive for Heart Disease'}

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, email):
        self.id = id
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("SELECT id, email FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        if user:
            return User(user[0], user[1])
        else:
            return None
    except mysql.connector.Error as e:
        app.logger.error(f"Error loading user: {e}")
        return None

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password.decode('utf-8'), salt.decode('utf-8')

def authenticate_user(email, password):
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, password FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        if user and bcrypt.checkpw(password.encode(), user[2].encode()):
            return user
        else:
            return None
    except mysql.connector.Error as e:
        app.logger.error(f"Error authenticating user: {e}")
        return None

def is_password_valid(password):
    if len(password) < 8:
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    if not any(c in '!@#$%^&*()-+?_=,<>/' for c in password):
        return False
    return True


def save_prediction(user_id, input_features, prediction):
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        # Convert prediction to 0 or 1
        prediction = 0 if prediction == 'Negative for Heart Disease' else 1

        cursor.execute(
            "INSERT INTO prediction_history (user_id, age, gender, cp, trestbps, chol, fbs, restecg, thalach, exang, oldpeak, slope, ca, thal, prediction) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (user_id, *input_features, prediction)
        )
        conn.commit()
        cursor.close()
        conn.close()
        app.logger.debug('Prediction saved successfully')
    except mysql.connector.Error as e:
        app.logger.error(f'Error saving prediction history: {e}')

def submit_feedback_to_database(user_id, email, feedback_text):
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        if user_id is not None:
            # Check if user_id exists in the users table
            cursor.execute("SELECT id FROM users WHERE id = %s", (user_id,))
            if cursor.fetchone() is None:
                user_id = None  # Set to None if user_id is not valid

        if user_id is None:
            # Insert feedback without user_id for non-logged-in users
            cursor.execute("INSERT INTO feedback (email, feedback) VALUES (%s, %s)", (email, feedback_text))
        else:
            # Insert feedback with user_id for logged-in users
            cursor.execute("INSERT INTO feedback (user_id, email, feedback) VALUES (%s, %s, %s)", (user_id, email, feedback_text))
        
        conn.commit()

        cursor.close()
        conn.close()

        return True
    except mysql.connector.Error as e:
        app.logger.error(f"Error submitting feedback: {e}")
        return False


        return True
    except mysql.connector.Error as e:
        app.logger.error(f"Error submitting feedback: {e}")
        return False


@app.route('/')
def index():
    return render_template('index.html',)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        security_question = request.form['security_question']
        security_answer = request.form['security_answer']

        if not is_password_valid(password):
            flash('Password must contain at least 8 characters, one uppercase letter, one digit, and one special character.', 'error')
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('signup'))

        if not security_question or not security_answer:
            flash('Please select a security question and provide an answer.', 'error')
            return redirect(url_for('signup'))

        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()

            if user:
                flash('Email already exists.', 'error')
                return redirect(url_for('signup'))

            hashed_password, salt = hash_password(password)

            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (email, password, salt, security_question, security_answer) VALUES (%s, %s, %s, %s, %s)",
                           (email, hashed_password, salt, security_question, security_answer))
            conn.commit()
            cursor.close()
            conn.close()

            flash('Account created successfully!', 'success')
            return redirect(url_for('login'))

        except mysql.connector.Error as e:
            app.logger.error(f"Error creating user: {e}")
            flash(f'Error creating user: {e}', 'error')
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = authenticate_user(email, password)
        if user:
            login_user(User(user[0], user[1]))
            flash('User successfully logged in.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Incorrect email or password.', 'error')
            # Clear any irrelevant flashed messages
            if 'error' in session:
                session.pop('_flashes', None)
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('index.html', plots=plots)


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        security_question = request.form['security_question']
        security_answer = request.form['security_answer']

        user = verify_security_question(email, security_question, security_answer)
        if user:
            return redirect(url_for('reset_password', email=email))
        else:
            flash('Invalid email or security question/answer.', 'error')

    return render_template('forgot_password.html')

@app.route('/reset_password/<email>', methods=['GET', 'POST'])
def reset_password(email):
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('reset_password', email=email))

        if not is_password_valid(new_password):
            flash('Password must contain at least 8 characters, one uppercase letter, one digit, and one special character.', 'error')
            return redirect(url_for('reset_password', email=email))

        update_password(email, new_password)
        flash('Your password has been successfully reset.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', email=email)

def verify_security_question(email, security_question, security_answer):
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, security_question, security_answer FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if user and user[2] == security_question and user[3] == security_answer:
            return user
        else:
            return None
    except mysql.connector.Error as e:
        app.logger.error(f"Error verifying security question: {e}")
        return None


def update_password(email, new_password):
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        hashed_password, salt = hash_password(new_password)
        cursor.execute("UPDATE users SET password = %s, salt = %s WHERE email = %s", (hashed_password, salt, email))
        conn.commit()
        cursor.close()
        conn.close()
    except mysql.connector.Error as e:
        app.logger.error(f"Error updating password: {e}")

        
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('User successfully logged out.', 'success')
    return redirect(url_for('login'))


@app.route('/predict', methods=['GET', 'POST'])
@login_required
def predict():
    if not current_user.is_authenticated:
        flash('Login required to make a prediction.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            # Get the input from the form
            input_features = [float(x) for x in request.form.values()]
            app.logger.debug(f'Input features: {input_features}')
            
            # Ensure input_features length matches the model's expected input length
            if len(input_features) != model.n_features_in_:
                flash('Incorrect number of input features.', 'error')
                return redirect(url_for('predict'))

            # Make prediction
            prediction_proba = model.predict_proba([input_features])[0]
            app.logger.debug(f'Prediction probabilities: {prediction_proba}')
            
            # Set a lower threshold for positive predictions if needed
            threshold = 0.3  # Adjust this threshold based on your evaluation
            prediction = 1 if prediction_proba[1] > threshold else 0
            app.logger.debug(f'Prediction result: {prediction}')
            
            # Convert prediction to human-readable format
            prediction_text = prediction_map.get(prediction, 'Unknown')

            # Save prediction history
            save_prediction(current_user.id, input_features, prediction_text)
            app.logger.debug('Prediction saved to history')

        except Exception as e:
            app.logger.error(f'An error occurred during prediction: {str(e)}')
            flash(f'An error occurred during prediction: {str(e)}', 'error')
            return redirect(url_for('predict'))

        return render_template("result.html", result=prediction_text)
    else:
        return render_template("prediction.html")


@app.route('/history')
@login_required
def history():
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)  # Set dictionary=True to fetch rows as dictionaries
        cursor.execute(
            "SELECT age, gender, cp, trestbps, chol, fbs, restecg, thalach, exang, oldpeak, slope, ca, thal, prediction, prediction_time "
            "FROM prediction_history WHERE user_id = %s ORDER BY prediction_time DESC", 
            (current_user.id,)
        )
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        app.logger.debug(f'Retrieved prediction history: {rows}')  # Log retrieved rows for debugging

        if not rows:
            app.logger.debug('No prediction history found')  # Log if no history found
            flash('No prediction history found.', 'info')
            return render_template('history.html', history=[])
        
        app.logger.debug('Processing prediction history')  # Log processing step
        
        # Apply mappings to convert numeric values to human-readable labels
        for row in rows:
            row['gender'] = gender_map.get(row['gender'], 'Unknown')
            row['cp'] = cp_map.get(row['cp'], 'Unknown')
            row['fbs'] = fbs_map.get(row['fbs'], 'Unknown')
            row['restecg'] = restecg_map.get(row['restecg'], 'Unknown')
            row['exang'] = exang_map.get(row['exang'], 'Unknown')
            row['slope'] = slope_map.get(row['slope'], 'Unknown')
            row['thal'] = thal_map.get(row['thal'], 'Unknown')
            # Update prediction to display as "Negative for Heart Disease" or "Positive for Heart Disease"
            row['prediction'] = 'Negative for Heart Disease' if row['prediction'] == 0 else 'Positive for Heart Disease'

        app.logger.debug('Prediction history processed successfully')  # Log processing success

        return render_template('history.html', history=rows)
    except mysql.connector.Error as e:
        app.logger.error(f"Error retrieving prediction history: {e}")
        flash('An error occurred while retrieving the prediction history.', 'error')
        return redirect(url_for('dashboard'))



@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')
    
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_new_password = request.form['confirm_new_password']
        if new_password != confirm_new_password:
            flash('Passwords do not match.', 'password_mismatch')  # Flash a message specifically for password mismatch
            return redirect(url_for('change_password'))  # Redirect back to the change password page

        if not is_password_valid(new_password):
            flash('Password must contain at least 8 characters, one uppercase letter, one digit, and one special character.', 'invalid_password')  # Flash a message for invalid password format
            return redirect(url_for('change_password'))  # Redirect back to the change password page

        user = authenticate_user(current_user.email, current_password)
        if user:
            update_password(current_user.email, new_password)
            flash('Your password has been successfully changed.', 'success')  # Flash a success message
            return redirect(url_for('settings'))
        else:
            flash('Current password is incorrect.', 'incorrect_password')  # Flash a message for incorrect current password
            return redirect(url_for('change_password'))  # Redirect back to the change password page

    return render_template('change_password.html')

@app.route('/deactivate_account', methods=['GET', 'POST'])
@login_required
def deactivate_account():
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match.', 'password_mismatch')
            return redirect(url_for('deactivate_account'))
        
        user = authenticate_user(current_user.email, password)
        if user:
            try:
                conn = mysql.connector.connect(**db_config)
                cursor = conn.cursor()

                # Delete associated feedback records
                cursor.execute("DELETE FROM feedback WHERE user_id = %s", (current_user.id,))

                # Delete the user
                cursor.execute("DELETE FROM users WHERE id = %s", (current_user.id,))
                
                conn.commit()
                cursor.close()
                conn.close()
                
                logout_user()
                flash('Your account has been deactivated.', 'success')
                return redirect(url_for('index'))
            except mysql.connector.Error as e:
                app.logger.error(f"Error deactivating account: {e}")
                flash('An error occurred while deactivating your account.', 'error')
                return redirect(url_for('settings'))
        else:
            flash('Incorrect password.', 'incorrect_password')
            return redirect(url_for('deactivate_account'))

    return render_template('deactivate_account.html')


@app.route('/feedback', methods=['GET', 'POST'])
@login_required
def feedback():
    if request.method == 'POST':
        email = current_user.email
        feedback_text = request.form['feedback']
        flash('Thank you for your feedback!', 'success')
        return redirect(url_for('index'))

    return render_template('feedback.html')

@app.route('/submit_feedback', methods=['POST'])
@login_required
def submit_feedback():
    if request.method == 'POST':
        email = current_user.email
        feedback_text = request.form['feedback']

        try:
            # Save feedback to the database
            if submit_feedback_to_database(current_user.id, email, feedback_text):
                flash('Thank you for your feedback!', 'success')
            else:
                flash('Failed to save feedback. Please try again later.', 'error')
        except Exception as e:
            app.logger.error(f"An error occurred while submitting feedback: {e}")
            traceback.print_exc()  # Print the traceback to see the full error details

        return redirect(url_for('index'))

    # Redirect to the index page if the request method is not POST
    return redirect(url_for('index'))


@app.route('/feedback_form')
@login_required
def feedback_form():
    return render_template('feedback.html')

@app.route('/trouble_login', methods=['GET', 'POST'])
def trouble_login():
    if request.method == 'POST':
        email = request.form['email']
        feedback_text = request.form['feedback']
        
        # Save feedback to the database
        if submit_feedback_to_database(None, email, feedback_text):  # user_id is None since the user might not be logged in
            flash('Thank you for your feedback! We will get back to you soon.', 'success')
        else:
            flash('Failed to save feedback. Please try again later.', 'error')
        
        return redirect(url_for('login'))

    return render_template('trouble_login.html')


if __name__ == '__main__':
    app.debug = True
    app.run()
