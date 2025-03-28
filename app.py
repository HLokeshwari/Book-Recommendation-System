import os
from flask import Flask, render_template, request, session, redirect, url_for, jsonify
import numpy as np
import joblib
import pandas as pd
import mysql.connector
import bcrypt
from google_auth_oauthlib.flow import Flow
import requests
from werkzeug.utils import secure_filename
import uuid
from datetime import datetime

# Allow HTTP for localhost during development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = '#'

# Session configuration
app.config['SESSION_COOKIE_DOMAIN'] = 'localhost'
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True

# File upload configuration for profile pictures
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Connect to MySQL
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="#",
    database="book_reviews"
)
cursor = db.cursor()

# Load preprocessed data
popular_df = joblib.load(open('popular.pkl', 'rb'))
pt = joblib.load(open('pt.pkl', 'rb'))
books = joblib.load(open('books.pkl', 'rb'))
similarity_scores = joblib.load(open('similarity_scores.pkl', 'rb'))

# Fix encoding issues for special characters
books['Book-Title'] = books['Book-Title'].str.encode('utf-8', errors='ignore').str.decode('utf-8', errors='ignore')
books['Book-Author'] = books['Book-Author'].str.encode('utf-8', errors='ignore').str.decode('utf-8', errors='ignore')
books['Publisher'] = books['Publisher'].str.encode('utf-8', errors='ignore').str.decode('utf-8', errors='ignore')

# Add a category column (for demonstration, assign random categories)
import random

categories = ['Fiction', 'Non-Fiction', 'Fantasy', 'Mystery', 'Science Fiction', 'Biography', 'History']
books['Category'] = [random.choice(categories) for _ in range(len(books))]

# Add a status column (for demonstration, assign random status)
statuses = ['Available', 'Out of Stock']
books['Status'] = [random.choice(statuses) for _ in range(len(books))]

# Normalize book titles for duplicate checking (convert to lowercase)
books['Book-Title-Normalized'] = books['Book-Title'].str.lower()

# Check for duplicates in books.pkl (case-insensitive)
duplicate_titles = books[books.duplicated(subset=['Book-Title-Normalized'], keep=False)]
print("Duplicate book titles in books.pkl (case-insensitive):")
print(duplicate_titles[['Book-Title', 'Book-Author', 'Year-Of-Publication', 'Publisher', 'Image-URL-M']])
print(f"Total number of rows with duplicate titles: {len(duplicate_titles)}")

# Remove duplicates, keeping the first occurrence
books = books.drop_duplicates(subset=['Book-Title-Normalized'], keep='first')
books = books.drop(columns=['Book-Title-Normalized'])  # Drop the temporary column
print(f"Books after removing duplicates: {len(books)}")


# Clean the Year-Of-Publication column
def clean_year(year):
    try:
        year_int = int(year)
        if 0 <= year_int <= 2025:
            return year_int
        else:
            return None
    except (ValueError, TypeError):
        return None


books['Year-Of-Publication'] = books['Year-Of-Publication'].apply(clean_year)

# Replace NaN with None for all columns to handle MySQL NULL
books = books.replace({np.nan: None})

# Ensure the books table exists
try:
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS books (
            id INT AUTO_INCREMENT PRIMARY KEY,
            book_title VARCHAR(255) NOT NULL,
            book_author VARCHAR(255),
            image_url VARCHAR(255),
            year INT,
            publisher VARCHAR(255),
            category VARCHAR(50),
            status VARCHAR(20),
            total_pages INT DEFAULT 300,  -- Added for reading progress tracking (default to 300 pages)
            UNIQUE(book_title)
        )
    """)
    db.commit()
    print("Books table ensured.")
except mysql.connector.Error as err:
    print("Error creating books table:", err)
    raise

# Add indexes for faster queries
try:
    cursor.execute("SHOW INDEX FROM books WHERE Key_name = 'idx_book_title'")
    if not cursor.fetchall():
        cursor.execute("CREATE INDEX idx_book_title ON books (book_title)")
        print("Created index idx_book_title.")
    else:
        print("Index idx_book_title already exists.")

    cursor.execute("SHOW INDEX FROM books WHERE Key_name = 'idx_book_author'")
    if not cursor.fetchall():
        cursor.execute("CREATE INDEX idx_book_author ON books (book_author)")
        print("Created index idx_book_author.")
    else:
        print("Index idx_book_author already exists.")

    cursor.execute("SHOW INDEX FROM books WHERE Key_name = 'idx_category'")
    if not cursor.fetchall():
        cursor.execute("CREATE INDEX idx_category ON books (category)")
        print("Created index idx_category.")
    else:
        print("Index idx_category already exists.")

    db.commit()
except mysql.connector.Error as err:
    print("Error creating indexes:", err)
    raise

# Update reading_list table to include reading progress
try:
    cursor.execute("SHOW COLUMNS FROM reading_list LIKE 'current_page'")
    if not cursor.fetchall():
        cursor.execute("ALTER TABLE reading_list ADD COLUMN current_page INT DEFAULT 0")
        print("Added current_page column to reading_list table.")
    cursor.execute("SHOW COLUMNS FROM reading_list LIKE 'progress_percentage'")
    if not cursor.fetchall():
        cursor.execute("ALTER TABLE reading_list ADD COLUMN progress_percentage FLOAT DEFAULT 0")
        print("Added progress_percentage column to reading_list table.")
    db.commit()
except mysql.connector.Error as err:
    print("Error updating reading_list table:", err)
    raise

# Create user_activities table for activity feed
try:
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_activities (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user VARCHAR(255) NOT NULL,
            activity_type ENUM('review', 'rating', 'favorite', 'reading_list') NOT NULL,
            book_title VARCHAR(255) NOT NULL,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.commit()
    print("User_activities table ensured.")
except mysql.connector.Error as err:
    print("Error creating user_activities table:", err)
    raise

# Create user_achievements table for badges
try:
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_achievements (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user VARCHAR(255) NOT NULL,
            achievement_name VARCHAR(100) NOT NULL,
            description TEXT,
            earned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user, achievement_name)
        )
    """)
    db.commit()
    print("User_achievements table ensured.")
except mysql.connector.Error as err:
    print("Error creating user_achievements table:", err)
    raise

# Update reviews table to add likes column
try:
    cursor.execute("SHOW COLUMNS FROM reviews LIKE 'likes'")
    if not cursor.fetchall():
        cursor.execute("ALTER TABLE reviews ADD COLUMN likes INT DEFAULT 0")
        print("Added likes column to reviews table.")
    else:
        print("likes column already exists in reviews table.")
    db.commit()
except mysql.connector.Error as err:
    print("Error adding likes column to reviews table:", err)
    raise

# Create review_likes table to track user likes
try:
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS review_likes (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user VARCHAR(255) NOT NULL,
            review_id INT NOT NULL,
            UNIQUE(user, review_id),
            FOREIGN KEY (review_id) REFERENCES reviews(id) ON DELETE CASCADE
        )
    """)
    db.commit()
    print("Review_likes table ensured.")
except mysql.connector.Error as err:
    print("Error creating review_likes table:", err)
    raise

# Create book_availability_subscriptions table
try:
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS book_availability_subscriptions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user VARCHAR(255) NOT NULL,
            book_title VARCHAR(255) NOT NULL,
            subscribed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user, book_title)
        )
    """)
    db.commit()
    print("Book_availability_subscriptions table ensured.")
except mysql.connector.Error as err:
    print("Error creating book_availability_subscriptions table:", err)
    raise

# Create notifications table
try:
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user VARCHAR(255) NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_read BOOLEAN DEFAULT FALSE
        )
    """)
    db.commit()
    print("Notifications table ensured.")
except mysql.connector.Error as err:
    print("Error creating notifications table:", err)
    raise

# Add profile_picture column to users table
try:
    cursor.execute("SHOW COLUMNS FROM users LIKE 'profile_picture'")
    if not cursor.fetchall():
        cursor.execute("ALTER TABLE users ADD COLUMN profile_picture VARCHAR(255) DEFAULT NULL")
        db.commit()
        print("Added profile_picture column to users table.")
    else:
        print("profile_picture column already exists in users table.")
except mysql.connector.Error as err:
    print("Error adding profile_picture column:", err)
    raise

# Check for titles longer than 255 characters
long_titles = books[books['Book-Title'].str.len() > 255]
if not long_titles.empty:
    print("Titles longer than 255 characters:")
    print(long_titles[['Book-Title']])

# Populate the books table (skip if already populated)
try:
    expected_book_count = len(books)
    cursor.execute("SELECT COUNT(*) FROM books")
    current_book_count = cursor.fetchone()[0]
    if current_book_count == expected_book_count:
        print(f"Books table already contains {current_book_count} books, skipping population.")
    else:
        if current_book_count == 0:
            print("Books table is empty, no need to truncate.")
        else:
            print("Truncating books table...")
            cursor.execute("TRUNCATE TABLE books")
            db.commit()
            print("Books table truncated.")

        print("Populating books table...")
        inserted_books = 0
        failed_books = []
        batch_size = 1000
        for i, (_, book) in enumerate(books.iterrows()):
            book_title = str(book['Book-Title'])[:255]
            try:
                cursor.execute("""
                    INSERT INTO books (book_title, book_author, image_url, year, publisher, category, status, total_pages)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (book_title, book['Book-Author'], book['Image-URL-M'],
                      book['Year-Of-Publication'], book['Publisher'], book['Category'], book['Status'],
                      300))  # Default total_pages
                inserted_books += 1
                if (i + 1) % batch_size == 0:
                    db.commit()
                    print(f"Committed {inserted_books} books so far...")
            except mysql.connector.Error as err:
                print(f"Error inserting book {book_title}: {err}")
                failed_books.append((book_title, str(err)))
        db.commit()
        print(f"Books table populated with {inserted_books} books.")
        if failed_books:
            print("Books that failed to insert:")
            for book_title, error in failed_books:
                print(f" - {book_title}: {error}")
except mysql.connector.Error as err:
    print("Error checking or populating books table:", err)
    raise

# Verify the number of books in the table
cursor.execute("SELECT COUNT(*) FROM books")
final_count = cursor.fetchone()[0]
print(f"Final count of books in the database: {final_count}")

# Google OAuth Configuration
GOOGLE_CLIENT_ID = '#'
GOOGLE_CLIENT_SECRET = '#'
REDIRECT_URI = 'http://localhost:5000/google/auth'
SCOPES = ['openid', 'https://www.googleapis.com/auth/userinfo.email',
          'https://www.googleapis.com/auth/userinfo.profile']


# Redirect to Login if User is Not Logged In
@app.before_request
def require_login():
    allowed_routes = ['login', 'signup', 'google_login', 'google_auth']
    if 'user' not in session and request.endpoint not in allowed_routes:
        return redirect(url_for('login'))


# Helper function to log user activity
def log_user_activity(username, activity_type, book_title, details=None):
    try:
        cursor.execute("""
            INSERT INTO user_activities (user, activity_type, book_title, details)
            VALUES (%s, %s, %s, %s)
        """, (username, activity_type, book_title, details))
        db.commit()
    except mysql.connector.Error as err:
        print(f"Error logging user activity: {err}")
        db.rollback()


# Helper function to award achievements
def award_achievement(username, achievement_name, description):
    try:
        cursor.execute("""
            INSERT INTO user_achievements (user, achievement_name, description)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE description=description
        """, (username, achievement_name, description))
        db.commit()
        # Notify user of new achievement
        message = f"🎉 You've earned the '{achievement_name}' badge: {description}"
        cursor.execute("INSERT INTO notifications (user, message) VALUES (%s, %s)", (username, message))
        db.commit()
    except mysql.connector.Error as err:
        print(f"Error awarding achievement: {err}")
        db.rollback()


# Check for achievements after certain actions
def check_achievements(username):
    # Check number of books read
    cursor.execute("SELECT COUNT(*) FROM reading_list WHERE user=%s AND status='Read'", (username,))
    books_read = cursor.fetchone()[0]
    if books_read >= 5 and not cursor.execute(
            "SELECT * FROM user_achievements WHERE user=%s AND achievement_name='Bookworm'", (username,)).fetchone():
        award_achievement(username, "Bookworm", "Read 5 books!")

    # Check number of reviews
    cursor.execute("SELECT COUNT(*) FROM reviews WHERE user=%s", (username,))
    reviews_count = cursor.fetchone()[0]
    if reviews_count >= 10 and not cursor.execute(
            "SELECT * FROM user_achievements WHERE user=%s AND achievement_name='Critic'", (username,)).fetchone():
        award_achievement(username, "Critic", "Wrote 10 reviews!")


# User Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()
        if user:
            return render_template('signup.html', error="Username already exists.")

        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
        db.commit()
        return redirect(url_for('login'))

    return render_template('signup.html')


# User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()

        if user and user[2] and bcrypt.checkpw(password, user[2].encode('utf-8')):
            session['user'] = username
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Invalid Credentials")

    return render_template('login.html')


# Google Login Route
@app.route('/google/login')
def google_login():
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uris": [REDIRECT_URI],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://accounts.google.com/o/oauth2/token"
            }
        },
        scopes=SCOPES
    )

    flow.redirect_uri = REDIRECT_URI
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )

    session['state'] = state
    print(f"Setting state in session: {state}")
    print(f"Authorization URL: {authorization_url}")
    return redirect(authorization_url)


# Google Authorization Callback
@app.route('/google/auth')
def google_auth():
    state = session.get('state')
    print(f"Retrieved state from session: {state}")
    print(f"State from Google callback: {request.args.get('state')}")

    if not state:
        return "Error: State mismatch or missing", 400

    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uris": [REDIRECT_URI],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://accounts.google.com/o/oauth2/token"
            }
        },
        scopes=SCOPES,
        state=state
    )

    flow.redirect_uri = REDIRECT_URI
    print(f"Request URL: {request.url}")

    try:
        flow.fetch_token(authorization_response=request.url)
    except Exception as e:
        print(f"Token fetch error: {str(e)}")
        return f"Error during token fetch: {str(e)}", 400

    credentials = flow.credentials
    session['google_token'] = credentials.to_json()

    user_info = requests.get(
        'https://www.googleapis.com/oauth2/v1/userinfo',
        headers={'Authorization': f'Bearer {credentials.token}'}
    ).json()

    if 'email' not in user_info:
        return "Error: Unable to fetch user email", 400

    email = user_info['email']
    username = email.split('@')[0]

    cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
    user = cursor.fetchone()
    if not user:
        cursor.execute("INSERT INTO users (username) VALUES (%s)", (username,))
        db.commit()

    session['user'] = username
    return redirect(url_for('index'))


# User Logout
@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('google_token', None)
    session.pop('viewed_books', None)
    return redirect(url_for('login'))


# Home Page
@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))

    sort_option = request.args.get('sort', 'rating')
    book_data = list(zip(popular_df['Book-Title'].values, popular_df['Book-Author'].values,
                         popular_df['Image-URL-M'].values, popular_df['num_ratings'].values,
                         popular_df['avg_rating'].values))

    if sort_option == 'votes':
        book_data = sorted(book_data, key=lambda x: x[3], reverse=True)
    else:
        book_data = sorted(book_data, key=lambda x: x[4], reverse=True)

    book_name, author, image, votes, rating = zip(*book_data)

    viewed_books_images = {}
    if 'viewed_books' in session:
        for book in session['viewed_books']:
            book_entry = books[books['Book-Title'] == book]
            if not book_entry.empty:
                viewed_books_images[book] = book_entry['Image-URL-M'].iloc[0]
            else:
                viewed_books_images[book] = 'https://source.unsplash.com/200x300/?book'

    # Fetch categories for filter dropdown
    cursor.execute("SELECT DISTINCT category FROM books WHERE category IS NOT NULL")
    categories = [row[0] for row in cursor.fetchall()]

    # Fetch recent activities for the activity feed
    cursor.execute("""
        SELECT user, activity_type, book_title, details, created_at
        FROM user_activities
        WHERE user=%s
        ORDER BY created_at DESC
        LIMIT 10
    """, (session['user'],))
    activities = cursor.fetchall()

    return render_template('index.html',
                           book_name=book_name,
                           author=author,
                           image=image,
                           votes=votes,
                           rating=rating,
                           viewed_books_images=viewed_books_images,
                           categories=categories,
                           activities=activities)


# Book Details Page
@app.route('/view_book/<book_title>')
def view_book(book_title):
    if 'user' not in session:
        return redirect(url_for('login'))

    book = books[books['Book-Title'].str.lower() == book_title.lower()]
    if book.empty:
        return "Book not found", 404

    book = book.iloc[0]
    book_id = book.get('id', 0)
    book_data = {
        'book_id': book_id,
        'book_title': book['Book-Title'],
        'book_author': book['Book-Author'],
        'image_url': book['Image-URL-M'],
        'year': book.get('Year-Of-Publication', 'N/A'),
        'publisher': book.get('Publisher', 'N/A'),
        'category': book.get('Category', 'N/A'),
        'status': book.get('Status', 'N/A'),
        'total_pages': 300  # Default for demo; in a real app, this would come from the dataset or database
    }

    # Fetch reviews with likes and check if the user liked each review
    cursor.execute("""
        SELECT r.id, r.user, r.review_text, r.created_at, r.likes,
               (SELECT COUNT(*) FROM review_likes rl WHERE rl.review_id = r.id AND rl.user = %s) as user_liked
        FROM reviews r
        WHERE r.book_title=%s
        ORDER BY r.likes DESC, r.created_at DESC
    """, (session['user'], book_title))
    reviews = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) as num_ratings, AVG(book_rating) as avg_rating FROM ratings WHERE book_title=%s",
                   (book_title,))
    rating_data = cursor.fetchone()
    total_votes = rating_data[0] if rating_data else 0
    avg_rating = round(rating_data[1], 2) if rating_data and rating_data[1] else 0

    if 'viewed_books' not in session:
        session['viewed_books'] = []
    viewed_books = session['viewed_books']
    if book_title not in viewed_books:
        viewed_books.append(book_title)
        if len(viewed_books) > 4:
            viewed_books.pop(0)
    session['viewed_books'] = viewed_books

    # Check if the book is in the user's reading list
    cursor.execute("SELECT status, current_page, progress_percentage FROM reading_list WHERE user=%s AND book_title=%s",
                   (session['user'], book_title))
    reading_status = cursor.fetchone()
    reading_status_data = {
        'status': reading_status[0] if reading_status else None,
        'current_page': reading_status[1] if reading_status else 0,
        'progress_percentage': reading_status[2] if reading_status else 0
    }

    return render_template('book_details.html',
                           book_id=book_data['book_id'],
                           book_title=book_data['book_title'],
                           author=book_data['book_author'],
                           image_url=book_data['image_url'],
                           year=book_data['year'],
                           publisher=book_data['publisher'],
                           category=book_data['category'],
                           status=book_data['status'],
                           total_pages=book_data['total_pages'],
                           avg_rating=avg_rating,
                           total_votes=total_votes,
                           reviews=reviews,
                           reading_status=reading_status_data)


# Add Review
@app.route('/add_review', methods=['POST'])
def add_review():
    if 'user' not in session:
        return jsonify({'error': 'You must be logged in'}), 401

    book_id = request.form.get('book_id')
    review_text = request.form.get('review')
    username = session['user']

    if not review_text or not book_id:
        return jsonify({'error': 'Review text and book ID are required'}), 400

    book = books[books['id'] == int(book_id)] if 'id' in books.columns else books[books['Book-Title'] == book_id]
    if book.empty:
        return jsonify({'error': 'Book not found'}), 404
    book_title = book.iloc[0]['Book-Title']

    try:
        cursor.execute("""
            INSERT INTO reviews (user, book_title, review_text, likes)
            VALUES (%s, %s, %s, 0)
            ON DUPLICATE KEY UPDATE review_text=%s, likes=likes
        """, (username, book_title, review_text, review_text))
        db.commit()
        # Fetch the newly added review's ID
        cursor.execute("SELECT id FROM reviews WHERE user=%s AND book_title=%s ORDER BY created_at DESC LIMIT 1",
                       (username, book_title))
        review_id = cursor.fetchone()[0]
        # Log activity
        log_user_activity(username, 'review', book_title, f"Wrote a review: {review_text[:50]}...")
        # Check for achievements
        check_achievements(username)
        return jsonify({'message': 'Review added successfully!', 'review_id': review_id})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500


# Like/Unlike Review
@app.route('/like_review/<int:review_id>', methods=['POST'])
def like_review(review_id):
    if 'user' not in session:
        return jsonify({'error': 'You must be logged in'}), 401

    username = session['user']
    try:
        # Check if the user has already liked the review
        cursor.execute("SELECT * FROM review_likes WHERE user=%s AND review_id=%s", (username, review_id))
        already_liked = cursor.fetchone()

        if already_liked:
            # Unlike the review
            cursor.execute("DELETE FROM review_likes WHERE user=%s AND review_id=%s", (username, review_id))
            cursor.execute("UPDATE reviews SET likes = likes - 1 WHERE id=%s", (review_id,))
            db.commit()
            return jsonify({'message': 'Review unliked', 'liked': False})
        else:
            # Like the review
            cursor.execute("INSERT INTO review_likes (user, review_id) VALUES (%s, %s)", (username, review_id))
            cursor.execute("UPDATE reviews SET likes = likes + 1 WHERE id=%s", (review_id,))
            db.commit()
            return jsonify({'message': 'Review liked', 'liked': True})
    except mysql.connector.Error as err:
        db.rollback()
        return jsonify({'error': str(err)}), 500


# Update Reading Progress
@app.route('/update_reading_progress', methods=['POST'])
def update_reading_progress():
    if 'user' not in session:
        return jsonify({'error': 'You must be logged in'}), 401

    book_title = request.form.get('book_title')
    current_page = request.form.get('current_page')
    total_pages = request.form.get('total_pages')

    if not book_title or not current_page or not total_pages:
        return jsonify({'error': 'Book title, current page, and total pages are required'}), 400

    try:
        current_page = int(current_page)
        total_pages = int(total_pages)
        if current_page < 0 or total_pages <= 0:
            return jsonify({'error': 'Invalid page numbers'}), 400
        if current_page > total_pages:
            current_page = total_pages

        progress_percentage = (current_page / total_pages) * 100
        cursor.execute("""
            UPDATE reading_list
            SET current_page=%s, progress_percentage=%s
            WHERE user=%s AND book_title=%s
        """, (current_page, progress_percentage, session['user'], book_title))
        db.commit()
        # Log activity
        log_user_activity(session['user'], 'reading_list', book_title,
                          f"Updated reading progress to {progress_percentage:.1f}%")
        return jsonify(
            {'message': 'Reading progress updated successfully!', 'progress_percentage': progress_percentage})
    except mysql.connector.Error as err:
        db.rollback()
        return jsonify({'error': str(err)}), 500


# Subscribe to Availability Alerts
@app.route('/subscribe_availability', methods=['POST'])
def subscribe_availability():
    if 'user' not in session:
        return jsonify({'error': 'You must be logged in'}), 401

    book_title = request.form.get('book_title')
    username = session['user']

    if not book_title:
        return jsonify({'error': 'Book title is required'}), 400

    cursor.execute("SELECT status FROM books WHERE book_title=%s", (book_title,))
    book_status = cursor.fetchone()
    if not book_status:
        return jsonify({'error': 'Book not found'}), 404

    if book_status[0] == 'Available':
        return jsonify({'error': 'Book is already available'}), 400

    try:
        cursor.execute("""
            INSERT INTO book_availability_subscriptions (user, book_title)
            VALUES (%s, %s)
            ON DUPLICATE KEY UPDATE subscribed_at=CURRENT_TIMESTAMP
        """, (username, book_title))
        db.commit()
        return jsonify({'message': 'Subscribed to availability alerts for this book'})
    except mysql.connector.Error as err:
        db.rollback()
        return jsonify({'error': str(err)}), 500


# Unsubscribe from Availability Alerts
@app.route('/unsubscribe_availability', methods=['POST'])
def unsubscribe_availability():
    if 'user' not in session:
        return jsonify({'error': 'You must be logged in'}), 401

    book_title = request.form.get('book_title')
    username = session['user']

    try:
        cursor.execute("DELETE FROM book_availability_subscriptions WHERE user=%s AND book_title=%s",
                       (username, book_title))
        db.commit()
        return jsonify({'message': 'Unsubscribed from availability alerts'})
    except mysql.connector.Error as err:
        db.rollback()
        return jsonify({'error': str(err)}), 500


# Notifications Page
@app.route('/notifications')
def notifications():
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user']

    # Fetch notifications
    cursor.execute("SELECT id, message, created_at, is_read FROM notifications WHERE user=%s ORDER BY created_at DESC",
                   (username,))
    notifications = cursor.fetchall()

    # Fetch availability subscriptions
    cursor.execute("""
        SELECT book_title, subscribed_at 
        FROM book_availability_subscriptions 
        WHERE user=%s 
        ORDER BY subscribed_at DESC
    """, (username,))
    subscriptions = cursor.fetchall()

    # Mark notifications as read when viewed
    cursor.execute("UPDATE notifications SET is_read=TRUE WHERE user=%s AND is_read=FALSE", (username,))
    db.commit()

    return render_template('notifications.html', notifications=notifications, subscriptions=subscriptions)


# Update Book Status (for Testing Notifications)
@app.route('/update_book_status/<book_title>/<status>', methods=['POST'])
def update_book_status(book_title, status):
    if status not in ['Available', 'Out of Stock']:
        return jsonify({'error': 'Invalid status'}), 400

    try:
        cursor.execute("UPDATE books SET status=%s WHERE book_title=%s", (status, book_title))
        db.commit()

        # Check for subscribers if the status changed to Available
        if status == 'Available':
            cursor.execute("SELECT user FROM book_availability_subscriptions WHERE book_title=%s", (book_title,))
            subscribers = cursor.fetchall()
            for subscriber in subscribers:
                user = subscriber[0]
                message = f"The book '{book_title}' is now available!"
                cursor.execute("INSERT INTO notifications (user, message) VALUES (%s, %s)", (user, message))
            # Clear subscriptions after notifying
            cursor.execute("DELETE FROM book_availability_subscriptions WHERE book_title=%s", (book_title,))
            db.commit()

        return jsonify({'message': f"Book status updated to {status}"})
    except mysql.connector.Error as err:
        db.rollback()
        return jsonify({'error': str(err)}), 500


# Rate Book
@app.route('/rate_book/<book_id>', methods=['GET', 'POST'])
def rate_book(book_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    book = books[books['id'] == int(book_id)] if 'id' in books.columns else books[books['Book-Title'] == book_id]
    if book.empty:
        return "Book not found", 404
    book_title = book.iloc[0]['Book-Title']

    if request.method == 'POST':
        rating = request.form.get('rating')
        username = session['user']

        try:
            rating = int(rating)
            if rating < 1 or rating > 5:
                return render_template('rate_book.html', book_title=book_title, error="Rating must be between 1 and 5.")
        except ValueError:
            return render_template('rate_book.html', book_title=book_title, error="Invalid rating value.")

        try:
            cursor.execute(
                "INSERT INTO ratings (user, book_title, book_rating) VALUES (%s, %s, %s) ON DUPLICATE KEY UPDATE book_rating=%s",
                (username, book_title, rating, rating))
            db.commit()
            # Log activity
            log_user_activity(username, 'rating', book_title, f"Rated the book {rating}/5")
            return redirect(url_for('view_book', book_title=book_title))
        except Exception as e:
            db.rollback()
            return render_template('rate_book.html', book_title=book_title, error=f"Error submitting rating: {str(e)}")

    return render_template('rate_book.html', book_title=book_title)


# Book Recommendation Page
@app.route('/recommend')
def recommend_ui():
    # Fetch categories, authors, and years for filters
    cursor.execute("SELECT DISTINCT category FROM books WHERE category IS NOT NULL")
    categories = [row[0] for row in cursor.fetchall()]
    cursor.execute("SELECT DISTINCT book_author FROM books WHERE book_author IS NOT NULL")
    authors = [row[0] for row in cursor.fetchall()]
    cursor.execute("SELECT DISTINCT year FROM books WHERE year IS NOT NULL ORDER BY year")
    years = [row[0] for row in cursor.fetchall()]
    return render_template('recommend.html', categories=categories, authors=authors, years=years)


@app.route('/recommend_books', methods=['POST'])
def recommend():
    if 'user' not in session:
        return redirect(url_for('login'))

    user_input = request.form.get('user_input')
    category_filter = request.form.get('category', '')
    author_filter = request.form.get('author', '')
    year_filter = request.form.get('year', '')

    if not user_input:
        return render_template('recommend.html', data=[], error="Please enter a book title.")

    if user_input not in pt.index:
        return render_template('recommend.html', data=[], error="Book not found. Try another title.")

    index = np.where(pt.index == user_input)[0][0]
    similar_items = sorted(list(enumerate(similarity_scores[index])), key=lambda x: x[1], reverse=True)[1:5]

    data = []
    for item in similar_items:
        book_title = pt.index[item[0]]
        temp_df = books[books['Book-Title'].str.lower() == book_title.lower()]
        if not temp_df.empty:
            book_info = temp_df.iloc[0]
            # Apply filters
            if category_filter and book_info['Category'] != category_filter:
                continue
            if author_filter and book_info['Book-Author'] != author_filter:
                continue
            if year_filter and str(book_info['Year-Of-Publication']) != year_filter:
                continue
            data.append([book_title, book_info['Book-Author'], book_info['Image-URL-M']])

    # Re-fetch filter options for rendering
    cursor.execute("SELECT DISTINCT category FROM books WHERE category IS NOT NULL")
    categories = [row[0] for row in cursor.fetchall()]
    cursor.execute("SELECT DISTINCT book_author FROM books WHERE book_author IS NOT NULL")
    authors = [row[0] for row in cursor.fetchall()]
    cursor.execute("SELECT DISTINCT year FROM books WHERE year IS NOT NULL ORDER BY year")
    years = [row[0] for row in cursor.fetchall()]

    return render_template('recommend.html', data=data, categories=categories, authors=authors, years=years)


# Favorites Routes
@app.route('/favorites')
def favorites():
    if 'user' not in session:
        return redirect(url_for('login'))
    cursor.execute("SELECT book_title, author, image_url FROM favorites WHERE user=%s", (session['user'],))
    favorite_books = cursor.fetchall()
    return render_template('favorites.html', books=favorite_books)


@app.route('/add_favorite', methods=['POST'])
def add_favorite():
    if 'user' not in session:
        return jsonify({'error': 'You must be logged in'}), 401
    book_id = request.form.get('book_id')
    book_title = request.form.get('book_title')
    author = request.form.get('author')
    image_url = request.form.get('image_url')
    if not book_title or not author or not image_url:
        return jsonify({'error': 'Missing book details'}), 400
    try:
        cursor.execute("INSERT INTO favorites (user, book_title, author, image_url) VALUES (%s, %s, %s, %s)",
                       (session['user'], book_title, author, image_url))
        db.commit()
        # Log activity
        log_user_activity(session['user'], 'favorite', book_title, "Added to favorites")
        return jsonify({'message': 'Book added to favorites successfully!'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/remove_favorite', methods=['POST'])
def remove_favorite():
    if 'user' not in session:
        return jsonify({'error': 'You must be logged in'}), 401
    book_title = request.form.get('book_title')
    try:
        cursor.execute("DELETE FROM favorites WHERE user=%s AND book_title=%s", (session['user'], book_title))
        db.commit()
        return redirect(url_for('favorites'))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Reading List Routes
@app.route('/reading_list')
def reading_list():
    if 'user' not in session:
        return redirect(url_for('login'))

    cursor.execute("""
        SELECT rl.book_title, rl.status, rl.added_at, b.image_url, rl.current_page, rl.progress_percentage
        FROM reading_list rl
        LEFT JOIN books b ON rl.book_title = b.book_title
        WHERE rl.user=%s
        ORDER BY rl.added_at DESC
    """, (session['user'],))
    reading_list = cursor.fetchall()
    return render_template('reading_list.html', reading_list=reading_list)


@app.route('/add_to_reading_list', methods=['POST'])
def add_to_reading_list():
    if 'user' not in session:
        return jsonify({'error': 'You must be logged in'}), 401

    book_title = request.form.get('book_title')
    status = request.form.get('status')
    if not book_title or not status:
        return jsonify({'error': 'Book title and status are required'}), 400

    if status not in ['To Read', 'Currently Reading', 'Read']:
        return jsonify({'error': 'Invalid status'}), 400

    try:
        cursor.execute("""
            INSERT INTO reading_list (user, book_title, status, current_page, progress_percentage)
            VALUES (%s, %s, %s, 0, 0)
            ON DUPLICATE KEY UPDATE status=%s
        """, (session['user'], book_title, status, status))
        db.commit()
        # Log activity
        log_user_activity(session['user'], 'reading_list', book_title, f"Added to reading list with status: {status}")
        # Check for achievements if status is 'Read'
        if status == 'Read':
            check_achievements(session['user'])
        return jsonify({'message': f'Book added to reading list with status: {status}'})
    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/remove_from_reading_list', methods=['POST'])
def remove_from_reading_list():
    if 'user' not in session:
        return jsonify({'error': 'You must be logged in'}), 401

    book_title = request.form.get('book_title')
    try:
        cursor.execute("DELETE FROM reading_list WHERE user=%s AND book_title=%s", (session['user'], book_title))
        db.commit()
        return redirect(url_for('reading_list'))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Trending Route
@app.route('/trending')
def trending():
    try:
        query = """
        SELECT r.book_title, 
               COALESCE(f.author, 'Unknown') AS author, 
               COALESCE(f.image_url, 'https://via.placeholder.com/150') AS image_url, 
               COUNT(r.book_title) AS num_ratings, 
               ROUND(AVG(r.book_rating), 2) AS avg_rating
        FROM ratings r
        LEFT JOIN favorites f ON r.book_title = f.book_title
        GROUP BY r.book_title, f.author, f.image_url
        ORDER BY num_ratings DESC, avg_rating DESC
        LIMIT 20;
        """
        cursor = db.cursor()
        cursor.execute(query)
        trending_books = cursor.fetchall()
        print("TRENDING BOOKS DATA:", trending_books)
        return render_template('trending.html', books=trending_books)
    except mysql.connector.Error as err:
        return f"Database error: {err}"
    finally:
        cursor.close()


# Profile Route with Enhancements
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user']

    # Handle profile picture upload
    if request.method == 'POST' and 'profile_picture' in request.files:
        file = request.files['profile_picture']
        if file and allowed_file(file.filename):
            filename = secure_filename(f"{uuid.uuid4()}_{file.filename}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            cursor.execute("UPDATE users SET profile_picture=%s WHERE username=%s",
                           (f"/{UPLOAD_FOLDER}/{filename}", username))
            db.commit()
            return redirect(url_for('profile'))

    # Fetch user data
    cursor.execute("SELECT profile_picture FROM users WHERE username=%s", (username,))
    user_data = cursor.fetchone()
    profile_picture = user_data[0] if user_data and user_data[0] else '/static/default_profile.jpg'

    cursor.execute("SELECT book_title, author, image_url FROM favorites WHERE user=%s", (username,))
    favorite_books = cursor.fetchall()

    cursor.execute("SELECT book_title, book_rating FROM ratings WHERE user=%s", (username,))
    user_ratings = cursor.fetchall()

    # Reading statistics
    cursor.execute("SELECT COUNT(*) FROM reading_list WHERE user=%s AND status='Read'", (username,))
    books_read = cursor.fetchone()[0]

    cursor.execute("SELECT AVG(book_rating) FROM ratings WHERE user=%s", (username,))
    avg_rating = cursor.fetchone()[0]
    avg_rating = round(avg_rating, 2) if avg_rating else 0

    # Fetch achievements
    cursor.execute(
        "SELECT achievement_name, description, earned_at FROM user_achievements WHERE user=%s ORDER BY earned_at DESC",
        (username,))
    achievements = cursor.fetchall()

    return render_template('profile.html',
                           username=username,
                           profile_picture=profile_picture,
                           favorites=favorite_books,
                           ratings=user_ratings,
                           books_read=books_read,
                           avg_rating=avg_rating,
                           achievements=achievements)


# Search Route with Pagination and Advanced Filters
@app.route('/search', methods=['GET'])
def search_books():
    query = request.args.get('q', '')
    author = request.args.get('author', '')
    category = request.args.get('category', '')
    min_rating = request.args.get('min_rating', '')
    min_year = request.args.get('min_year', '')
    max_year = request.args.get('max_year', '')
    sort = request.args.get('sort', 'title')
    page = int(request.args.get('page', 1))
    per_page = 10

    cursor = db.cursor()
    base_query = """
        SELECT b.id, b.book_title, b.book_author, b.image_url, b.year, b.publisher, b.category,
               (SELECT COALESCE(AVG(r.book_rating), 0)
                FROM ratings r
                WHERE r.book_title = b.book_title) as avg_rating
        FROM books b
        WHERE 1=1
    """
    params = []

    if query:
        base_query += " AND (b.book_title LIKE %s OR b.book_author LIKE %s)"
        params.extend(['%' + query + '%', '%' + query + '%'])
    if author:
        base_query += " AND b.book_author LIKE %s"
        params.append('%' + author + '%')
    if category:
        base_query += " AND b.category = %s"
        params.append(category)
    if min_rating:
        try:
            min_rating = float(min_rating)
            base_query += " AND (SELECT COALESCE(AVG(r.book_rating), 0) FROM ratings r WHERE r.book_title = b.book_title) >= %s"
            params.append(min_rating)
        except ValueError:
            pass
    if min_year:
        try:
            min_year = int(min_year)
            base_query += " AND b.year >= %s"
            params.append(min_year)
        except ValueError:
            pass
    if max_year:
        try:
            max_year = int(max_year)
            base_query += " AND b.year <= %s"
            params.append(max_year)
        except ValueError:
            pass

    # Get total count for pagination
    count_query = "SELECT COUNT(*) FROM (" + base_query + ") as subquery"
    cursor.execute(count_query, params)
    total_books = cursor.fetchone()[0]

    # Add sorting and pagination
    if sort == 'rating_desc':
        base_query += " ORDER BY avg_rating DESC"
    elif sort == 'rating_asc':
        base_query += " ORDER BY avg_rating ASC"
    else:
        base_query += " ORDER BY b.book_title ASC"

    base_query += " LIMIT %s OFFSET %s"
    params.extend([per_page, (page - 1) * per_page])

    print("Executing query:", base_query)
    print("With parameters:", params)

    cursor.execute(base_query, params)
    books_result = cursor.fetchall()
    cursor.close()

    books_list = []
    for book in books_result:
        books_list.append({
            'id': book[0],
            'book_title': book[1],
            'book_author': book[2],
            'image_url': book[3],
            'year': book[4],
            'publisher': book[5],
            'category': book[6],
            'avg_rating': round(book[7], 2) if book[7] else 'N/A'
        })

    total_pages = (total_books + per_page - 1) // per_page
    return jsonify({
        'books': books_list,
        'total_books': total_books,
        'total_pages': total_pages,
        'current_page': page
    })


# Category Filter Route
@app.route('/category/<category>')
def books_by_category(category):
    if 'user' not in session:
        return redirect(url_for('login'))

    cursor.execute("""
        SELECT b.book_title, b.book_author, b.image_url,
               (SELECT COUNT(*) FROM ratings r WHERE r.book_title = b.book_title) as num_ratings,
               (SELECT AVG(r.book_rating) FROM ratings r WHERE r.book_title = b.book_title) as avg_rating
        FROM books b
        WHERE b.category = %s
        LIMIT 20
    """, (category,))
    books_data = cursor.fetchall()

    book_data = []
    for book in books_data:
        book_data.append({
            'book_title': book[0],
            'book_author': book[1],
            'image_url': book[2],
            'num_ratings': book[3],
            'avg_rating': round(book[4], 2) if book[4] else 0
        })

    return render_template('category.html', category=category, books=book_data)


# Helper function for file uploads
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


if __name__ == '__main__':
    try:
        app.run(debug=True, host='localhost', port=5000)
    finally:
        cursor.close()
        db.close()
        print("Database connection closed.")
