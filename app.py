from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from config import Config
from datetime import datetime, timedelta
import os
import hashlib
from werkzeug.utils import secure_filename
from sqlalchemy.orm import joinedload
from sqlalchemy import create_engine, MetaData, Table, text
from sqlalchemy.orm import sessionmaker
import secrets
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
import time
import threading
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mssql+pyodbc://E\\SQLEXPRESS/ReviseMe?driver=ODBC+Driver+17+for+SQL+Server&trusted_connection=yes'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# CSRF korumasını aktif et
csrf = CSRFProtect(app)

# E-posta ayarları
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'  # Gmail adresiniz
app.config['MAIL_PASSWORD'] = 'your-app-password'     # Gmail uygulama şifreniz
app.config['MAIL_DEFAULT_SENDER'] = 'your-email@gmail.com'

# SendGrid API anahtarı
app.config['SENDGRID_API_KEY'] = 'YOUR_SENDGRID_API_KEY'  # SendGrid API anahtarınızı buraya yazın
app.config['SENDGRID_FROM_EMAIL'] = 'your-verified-sender@yourdomain.com'  # Doğrulanmış gönderici e-posta adresiniz

# SQLAlchemy bağlantısını oluştur
engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
Session = sessionmaker(bind=engine)
session = Session()

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

# Database Models
class User(UserMixin, db.Model):
    __tablename__ = 'Users'
    UserId = db.Column(db.Integer, primary_key=True)
    UserName = db.Column(db.String(50), unique=True, nullable=False)
    PasswordHash = db.Column(db.String(128), nullable=False)
    Name = db.Column(db.String(50))
    Surname = db.Column(db.String(50))
    Class = db.Column(db.String(50))
    YearOfBirth = db.Column(db.Integer)
    Area = db.Column(db.String(50))
    Aim = db.Column(db.String(100))
    Email = db.Column(db.String(100))
    PhoneNumber = db.Column(db.String(20))
    GoogleAuthId = db.Column(db.String(100))
    SecurityQuestion = db.Column(db.String(200))

    def get_id(self):
        return str(self.UserId)
        
    def can_modify(self, question):
        return self.UserId == question.UserId

class Category(db.Model):
    __tablename__ = 'Categories'
    CategoryId = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(50))

class Question(db.Model):
    __tablename__ = 'Questions'
    
    QuestionId = db.Column(db.Integer, primary_key=True)
    UserId = db.Column(db.Integer, db.ForeignKey('Users.UserId'), nullable=False)
    Content = db.Column(db.Text, nullable=False)
    CategoryId = db.Column(db.Integer, db.ForeignKey('Categories.CategoryId'), nullable=False)
    DifficultyLevel = db.Column(db.String(20))
    PhotoPath = db.Column(db.String(255))
    IsRepeated = db.Column(db.Boolean, default=False)
    RepeatCount = db.Column(db.Integer, default=0)
    Repeat1Date = db.Column(db.DateTime)
    Repeat2Date = db.Column(db.DateTime)
    Repeat3Date = db.Column(db.DateTime)
    IsCompleted = db.Column(db.Boolean, default=False)
    IsViewed = db.Column(db.Boolean, default=False)
    Explanation = db.Column(db.Text)
    ImagePath = db.Column(db.String(255))
    IsHidden = db.Column(db.Boolean, default=False)  # Yeni eklenen sütun
    
    user = db.relationship('User', backref=db.backref('questions', lazy=True))
    category = db.relationship('Category', backref=db.backref('questions', lazy=True))

class Note(db.Model):
    __tablename__ = 'Notes'
    NoteId = db.Column(db.Integer, primary_key=True)
    QuestionId = db.Column(db.Integer, db.ForeignKey('Questions.QuestionId'))
    Content = db.Column(db.Text)
    
    # İlişki
    question = db.relationship('Question', backref='notes')

class Favorite(db.Model):
    __tablename__ = 'Favorites'
    FavoriteId = db.Column(db.Integer, primary_key=True)
    QuestionId = db.Column(db.Integer, db.ForeignKey('Questions.QuestionId'), nullable=False)
    UserId = db.Column(db.Integer, db.ForeignKey('Users.UserId'), nullable=False)
    
    # İlişkiler
    question = db.relationship('Question', backref='favorites')
    user = db.relationship('User', backref='favorites')

class Notification(db.Model):
    __tablename__ = 'Notifications'
    NotificationId = db.Column(db.Integer, primary_key=True)
    UserId = db.Column(db.Integer, db.ForeignKey('Users.UserId'))
    NotificationType = db.Column(db.String(50))
    TaskId = db.Column(db.Integer, db.ForeignKey('Tasks.TaskId'))
    Schedule = db.Column(db.DateTime)
    IsRead = db.Column(db.Boolean, default=False)
    
    user = db.relationship('User', backref='notifications')
    task = db.relationship('Task', backref='notifications')

class PasswordResetToken(db.Model):
    __tablename__ = 'PasswordResetTokens'
    TokenId = db.Column(db.Integer, primary_key=True)
    UserId = db.Column(db.Integer, db.ForeignKey('Users.UserId'), nullable=False)
    Token = db.Column(db.String(100), unique=True, nullable=False)
    ExpiresAt = db.Column(db.DateTime, nullable=False)
    IsUsed = db.Column(db.Boolean, default=False)
    
    user = db.relationship('User', backref='password_reset_tokens')

class TedTalk(db.Model):
    __tablename__ = 'TedTalks'
    TalkId = db.Column(db.Integer, primary_key=True)
    Title = db.Column(db.String(200), nullable=False)
    Speaker = db.Column(db.String(100), nullable=False)
    VideoUrl = db.Column(db.String(500), nullable=False)
    Description = db.Column(db.Text)
    Duration = db.Column(db.String(50))
    Category = db.Column(db.String(100))
    IsWatched = db.Column(db.Boolean, default=False)
    UserId = db.Column(db.Integer, db.ForeignKey('Users.UserId'), nullable=False)
    user = db.relationship('User', backref='ted_talks')

class Book(db.Model):
    __tablename__ = 'Books'
    BookId = db.Column(db.Integer, primary_key=True)
    Title = db.Column(db.String(200))
    Author = db.Column(db.String(100))
    CurrentPage = db.Column(db.Integer)
    TotalPages = db.Column(db.Integer)
    StartDate = db.Column(db.DateTime)
    UserId = db.Column(db.Integer, db.ForeignKey('Users.UserId'))
    user = db.relationship('User', backref='books')

class BookQuote(db.Model):
    __tablename__ = 'BookQuotes'
    QuoteId = db.Column(db.Integer, primary_key=True)
    BookId = db.Column(db.Integer, db.ForeignKey('Books.BookId'))
    PageNumber = db.Column(db.Integer)
    Content = db.Column(db.Text)
    Note = db.Column(db.Text)
    CreatedAt = db.Column(db.DateTime, default=datetime.utcnow)
    book = db.relationship('Book', backref='quotes')

class ChatMessage(db.Model):
    __tablename__ = 'ChatMessages'
    MessageId = db.Column(db.Integer, primary_key=True)
    UserId = db.Column(db.Integer, db.ForeignKey('Users.UserId'))
    Content = db.Column(db.Text)
    IsFromAI = db.Column(db.Boolean, default=False)
    CreatedAt = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='chat_messages')

class Task(db.Model):
    __tablename__ = 'Tasks'
    TaskId = db.Column(db.Integer, primary_key=True)
    UserId = db.Column(db.Integer, db.ForeignKey('Users.UserId'))
    Title = db.Column(db.String(200))
    Description = db.Column(db.Text)
    DueDate = db.Column(db.DateTime)
    Priority = db.Column(db.String(20))  # 'high', 'medium', 'low'
    Category = db.Column(db.String(50))  # 'work', 'personal', 'hobby'
    Status = db.Column(db.String(20))  # 'pending', 'completed'
    CreatedAt = db.Column(db.DateTime, default=datetime.utcnow)
    CompletedAt = db.Column(db.DateTime)
    user = db.relationship('User', backref='tasks')

class TaskTime(db.Model):
    __tablename__ = 'TaskTimes'
    TimeId = db.Column(db.Integer, primary_key=True)
    TaskId = db.Column(db.Integer, db.ForeignKey('Tasks.TaskId'))
    StartTime = db.Column(db.DateTime)
    EndTime = db.Column(db.DateTime)
    Duration = db.Column(db.Integer)  # Dakika cinsinden
    task = db.relationship('Task', backref='time_records')

class TaskReport(db.Model):
    __tablename__ = 'TaskReports'
    ReportId = db.Column(db.Integer, primary_key=True)
    UserId = db.Column(db.Integer, db.ForeignKey('Users.UserId'))
    ReportDate = db.Column(db.DateTime)
    CompletedTasks = db.Column(db.Integer)
    OverdueTasks = db.Column(db.Integer)
    TotalTimeSpent = db.Column(db.Integer)  # Dakika cinsinden
    ReportContent = db.Column(db.Text)
    user = db.relationship('User', backref='task_reports')

class UserSettings(db.Model):
    __tablename__ = 'UserSettings'
    SettingId = db.Column(db.Integer, primary_key=True)
    UserId = db.Column(db.Integer, db.ForeignKey('Users.UserId'))
    Theme = db.Column(db.String(20), default='light')  # 'light', 'dark'
    EmailNotifications = db.Column(db.Boolean, default=True)
    user = db.relationship('User', backref='settings')

class Reminder(db.Model):
    __tablename__ = 'Reminders'
    ReminderId = db.Column(db.Integer, primary_key=True)
    UserId = db.Column(db.Integer, db.ForeignKey('Users.UserId'), nullable=False)
    QuestionId = db.Column(db.Integer, db.ForeignKey('Questions.QuestionId'), nullable=False)
    Frequency = db.Column(db.String(20))  # 'daily', 'weekly', 'monthly'
    Time = db.Column(db.Time)  # Hatırlatma saati
    IsActive = db.Column(db.Boolean, default=True)
    LastSent = db.Column(db.DateTime)
    CreatedAt = db.Column(db.DateTime, default=datetime.now)
    
    user = db.relationship('User', backref='reminders')
    question = db.relationship('Question', backref='reminders')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/welcome')
def welcome():
    return render_template('welcome.html')

@app.route('/')
@login_required
def index():
    # Bugünün sorularını say
    today = datetime.now().date()
    daily_questions_count = Question.query.filter(
        Question.UserId == current_user.UserId,
        db.text("CAST([Questions].[Repeat1Date] AS DATE) = :today"),
        Question.IsCompleted == False
    ).params(today=today).count()

    # Toplam soru sayısı
    total_questions_count = Question.query.filter_by(
        UserId=current_user.UserId
    ).count()

    # Okunan kitap sayısı
    books_count = Book.query.filter_by(
        UserId=current_user.UserId
    ).count()

    # İzlenen TEDx sayısı
    ted_talks_count = TedTalk.query.filter_by(
        UserId=current_user.UserId
    ).count()

    # Aktif görev sayısı
    tasks_count = Task.query.filter_by(
        UserId=current_user.UserId,
        Status='pending'
    ).count()

    # Motivasyon mesajları
    motivation_messages = [
        "Başarı, küçük adımların toplamıdır!",
        "Her gün bir adım daha ileriye!",
        "Zorlandığında vazgeçme, mola ver ve devam et!",
        "Küçük adımlar büyük başarılar getirir!",
        "Bugün dünden daha iyi ol!",
        "Başarı yolunda ilerliyorsun!",
        "Kendine inan, başarabilirsin!",
        "Her tekrar seni hedefe yaklaştırır!"
    ]
    motivation_message = random.choice(motivation_messages)

    return render_template('index.html',
                         daily_questions_count=daily_questions_count,
                         total_questions_count=total_questions_count,
                         books_count=books_count,
                         ted_talks_count=ted_talks_count,
                         tasks_count=tasks_count,
                         motivation_message=motivation_message)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        class_level = request.form.get('class_level')
        year_of_birth = request.form.get('year_of_birth')
        area = request.form.get('area')
        aim = request.form.get('aim')
        security_question = request.form.get('security_question')
        security_answer = request.form.get('security_answer')

        # Kullanıcı adı kontrolü
        if User.query.filter_by(UserName=username).first():
            flash('Bu kullanıcı adı zaten kullanılıyor.')
            return redirect(url_for('register'))

        # E-posta kontrolü
        if User.query.filter_by(Email=email).first():
            flash('Bu e-posta adresi zaten kullanılıyor.')
            return redirect(url_for('register'))

        # Şifre kontrolü
        if password != password_confirm:
            flash('Şifreler eşleşmiyor.')
            return redirect(url_for('register'))

        # Şifreyi hashle
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        # Yeni kullanıcı oluştur
        new_user = User(
            UserName=username,
            PasswordHash=password_hash,
            Name=first_name,
            Surname=last_name,
            Email=email,
            Class=class_level,
            YearOfBirth=year_of_birth,
            Area=area,
            Aim=aim,
            SecurityQuestion=security_question
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Kayıt başarılı! Şimdi giriş yapabilirsiniz.')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Kayıt sırasında bir hata oluştu. Lütfen tekrar deneyin.')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(UserName=username).first()
        
        if user and user.PasswordHash == hashlib.sha256(password.encode()).hexdigest():
            login_user(user)
            flash('Başarıyla giriş yaptınız!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Geçersiz kullanıcı adı veya şifre', 'danger')
    return render_template('login.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/add_question', methods=['GET', 'POST'])
@login_required
def add_question():
    if request.method == 'POST':
        try:
            content = request.form.get('content')
            category = request.form.get('category')
            question_image = request.files.get('question_image')
            
            if not content or not category:
                flash('Lütfen tüm zorunlu alanları doldurun.', 'error')
                return redirect(url_for('add_question'))
            
            # Görsel yükleme işlemi
            image_path = None
            if question_image and question_image.filename:
                try:
                    filename = secure_filename(question_image.filename)
                    unique_filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
                    
                    upload_folder = os.path.join(app.static_folder, 'uploads')
                    if not os.path.exists(upload_folder):
                        os.makedirs(upload_folder)
                    
                    image_path = f"uploads/{unique_filename}"
                    full_path = os.path.join(app.static_folder, 'uploads', unique_filename)
                    
                    question_image.save(full_path)
                except Exception as e:
                    flash('Görsel yüklenirken bir hata oluştu.', 'error')
            
            # Yeni soru oluştur
            now = datetime.now()
            new_question = Question(
                UserId=current_user.UserId,
                Content=content,
                CategoryId=category,
                ImagePath=image_path,
                PhotoPath=None,
                IsCompleted=False,
                IsViewed=False,
                IsRepeated=False,
                RepeatCount=0,
                Repeat1Date=now,
                Repeat2Date=now + timedelta(days=3),
                Repeat3Date=now + timedelta(days=7),
                Explanation=None,
                DifficultyLevel=None
            )
            
            db.session.add(new_question)
            db.session.commit()
            
            flash('Soru başarıyla eklendi.', 'success')
            return redirect(url_for('questions'))
            
        except Exception as e:
            db.session.rollback()
            flash('Soru eklenirken bir hata oluştu: ' + str(e), 'error')
            return redirect(url_for('add_question'))
    
    # Kategorileri veritabanından çek
    categories = Category.query.order_by(Category.Name).all()
    return render_template('add_question.html', categories=categories)

@app.route('/edit_question/<int:question_id>', methods=['GET', 'POST'])
@login_required
def edit_question(question_id):
    question = Question.query.get_or_404(question_id)
    if question.UserId != current_user.UserId:
        flash('Bu soruyu düzenleme yetkiniz yok.')
        return redirect(url_for('questions'))
    
    if request.method == 'POST':
        question.Content = request.form.get('content')
        question.CategoryId = request.form.get('category')
        
        try:
            db.session.commit()
            flash('Soru başarıyla güncellendi.')
            return redirect(url_for('questions'))
        except Exception as e:
            db.session.rollback()
            flash('Soru güncellenirken bir hata oluştu.')
            return redirect(url_for('edit_question', question_id=question_id))
    
    categories = Category.query.order_by(Category.Name).all()
    return render_template('edit_question.html', question=question, categories=categories)

@app.route('/view_question/<int:question_id>')
@login_required
def view_question(question_id):
    question = Question.query.get_or_404(question_id)
    if question.UserId != current_user.UserId:
        flash('Bu soruyu görüntüleme yetkiniz yok.', 'error')
        return redirect(url_for('index'))
    
    # Notları getir
    notes = Note.query.filter_by(QuestionId=question_id).order_by(Note.NoteId.desc()).all()
    
    # Favori durumunu kontrol et
    is_favorite = Favorite.query.filter_by(
        QuestionId=question_id,
        UserId=current_user.UserId
    ).first() is not None
    
    # Tekrar durumunu hesapla
    repeat_status = {
        'count': question.RepeatCount,
        'is_completed': question.IsCompleted,
        'is_repeated': question.IsRepeated,
        'dates': {
            'repeat1': question.Repeat1Date,
            'repeat2': question.Repeat2Date,
            'repeat3': question.Repeat3Date
        }
    }
    
    return render_template('view_question.html', 
                         question=question, 
                         notes=notes,
                         is_favorite=is_favorite,
                         repeat_status=repeat_status)

@app.route('/add_note/<int:question_id>', methods=['POST'])
@login_required
def add_note(question_id):
    try:
        question = Question.query.get_or_404(question_id)
        if question.UserId != current_user.UserId:
            return jsonify({'success': False, 'error': 'Bu işlem için yetkiniz yok.'}), 403

        data = request.get_json()
        if not data or 'content' not in data:
            return jsonify({'success': False, 'error': 'Not içeriği gerekli.'}), 400

        note = Note(
            Content=data['content'],
            QuestionId=question_id
        )
        db.session.add(note)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'note': {
                'content': note.Content,
                'created_at': note.CreatedAt.strftime('%d.%m.%Y %H:%M') if note.CreatedAt else datetime.now().strftime('%d.%m.%Y %H:%M')
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/delete_question/<int:question_id>', methods=['POST'])
@login_required
def delete_question(question_id):
    try:
        question = Question.query.get_or_404(question_id)
        if question.UserId != current_user.UserId:
            return jsonify({'success': False, 'error': 'Bu işlem için yetkiniz yok.'}), 403

        # Önce favorilerden sil
        Favorite.query.filter_by(QuestionId=question_id).delete()
        
        # Sonra soruyu sil
        db.session.delete(question)
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/mark_completed/<int:question_id>', methods=['POST'])
@login_required
def mark_completed(question_id):
    question = Question.query.get_or_404(question_id)
    if question.UserId != current_user.UserId:
        abort(403)
    
    question.IsCompleted = True
    question.CompletedAt = datetime.now()
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/questions')
@login_required
def questions():
    categories = Category.query.all()
    selected_category = request.args.get('category', type=int)
    query = Question.query.filter_by(UserId=current_user.UserId, IsHidden=False)
    if selected_category:
        query = query.filter_by(CategoryId=selected_category)
    questions = query.order_by(Question.QuestionId.desc()).all()
    # Rastgele motive mesajı seç
    motivation_messages = [
        "Her gün bir adım daha ileriye!",
        "Başarı yolunda her soru bir fırsat!",
        "Bugün çalış, yarın başar!",
        "Küçük adımlar büyük başarılar getirir!",
        "Her soru seni hedefine yaklaştırıyor!"
    ]
    motivation_message = random.choice(motivation_messages)
    return render_template('questions.html', 
                         questions=questions, 
                         categories=categories,
                         selected_category=selected_category,
                         motivation_message=motivation_message)

@app.route('/category/<int:category_id>')
@login_required
def category_questions(category_id):
    category = Category.query.get_or_404(category_id)
    questions = Question.query.filter_by(
        UserId=current_user.UserId,
        CategoryId=category_id
    ).order_by(Question.Repeat1Date).all()
    return render_template('category_questions.html', category=category, questions=questions)

@app.route('/favorites')
@login_required
def favorites():
    questions = Question.query.join(
        Favorite,
        Question.QuestionId == Favorite.QuestionId
    ).filter(
        Favorite.UserId == current_user.UserId
    ).order_by(Question.Repeat1Date).all()
    return render_template('favorites.html', questions=questions)

@app.route('/toggle_favorite/<int:question_id>', methods=['POST'])
@login_required
def toggle_favorite(question_id):
    try:
        question = Question.query.get_or_404(question_id)
        if question.UserId != current_user.UserId:
            return jsonify({'success': False, 'error': 'Bu soruya erişim izniniz yok.'})
        
        favorite = Favorite.query.filter_by(
            UserId=current_user.UserId,
            QuestionId=question_id
        ).first()
        
        if favorite:
            db.session.delete(favorite)
            is_favorite = False
        else:
            favorite = Favorite(UserId=current_user.UserId, QuestionId=question_id)
            db.session.add(favorite)
            is_favorite = True
        
        db.session.commit()
        return jsonify({'success': True, 'is_favorite': is_favorite})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/notifications')
@login_required
def notifications():
    today = datetime.now().date()
    now = datetime.now()
    # Soru bildirimleri
    today_questions = Question.query.filter(
        Question.UserId == current_user.UserId,
        Question.Repeat1Date == today,
        Question.IsCompleted == False
    ).all()
    past_questions = Question.query.filter(
        Question.UserId == current_user.UserId,
        Question.Repeat1Date < today,
        Question.IsCompleted == False
    ).all()
    completed_today = Question.query.filter(
        Question.UserId == current_user.UserId,
        Question.IsCompleted == True,
        Question.Repeat1Date == today
    ).all()
    # Görev bildirimleri
    overdue_tasks = Task.query.filter(
        Task.UserId == current_user.UserId,
        Task.Status == 'pending',
        Task.DueDate < now
    ).all()
    completed_tasks = Task.query.filter(
        Task.UserId == current_user.UserId,
        Task.Status == 'completed',
        Task.CompletedAt >= now - timedelta(days=1)
    ).all()
    new_tasks = Task.query.filter(
        Task.UserId == current_user.UserId,
        Task.Status == 'pending',
        Task.CreatedAt >= now - timedelta(days=1)
    ).all()
    return render_template('notifications.html',
                         today_questions=today_questions,
                         past_questions=past_questions,
                         completed_today=completed_today,
                         overdue_tasks=overdue_tasks,
                         completed_tasks=completed_tasks,
                         new_tasks=new_tasks)

@app.route('/mark_notification_read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    if notification.UserId != current_user.UserId:
        flash('Bu bildirimi düzenleme yetkiniz yok.', 'error')
        return redirect(url_for('notifications'))
    
    try:
        notification.IsRead = True
        db.session.commit()
        flash('Bildirim okundu olarak işaretlendi.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Bildirim güncellenirken bir hata oluştu.', 'error')
    
    return redirect(url_for('notifications'))

@app.route('/ted-talks')
@login_required
def ted_talks():
    talks = TedTalk.query.filter_by(UserId=current_user.UserId).all()
    return render_template('ted_talks.html', talks=talks)

@app.route('/add-ted-talk', methods=['GET', 'POST'])
@login_required
def add_ted_talk():
    if request.method == 'POST':
        title = request.form.get('title')
        speaker = request.form.get('speaker')
        video_url = request.form.get('video_url')
        description = request.form.get('description')
        duration = request.form.get('duration')
        category = request.form.get('category')

        # YouTube URL'sini kontrol et ve düzenle
        if 'youtube.com' in video_url or 'youtu.be' in video_url:
            if 'youtube.com/watch?v=' in video_url:
                video_id = video_url.split('watch?v=')[1]
            elif 'youtu.be/' in video_url:
                video_id = video_url.split('youtu.be/')[1]
            else:
                flash('Geçersiz YouTube URL\'si!', 'error')
                return redirect(url_for('add_ted_talk'))
            
            # Embed URL'sini oluştur
            video_url = f'https://www.youtube.com/embed/{video_id}'
        else:
            flash('Lütfen geçerli bir YouTube URL\'si girin!', 'error')
            return redirect(url_for('add_ted_talk'))

        new_talk = TedTalk(
            Title=title,
            Speaker=speaker,
            VideoUrl=video_url,
            Description=description,
            Duration=duration,
            Category=category,
            UserId=current_user.UserId
        )

        db.session.add(new_talk)
        db.session.commit()
        flash('TEDx konuşması başarıyla eklendi!', 'success')
        return redirect(url_for('ted_talks'))

    return render_template('add_ted_talk.html')

@app.route('/mark-talk-watched/<int:talk_id>', methods=['POST'])
@login_required
def mark_talk_watched(talk_id):
    talk = TedTalk.query.get_or_404(talk_id)
    if talk.UserId != current_user.UserId:
        return jsonify({'success': False, 'error': 'Bu işlem için yetkiniz yok!'}), 403
    
    try:
        talk.IsWatched = True
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/delete-talk/<int:talk_id>', methods=['POST'])
@login_required
def delete_talk(talk_id):
    talk = TedTalk.query.get_or_404(talk_id)
    if talk.UserId != current_user.UserId:
        return jsonify({'success': False, 'error': 'Bu işlem için yetkiniz yok!'}), 403
    
    try:
        db.session.delete(talk)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# Kitap Takip Sistemi Route'ları
@app.route('/books')
@login_required
def books():
    user_books = Book.query.filter_by(UserId=current_user.UserId).all()
    return render_template('books.html', books=user_books)

@app.route('/add-book', methods=['GET', 'POST'])
@login_required
def add_book():
    if request.method == 'POST':
        title = request.form.get('title')
        author = request.form.get('author')
        total_pages = request.form.get('total_pages')
        current_page = request.form.get('current_page', 1)

        new_book = Book(
            Title=title,
            Author=author,
            TotalPages=total_pages,
            CurrentPage=current_page,
            StartDate=datetime.utcnow(),
            UserId=current_user.UserId
        )

        db.session.add(new_book)
        db.session.commit()
        flash('Kitap başarıyla eklendi!', 'success')
        return redirect(url_for('books'))

    return render_template('add_book.html')

@app.route('/edit-book/<int:book_id>', methods=['POST'])
@login_required
def edit_book(book_id):
    try:
        book = Book.query.get_or_404(book_id)
        if book.UserId != current_user.UserId:
            flash('Bu işlem için yetkiniz yok.', 'danger')
            return redirect(url_for('books'))
        
        book.Title = request.form.get('title')
        book.Author = request.form.get('author')
        book.CurrentPage = request.form.get('current_page')
        book.TotalPages = request.form.get('total_pages')
        
        db.session.commit()
        flash('Kitap başarıyla güncellendi.', 'success')
        return redirect(url_for('books'))
    except Exception as e:
        db.session.rollback()
        flash('Kitap güncellenirken bir hata oluştu.', 'danger')
        return redirect(url_for('books'))

@app.route('/update-book-progress/<int:book_id>', methods=['POST'])
@login_required
def update_book_progress(book_id):
    book = Book.query.get_or_404(book_id)
    if book.UserId != current_user.UserId:
        flash('Bu işlem için yetkiniz yok!', 'danger')
        return redirect(url_for('books'))

    current_page = request.form.get('current_page')
    if current_page and current_page.isdigit():
        book.CurrentPage = int(current_page)
        db.session.commit()
        flash('Kitap ilerlemesi güncellendi!', 'success')

    return redirect(url_for('books'))

@app.route('/add-quote/<int:book_id>', methods=['POST'])
@login_required
def add_quote(book_id):
    try:
        book = Book.query.get_or_404(book_id)
        if book.UserId != current_user.UserId:
            flash('Bu işlem için yetkiniz yok.', 'danger')
            return redirect(url_for('books'))
        
        content = request.form.get('content')
        page_number = request.form.get('page_number')
        
        if not content:
            flash('Alıntı içeriği boş olamaz.', 'danger')
            return redirect(url_for('books'))
        
        quote = BookQuote(
            BookId=book_id,
            Content=content,
            PageNumber=page_number,
            CreatedAt=datetime.now()
        )
        
        db.session.add(quote)
        db.session.commit()
        
        flash('Alıntı başarıyla eklendi.', 'success')
        return redirect(url_for('books'))
    except Exception as e:
        db.session.rollback()
        flash('Alıntı eklenirken bir hata oluştu.', 'danger')
        return redirect(url_for('books'))

@app.route('/delete-quote/<int:quote_id>', methods=['POST'])
@login_required
def delete_quote(quote_id):
    quote = BookQuote.query.get_or_404(quote_id)
    book = Book.query.get_or_404(quote.BookId)
    
    if book.UserId != current_user.UserId:
        return jsonify({'success': False, 'message': 'Bu işlem için yetkiniz yok.'})
    
    db.session.delete(quote)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/edit-quote/<int:quote_id>', methods=['POST'])
@login_required
def edit_quote(quote_id):
    quote = BookQuote.query.get_or_404(quote_id)
    book = Book.query.get_or_404(quote.BookId)
    
    if book.UserId != current_user.UserId:
        flash('Bu işlem için yetkiniz yok.', 'danger')
        return redirect(url_for('books'))
    
    content = request.form.get('content')
    page_number = request.form.get('page_number')
    
    if not content:
        flash('Alıntı içeriği boş olamaz.', 'danger')
        return redirect(url_for('books'))
    
    quote.Content = content
    quote.PageNumber = page_number
    
    db.session.commit()
    
    flash('Alıntı başarıyla güncellendi.', 'success')
    return redirect(url_for('books'))

# Yapay Zeka Sohbet Asistanı Route'ları
@app.route('/chat')
@login_required
def chat():
    messages = ChatMessage.query.filter_by(UserId=current_user.UserId).order_by(ChatMessage.CreatedAt).all()
    return render_template('chat.html', messages=messages)

@app.route('/send-message', methods=['POST'])
@login_required
def send_message():
    content = request.form.get('content')
    if not content:
        return jsonify({'error': 'Mesaj boş olamaz!'}), 400

    # Kullanıcı mesajını kaydet
    user_message = ChatMessage(
        UserId=current_user.UserId,
        Content=content,
        IsFromAI=False
    )
    db.session.add(user_message)

    # Kullanıcının mesajını analiz et ve uygun yanıtı oluştur
    response = generate_ai_response(content)
    
    # AI yanıtını kaydet
    ai_message = ChatMessage(
        UserId=current_user.UserId,
        Content=response,
        IsFromAI=True
    )
    db.session.add(ai_message)
    db.session.commit()

    return jsonify({
        'user_message': content,
        'ai_response': response
    })

def generate_ai_response(user_message):
    # Mesajı küçük harfe çevir
    message = user_message.lower()
    
    # Motivasyon kelimeleri
    motivation_keywords = ['motivasyon', 'motivasyonum', 'motive', 'enerji', 'güç', 'güçlü']
    study_keywords = ['çalışma', 'ders', 'sınav', 'test', 'ödev', 'proje']
    stress_keywords = ['stres', 'kaygı', 'endişe', 'panik', 'korku', 'baskı']
    success_keywords = ['başarı', 'kazanmak', 'kazanma', 'hedef', 'amaç']
    time_keywords = ['zaman', 'süre', 'vakit', 'geç', 'kalmak']
    
    # Mesajı analiz et ve uygun yanıtı seç
    if any(keyword in message for keyword in motivation_keywords):
        return "Motivasyonunuzu yüksek tutmak için şunları deneyebilirsiniz:\n" + \
               "1. Küçük hedefler belirleyin ve her başarıda kendinizi ödüllendirin\n" + \
               "2. Başarı hikayelerini okuyun veya dinleyin\n" + \
               "3. Düzenli egzersiz yapın\n" + \
               "4. Pozitif düşüncelere odaklanın\n" + \
               "5. Başarılarınızı bir günlüğe kaydedin"
    
    elif any(keyword in message for keyword in study_keywords):
        return "Etkili çalışma için önerilerim:\n" + \
               "1. Pomodoro tekniğini kullanın (25 dakika çalışma, 5 dakika mola)\n" + \
               "2. Çalışma ortamınızı düzenleyin\n" + \
               "3. Notlar alın ve düzenli tekrar yapın\n" + \
               "4. Farklı kaynaklardan yararlanın\n" + \
               "5. Grup çalışması yapın"
    
    elif any(keyword in message for keyword in stress_keywords):
        return "Stres yönetimi için önerilerim:\n" + \
               "1. Derin nefes egzersizleri yapın\n" + \
               "2. Düzenli uyku ve beslenme alışkanlığı edinin\n" + \
               "3. Hobilerinize zaman ayırın\n" + \
               "4. Sosyal destek alın\n" + \
               "5. Meditasyon veya yoga yapın"
    
    elif any(keyword in message for keyword in success_keywords):
        return "Başarıya ulaşmak için:\n" + \
               "1. Net ve ölçülebilir hedefler belirleyin\n" + \
               "2. Planlı ve düzenli çalışın\n" + \
               "3. Hatalarınızdan ders çıkarın\n" + \
               "4. Sürekli kendinizi geliştirin\n" + \
               "5. Başarılı insanların hikayelerini okuyun"
    
    elif any(keyword in message for keyword in time_keywords):
        return "Zaman yönetimi için önerilerim:\n" + \
               "1. Günlük plan yapın\n" + \
               "2. Önceliklerinizi belirleyin\n" + \
               "3. Zaman tuzaklarından kaçının\n" + \
               "4. Düzenli molalar verin\n" + \
               "5. Teknolojiyi verimli kullanın"
    
    else:
        return "Merhaba! Ben senin motivasyon asistanınım. Sana nasıl yardımcı olabilirim?\n" + \
               "Motivasyon, çalışma, stres, başarı veya zaman yönetimi konularında konuşabiliriz."

@app.route('/tasks')
@login_required
def tasks():
    # Aktif görevleri getir
    active_tasks = Task.query.filter_by(
        UserId=current_user.UserId,
        Status='pending'
    ).order_by(Task.DueDate.asc()).all()
    
    # Tamamlanan görevleri getir (son 24 saat içinde)
    completed_tasks = Task.query.filter_by(
        UserId=current_user.UserId,
        Status='completed'
    ).filter(
        Task.CompletedAt >= datetime.now() - timedelta(hours=24)
    ).order_by(Task.CompletedAt.desc()).all()
    
    return render_template('tasks.html',
                         active_tasks=active_tasks,
                         completed_tasks=completed_tasks)

@app.route('/add-task', methods=['GET', 'POST'])
@login_required
def add_task():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        due_date = datetime.strptime(request.form.get('due_date'), '%Y-%m-%dT%H:%M')
        priority = request.form.get('priority')
        category = request.form.get('category')

        new_task = Task(
            UserId=current_user.UserId,
            Title=title,
            Description=description,
            DueDate=due_date,
            Priority=priority,
            Category=category,
            Status='pending'
        )

        db.session.add(new_task)
        db.session.commit()
        flash('Görev başarıyla eklendi!', 'success')
        return redirect(url_for('tasks'))

    return render_template('add_task.html')

@app.route('/edit-task/<int:task_id>', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    
    # Kullanıcı yetkisi kontrolü
    if task.UserId != current_user.UserId:
        flash('Bu görevi düzenleme yetkiniz yok!', 'danger')
        return redirect(url_for('tasks'))
    
    if request.method == 'POST':
        task.Title = request.form.get('title')
        task.Description = request.form.get('description')
        task.DueDate = datetime.strptime(request.form.get('due_date'), '%Y-%m-%dT%H:%M')
        task.Priority = request.form.get('priority')
        task.Category = request.form.get('category')
        
        db.session.commit()
        flash('Görev başarıyla güncellendi!', 'success')
        return redirect(url_for('tasks'))
    
    return render_template('edit_task.html', task=task)

@app.route('/delete-task/<int:task_id>', methods=['POST'])
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.UserId != current_user.UserId:
        return jsonify({'success': False, 'error': 'Bu işlem için yetkiniz yok!'}), 403
    
    try:
        db.session.delete(task)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/generate-report', methods=['POST'])
@login_required
def generate_report():
    today = datetime.now().date()
    
    # Tamamlanan görevler
    completed_tasks = Task.query.filter(
        Task.UserId == current_user.UserId,
        Task.Status == 'completed',
        db.text("CAST([Tasks].[CompletedAt] AS DATE) = :today")
    ).params(today=today).all()
    
    # Geciken görevler
    overdue_tasks = Task.query.filter(
        Task.UserId == current_user.UserId,
        Task.Status == 'pending',
        Task.DueDate < datetime.now()
    ).all()
    
    # Toplam çalışma süresi (görev türü fark etmeksizin, o günün tüm TaskTime kayıtları)
    total_time = db.session.query(db.func.sum(TaskTime.Duration)).join(Task).filter(
        Task.UserId == current_user.UserId,
        db.text("CAST([TaskTimes].[StartTime] AS DATE) = :today")
    ).params(today=today).scalar() or 0
    
    # Toplam görev sayısı (bugün tamamlanan + geciken + aktif)
    total_tasks = len(completed_tasks) + len(overdue_tasks)
    completion_rate = int((len(completed_tasks) / total_tasks) * 100) if total_tasks > 0 else 0
    
    # Rapor içeriğini oluştur
    report_content = f"""Günlük Görev Raporu - {today.strftime('%d.%m.%Y')}

Tamamlanan Görevler:
{'-' * 50}
"""
    
    for task in completed_tasks:
        report_content += f"- {task.Title}\n"
    
    report_content += f"""
Geciken Görevler:
{'-' * 50}
"""
    
    for task in overdue_tasks:
        report_content += f"- {task.Title} (Son Tarih: {task.DueDate.strftime('%d.%m.%Y %H:%M')})\n"
    
    report_content += f"""
Toplam Çalışma Süresi: {total_time} dakika
"""
    
    # Raporu kaydet
    report = TaskReport(
        UserId=current_user.UserId,
        ReportDate=datetime.now(),
        CompletedTasks=len(completed_tasks),
        OverdueTasks=len(overdue_tasks),
        TotalTimeSpent=total_time,
        ReportContent=report_content
    )
    
    db.session.add(report)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'report': {
            'content': report_content,
            'completed': len(completed_tasks),
            'overdue': len(overdue_tasks),
            'time': total_time,
            'completion_rate': completion_rate
        }
    })

@app.route('/start-timer/<int:task_id>', methods=['POST'])
@login_required
def start_timer(task_id):
    task = Task.query.get_or_404(task_id)
    if task.UserId != current_user.UserId:
        return jsonify({'success': False, 'error': 'Bu işlem için yetkiniz yok!'}), 403
    
    # Aktif zamanlayıcı var mı kontrol et
    active_timer = TaskTime.query.filter_by(
        TaskId=task_id,
        EndTime=None
    ).first()
    
    if active_timer:
        return jsonify({'success': False, 'error': 'Bu görev için zaten aktif bir zamanlayıcı var!'}), 400
    
    # Yeni zamanlayıcı başlat
    timer = TaskTime(
        TaskId=task_id,
        StartTime=datetime.now()
    )
    
    db.session.add(timer)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'time_id': timer.TimeId
    })

@app.route('/stop-timer/<int:time_id>', methods=['POST'])
@login_required
def stop_timer(time_id):
    timer = TaskTime.query.get_or_404(time_id)
    if timer.task.UserId != current_user.UserId:
        return jsonify({'success': False, 'error': 'Bu işlem için yetkiniz yok!'}), 403
    
    timer.EndTime = datetime.now()
    timer.Duration = int((timer.EndTime - timer.StartTime).total_seconds() / 60)
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'duration': timer.Duration
    })

@app.route('/task-timer/<int:task_id>')
@login_required
def task_timer(task_id):
    task = Task.query.get_or_404(task_id)
    if task.UserId != current_user.UserId:
        flash('Bu görev için zamanlayıcı kullanamazsınız!', 'danger')
        return redirect(url_for('tasks'))
    
    return render_template('task_timer.html', task=task)

@app.route('/complete-task/<int:task_id>', methods=['POST'])
@login_required
def complete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.UserId != current_user.UserId:
        return jsonify({'success': False, 'error': 'Bu işlem için yetkiniz yok!'}), 403
    
    try:
        task.Status = 'completed'
        task.CompletedAt = datetime.now()
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# Otomatik görev temizleme fonksiyonu
def cleanup_completed_tasks():
    with app.app_context():
        try:
            # 24 saatten eski tamamlanmış görevleri sil
            old_completed_tasks = Task.query.filter(
                Task.Status == 'completed',
                Task.CompletedAt < datetime.now() - timedelta(hours=24)
            ).all()
            
            for task in old_completed_tasks:
                db.session.delete(task)
            
            db.session.commit()
            print(f"{len(old_completed_tasks)} adet eski tamamlanmış görev silindi.")
        except Exception as e:
            db.session.rollback()
            print(f"Görev temizleme hatası: {str(e)}")

# Zamanlanmış görev temizleme işlemi
def schedule_cleanup():
    while True:
        cleanup_completed_tasks()
        time.sleep(3600)  # Her saat başı kontrol et

# Arka planda çalışacak temizleme thread'ini başlat
cleanup_thread = threading.Thread(target=schedule_cleanup, daemon=True)
cleanup_thread.start()

def check_overdue_tasks():
    try:
        # Geciken görevleri bul
        overdue_tasks = Task.query.filter(
            Task.Status == 'pending',
            Task.DueDate < datetime.now()
        ).all()

        for task in overdue_tasks:
            user = User.query.get(task.UserId)
            if user:
                # Son bildirim gönderilme zamanını kontrol et
                last_notification = Notification.query.filter_by(
                    UserId=user.UserId,
                    NotificationType='overdue_task',
                    TaskId=task.TaskId
                ).order_by(Notification.Schedule.desc()).first()

                # Eğer son 24 saat içinde bildirim gönderilmemişse
                if not last_notification or (datetime.now() - last_notification.Schedule).total_seconds() > 86400:
                    # Bildirimi kaydet
                    notification = Notification(
                        UserId=user.UserId,
                        NotificationType='overdue_task',
                        TaskId=task.TaskId,
                        Schedule=datetime.now()
                    )
                    db.session.add(notification)
                    db.session.commit()
                    print(f"Geciken görev bildirimi kaydedildi: {task.Title}")

    except Exception as e:
        print(f"Geciken görev kontrolü hatası: {str(e)}")

@app.route('/send-reminder/<int:task_id>', methods=['POST'])
@login_required
def send_reminder(task_id):
    task = Task.query.get_or_404(task_id)
    if task.UserId != current_user.UserId:
        return jsonify({'success': False, 'error': 'Bu işlem için yetkiniz yok!'}), 403
    
    try:
        # Bildirimi kaydet
        notification = Notification(
            UserId=current_user.UserId,
            NotificationType='manual_reminder',
            TaskId=task.TaskId,
            Schedule=datetime.now()
        )
        db.session.add(notification)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/update_repeat_count/<int:question_id>', methods=['POST'])
@login_required
def update_repeat_count(question_id):
    question = Question.query.get_or_404(question_id)
    if question.UserId != current_user.UserId:
        return jsonify({'success': False, 'error': 'Bu soruya erişim izniniz yok.'})
    
    try:
        question.RepeatCount += 1
        
        # 3 tekrar tamamlandıysa soruyu tamamlandı olarak işaretle
        if question.RepeatCount >= 3:
            question.IsCompleted = True
            question.CompletedAt = datetime.now()
            
            # Tekrar tarihlerini güncelle
            now = datetime.now()
            question.Repeat1Date = now
            question.Repeat2Date = now + timedelta(days=3)
            question.Repeat3Date = now + timedelta(days=7)
        
        db.session.commit()
        return jsonify({
            'success': True, 
            'repeat_count': question.RepeatCount,
            'is_completed': question.IsCompleted,
            'next_repeat_date': question.Repeat1Date.strftime('%d.%m.%Y') if question.Repeat1Date else None
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/complete_question/<int:question_id>', methods=['POST'])
@login_required
def complete_question(question_id):
    question = Question.query.get_or_404(question_id)
    if question.UserId != current_user.UserId:
        return jsonify({'success': False, 'error': 'Bu soruya erişim izniniz yok.'})
    
    try:
        question.IsCompleted = True
        question.CompletedAt = datetime.now()
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/get_notifications')
@login_required
def get_notifications():
    try:
        notifications = []
        question_notifications = []
        planning_notifications = []
        task_notifications = []
        now = datetime.now()

        # Soru Bildirimleri
        today_questions = Question.query.filter(
            Question.UserId == current_user.UserId,
            Question.Repeat1Date == now.date(),
            Question.IsCompleted == False
        ).count()
        if today_questions > 0:
            notifications.append({
                'icon': '🔔',
                'message': f'Bugün seni bekleyen {today_questions} soru var!',
                'type': 'question',
                'time': 'Şimdi'
            })
        overdue_questions = Question.query.filter(
            Question.UserId == current_user.UserId,
            Question.IsCompleted == False,
            Question.Repeat1Date < now.date()
        ).count()
        if overdue_questions > 0:
            notifications.append({
                'icon': '⏰',
                'message': f'{overdue_questions} sorunun tekrar günü geçmiş.',
                'type': 'question',
                'time': 'Şimdi'
            })
        yesterday_completed = Question.query.filter(
            Question.UserId == current_user.UserId,
            Question.IsCompleted == True,
            Question.CompletedAt >= now.date() - timedelta(days=1)
        ).count()
        if yesterday_completed > 0:
            notifications.append({
                'icon': '🎉',
                'message': f'Aferin! {yesterday_completed} soruyu başarıyla tamamladın.',
                'type': 'question',
                'time': 'Dün'
            })

        # Görev Bildirimleri
        overdue_tasks = Task.query.filter(
            Task.UserId == current_user.UserId,
            Task.Status == 'pending',
            Task.DueDate < now
        ).all()
        for task in overdue_tasks:
            task_notifications.append({
                'icon': '⚠️',
                'message': f'Geciken görev: {task.Title}',
                'type': 'task',
                'time': task.DueDate.strftime('%d.%m.%Y %H:%M')
            })
        completed_tasks = Task.query.filter(
            Task.UserId == current_user.UserId,
            Task.Status == 'completed',
            Task.CompletedAt >= now - timedelta(days=1)
        ).all()
        for task in completed_tasks:
            task_notifications.append({
                'icon': '✅',
                'message': f'Tamamlanan görev: {task.Title}',
                'type': 'task',
                'time': task.CompletedAt.strftime('%d.%m.%Y %H:%M')
            })
        new_tasks = Task.query.filter(
            Task.UserId == current_user.UserId,
            Task.Status == 'pending',
            Task.CreatedAt >= now - timedelta(days=1)
        ).all()
        for task in new_tasks:
            task_notifications.append({
                'icon': '🆕',
                'message': f'Yeni görev: {task.Title}',
                'type': 'task',
                'time': task.CreatedAt.strftime('%d.%m.%Y %H:%M')
            })

        # Motivasyon mesajı
        motivation_messages = [
            "Başarı, küçük adımların toplamıdır!",
            "Her gün bir adım daha ileriye!",
            "Zorlandığında vazgeçme, mola ver ve devam et!",
            "Küçük adımlar büyük başarılar getirir!",
            "Bugün dünden daha iyi ol!",
            "Başarı yolunda ilerliyorsun!",
            "Kendine inan, başarabilirsin!",
            "Her tekrar seni hedefe yaklaştırır!"
        ]
        motivation_message = random.choice(motivation_messages)
        planning_notifications.append({
            'icon': '💡',
            'message': motivation_message,
            'type': 'motivation',
            'time': 'Şimdi'
        })

        return jsonify({
            'success': True,
            'notifications': notifications,
            'question_notifications': question_notifications,
            'planning_notifications': planning_notifications,
            'task_notifications': task_notifications
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

def create_categories():
    categories = [
        {'name': 'Matematik', 'icon': 'math.png'},
        {'name': 'Türk Dili ve Edebiyatı', 'icon': 'literature.png'},
        {'name': 'Felsefe', 'icon': 'philosophy.png'},
        {'name': 'Din', 'icon': 'religion.png'},
        {'name': 'Coğrafya', 'icon': 'geography.png'},
        {'name': 'Fizik', 'icon': 'physics.png'},
        {'name': 'Kimya', 'icon': 'chemistry.png'},
        {'name': 'Biyoloji', 'icon': 'biology.png'},
        {'name': 'Tarih', 'icon': 'history.png'},
        {'name': 'Yabancı Dil', 'icon': 'language.png'}
    ]
    
    for category in categories:
        if not Category.query.filter_by(Name=category['name']).first():
            new_category = Category(Name=category['name'])
            db.session.add(new_category)
    
    try:
        db.session.commit()
        print("Kategoriler başarıyla oluşturuldu.")
    except Exception as e:
        db.session.rollback()
        print(f"Kategori oluşturma hatası: {str(e)}")

@app.route('/today_questions')
@login_required
def today_questions():
    today = datetime.now().date()
    questions = Question.query.filter(
        Question.UserId == current_user.UserId,
        db.text("CAST([Questions].[Repeat1Date] AS DATE) = :today"),
        Question.IsCompleted == False,
        Question.RepeatCount < 3
    ).params(today=today).order_by(Question.Repeat1Date).all()
    
    categories = Category.query.all()
    return render_template('questions.html', questions=questions, categories=categories)

@app.route('/past_questions')
@login_required
def past_questions():
    today = datetime.now().date()
    questions = Question.query.filter(
        Question.UserId == current_user.UserId,
        db.text("CAST([Questions].[Repeat1Date] AS DATE) < :today"),
        Question.IsCompleted == False,
        Question.RepeatCount < 3
    ).params(today=today).order_by(Question.Repeat1Date.desc()).all()
    
    categories = Category.query.all()
    return render_template('questions.html', questions=questions, categories=categories)

@app.route('/reminders')
@login_required
def reminders():
    today = datetime.now().date()
    questions = Question.query.filter(
        Question.UserId == current_user.UserId,
        db.text("CAST([Questions].[Repeat1Date] AS DATE) > :today"),
        Question.IsCompleted == False,
        Question.RepeatCount < 3
    ).params(today=today).order_by(Question.Repeat1Date).all()
    
    categories = Category.query.all()
    return render_template('questions.html', questions=questions, categories=categories)

@app.route('/set_reminder/<int:question_id>', methods=['POST'])
@login_required
def set_reminder(question_id):
    try:
        data = request.get_json()
        frequency = data.get('frequency')
        time_str = data.get('time')
        
        if not frequency or not time_str:
            return jsonify({'success': False, 'error': 'Tüm alanları doldurun.'})
        
        # Saat formatını kontrol et
        try:
            reminder_time = datetime.strptime(time_str, '%H:%M').time()
        except ValueError:
            return jsonify({'success': False, 'error': 'Geçersiz saat formatı.'})
        
        # Mevcut hatırlatıcıyı kontrol et
        existing_reminder = Reminder.query.filter_by(
            UserId=current_user.UserId,
            QuestionId=question_id
        ).first()
        
        if existing_reminder:
            # Mevcut hatırlatıcıyı güncelle
            existing_reminder.Frequency = frequency
            existing_reminder.Time = reminder_time
            existing_reminder.IsActive = True
        else:
            # Yeni hatırlatıcı oluştur
            new_reminder = Reminder(
                UserId=current_user.UserId,
                QuestionId=question_id,
                Frequency=frequency,
                Time=reminder_time
            )
            db.session.add(new_reminder)
        
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

@app.route('/get_reminders')
@login_required
def get_reminders():
    try:
        reminders = Reminder.query.filter_by(
            UserId=current_user.UserId,
            IsActive=True
        ).all()
        
        reminder_list = []
        for reminder in reminders:
            question = Question.query.get(reminder.QuestionId)
            if question and not question.IsCompleted:
                reminder_list.append({
                    'id': reminder.ReminderId,
                    'question_id': reminder.QuestionId,
                    'question_content': question.Content[:100] + '...' if len(question.Content) > 100 else question.Content,
                    'frequency': reminder.Frequency,
                    'time': reminder.Time.strftime('%H:%M'),
                    'category': question.category.Name
                })
        
        return jsonify({'success': True, 'reminders': reminder_list})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/delete_reminder/<int:reminder_id>', methods=['POST'])
@login_required
def delete_reminder(reminder_id):
    try:
        reminder = Reminder.query.get_or_404(reminder_id)
        if reminder.UserId != current_user.UserId:
            return jsonify({'success': False, 'error': 'Bu hatırlatıcıya erişim izniniz yok.'})
        
        db.session.delete(reminder)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})

def check_reminders():
    """Hatırlatıcıları kontrol eden ve bildirim gönderen fonksiyon"""
    with app.app_context():
        try:
            now = datetime.now()
            current_time = now.time()
            
            # Aktif hatırlatıcıları al
            reminders = Reminder.query.filter_by(IsActive=True).all()
            
            for reminder in reminders:
                # Son gönderim zamanını kontrol et
                if reminder.LastSent:
                    time_diff = now - reminder.LastSent
                    
                    # Frekansa göre kontrol
                    if reminder.Frequency == 'daily' and time_diff.days < 1:
                        continue
                    elif reminder.Frequency == 'weekly' and time_diff.days < 7:
                        continue
                    elif reminder.Frequency == 'monthly' and time_diff.days < 30:
                        continue
                
                # Hatırlatma saatini kontrol et
                if reminder.Time.hour == current_time.hour and reminder.Time.minute == current_time.minute:
                    # Bildirim gönder
                    question = Question.query.get(reminder.QuestionId)
                    if question and not question.IsCompleted:
                        notification = Notification(
                            UserId=reminder.UserId,
                            NotificationType='reminder',
                            TaskId=None,
                            Schedule=now
                        )
                        db.session.add(notification)
                        reminder.LastSent = now
                        db.session.commit()
                        
                        print(f"Hatırlatma gönderildi: {question.Content[:50]}...")
        
        except Exception as e:
            print(f"Hatırlatıcı kontrolü hatası: {str(e)}")

# Hatırlatıcı kontrolü için zamanlanmış görev
def schedule_reminder_check():
    while True:
        check_reminders()
        time.sleep(60)  # Her dakika kontrol et

# Arka planda çalışacak hatırlatıcı thread'ini başlat
reminder_thread = threading.Thread(target=schedule_reminder_check, daemon=True)
reminder_thread.start()

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(Email=email).first()
        
        if user:
            # Benzersiz bir token oluştur
            token = secrets.token_urlsafe(32)
            expires_at = datetime.now() + timedelta(hours=24)
            
            # Token'ı veritabanına kaydet
            reset_token = PasswordResetToken(
                UserId=user.UserId,
                Token=token,
                ExpiresAt=expires_at
            )
            db.session.add(reset_token)
            db.session.commit()
            
            # E-posta gönder
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('Şifre Sıfırlama',
                        recipients=[user.Email])
            msg.body = f'''Şifrenizi sıfırlamak için aşağıdaki bağlantıya tıklayın:
{reset_url}

Bu bağlantı 24 saat boyunca geçerlidir.

Eğer bu isteği siz yapmadıysanız, bu e-postayı görmezden gelebilirsiniz.
'''
            mail.send(msg)
            
            flash('Şifre sıfırlama bağlantısı e-posta adresinize gönderildi.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Bu e-posta adresi ile kayıtlı bir kullanıcı bulunamadı.', 'error')
    
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    reset_token = PasswordResetToken.query.filter_by(Token=token, IsUsed=False).first()
    
    if not reset_token or reset_token.ExpiresAt < datetime.now():
        flash('Geçersiz veya süresi dolmuş şifre sıfırlama bağlantısı.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Şifreler eşleşmiyor.', 'error')
            return redirect(url_for('reset_password', token=token))
        
        # Şifreyi güncelle
        user = User.query.get(reset_token.UserId)
        user.PasswordHash = hashlib.sha256(password.encode()).hexdigest()
        
        # Token'ı kullanıldı olarak işaretle
        reset_token.IsUsed = True
        
        db.session.commit()
        flash('Şifreniz başarıyla güncellendi. Şimdi giriş yapabilirsiniz.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html')

@app.route('/report')
@login_required
def report():
    today = datetime.now().date()
    # Tamamlanan görevler
    completed_tasks = Task.query.filter(
        Task.UserId == current_user.UserId,
        Task.Status == 'completed',
        db.text("CAST([Tasks].[CompletedAt] AS DATE) = :today")
    ).params(today=today).all()
    # Geciken görevler
    overdue_tasks = Task.query.filter(
        Task.UserId == current_user.UserId,
        Task.Status == 'pending',
        Task.DueDate < datetime.now()
    ).all()
    # Toplam çalışma süresi (görev türü fark etmeksizin, o günün tüm TaskTime kayıtları)
    total_time = db.session.query(db.func.sum(TaskTime.Duration)).join(Task).filter(
        Task.UserId == current_user.UserId,
        db.text("CAST([TaskTimes].[StartTime] AS DATE) = :today")
    ).params(today=today).scalar() or 0
    # Toplam görev sayısı (bugün tamamlanan + geciken + aktif)
    total_tasks = len(completed_tasks) + len(overdue_tasks)
    completion_rate = int((len(completed_tasks) / total_tasks) * 100) if total_tasks > 0 else 0
    return render_template(
        'report.html',
        report_date=today.strftime('%d.%m.%Y'),
        completed_count=len(completed_tasks),
        overdue_count=len(overdue_tasks),
        total_time=total_time,
        completed_tasks=completed_tasks,
        overdue_tasks=overdue_tasks,
        completion_rate=completion_rate
    )

@app.route('/pomodoro_settings')
@login_required
def pomodoro_settings():
    return render_template('pomodoro_settings.html')

@app.route('/timer')
@login_required
def timer():
    return render_template('timer.html')

@app.route('/hide_question/<int:question_id>', methods=['POST'])
@login_required
def hide_question(question_id):
    question = Question.query.get_or_404(question_id)
    if question.UserId != current_user.UserId:
        return jsonify({'success': False, 'error': 'Bu işlem için yetkiniz yok'}), 403
    
    try:
        question.IsHidden = True
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/progress_report')
@login_required
def progress_report():
    today = datetime.now().date()
    week_ago = today - timedelta(days=7)
    month_ago = today - timedelta(days=30)

    # Haftalık ve aylık tamamlanan soru/görev
    weekly_questions = Question.query.filter(
        Question.UserId == current_user.UserId,
        Question.IsCompleted == True,
        db.text("CAST([Questions].[CompletedAt] AS DATE) >= :week_ago")
    ).params(week_ago=week_ago).all()
    monthly_questions = Question.query.filter(
        Question.UserId == current_user.UserId,
        Question.IsCompleted == True,
        db.text("CAST([Questions].[CompletedAt] AS DATE) >= :month_ago")
    ).params(month_ago=month_ago).all()

    weekly_tasks = Task.query.filter(
        Task.UserId == current_user.UserId,
        Task.Status == 'completed',
        db.text("CAST([Tasks].[CompletedAt] AS DATE) >= :week_ago")
    ).params(week_ago=week_ago).all()
    monthly_tasks = Task.query.filter(
        Task.UserId == current_user.UserId,
        Task.Status == 'completed',
        db.text("CAST([Tasks].[CompletedAt] AS DATE) >= :month_ago")
    ).params(month_ago=month_ago).all()

    # Kategori bazlı dağılım (haftalık)
    categories = Category.query.all()
    category_stats = []
    for category in categories:
        count = Question.query.filter(
            Question.UserId == current_user.UserId,
            Question.IsCompleted == True,
            Question.CategoryId == category.CategoryId,
            db.text("CAST([Questions].[CompletedAt] AS DATE) >= :week_ago")
        ).params(week_ago=week_ago).count()
        category_stats.append({
            'category': category.Name,
            'count': count
        })

    # Başarı oranı (haftalık)
    total_weekly_questions = Question.query.filter(
        Question.UserId == current_user.UserId,
        db.text("CAST([Questions].[Repeat1Date] AS DATE) >= :week_ago")
    ).params(week_ago=week_ago).count()
    completed_weekly_questions = len(weekly_questions)
    success_rate = int((completed_weekly_questions / total_weekly_questions) * 100) if total_weekly_questions > 0 else 0

    # Öneri ve hedef (en az yapılan kategori)
    min_category = min(category_stats, key=lambda x: x['count']) if category_stats else None
    suggestion = None
    if min_category and min_category['count'] < 5:
        suggestion = f"Bu hafta {min_category['category']} kategorisinde daha fazla soru çözmeye çalış!"
    elif min_category:
        suggestion = f"Harika! Tüm kategorilerde iyi gidiyorsun."

    # Haftalık hedef (örnek: 10 soru)
    weekly_goal = 10
    goal_message = f"Bu hafta en az {weekly_goal} soru çöz!"

    return jsonify({
        'weekly_questions': completed_weekly_questions,
        'monthly_questions': len(monthly_questions),
        'weekly_tasks': len(weekly_tasks),
        'monthly_tasks': len(monthly_tasks),
        'success_rate': success_rate,
        'category_stats': category_stats,
        'suggestion': suggestion,
        'goal_message': goal_message
    })

@app.route('/progress')
@login_required
def progress():
    return render_template('progress_report.html')

@app.route('/next_question/<int:current_id>')
@login_required
def next_question(current_id):
    # Kullanıcının tüm sorularını id'ye göre sırala
    questions = Question.query.filter_by(UserId=current_user.UserId, IsHidden=False).order_by(Question.QuestionId).all()
    ids = [q.QuestionId for q in questions]
    if current_id in ids:
        idx = ids.index(current_id)
        if idx + 1 < len(ids):
            return jsonify({'next_id': ids[idx+1]})
    # Sonraki yoksa veya tek soru ise
    return jsonify({'next_id': None})

# Ana sayfa yönlendirmesi
@app.before_request
def redirect_to_welcome():
    if not current_user.is_authenticated and request.endpoint in ['index', None]:
        return redirect(url_for('welcome'))

@app.route('/save_timer', methods=['POST'])
@login_required
def save_timer():
    data = request.get_json()
    seconds = data.get('seconds', 0)
    if not seconds or seconds <= 0:
        return jsonify({'success': False, 'error': 'Geçersiz süre'}), 400
    # TaskTime tablosuna günlük serbest çalışma olarak ekle
    from datetime import datetime
    now = datetime.now()
    # Serbest çalışma için özel bir Task kaydı bul veya oluştur
    free_task = Task.query.filter_by(UserId=current_user.UserId, Title='Serbest Çalışma', Status='completed').filter(Task.CompletedAt >= now.replace(hour=0, minute=0, second=0, microsecond=0)).first()
    if not free_task:
        free_task = Task(
            UserId=current_user.UserId,
            Title='Serbest Çalışma',
            Description='Sayaç ile kaydedilen serbest çalışma',
            Status='completed',
            CompletedAt=now
        )
        db.session.add(free_task)
        db.session.commit()
    # TaskTime kaydı ekle
    time_entry = TaskTime(
        TaskId=free_task.TaskId,
        StartTime=now,
        EndTime=now,
        Duration=int(seconds // 60)
    )
    db.session.add(time_entry)
    db.session.commit()
    return jsonify({'success': True})

# Uygulama başlatıldığında temizleme işlemini yap
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_categories()  # Kategorileri oluştur
    app.run(host='127.0.0.1', port=5000, debug=True)
