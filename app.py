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
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mssql+pyodbc://(local)\\SQLK/ReviseMe?trusted_connection=yes&driver=ODBC+Driver+17+for+SQL+Server'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# E-posta ayarları
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'  # Gmail adresiniz
app.config['MAIL_PASSWORD'] = 'your-app-password'     # Gmail uygulama şifreniz
app.config['MAIL_DEFAULT_SENDER'] = 'your-email@gmail.com'

# SQLAlchemy bağlantısını oluştur
engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
Session = sessionmaker(bind=engine)
session = Session()

db = SQLAlchemy(app)
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

class Question(db.Model):
    __tablename__ = 'Questions'
    QuestionId = db.Column(db.Integer, primary_key=True)
    UserId = db.Column(db.Integer, db.ForeignKey('Users.UserId'))
    Content = db.Column(db.Text)
    CategoryId = db.Column(db.Integer, db.ForeignKey('Categories.CategoryId'))
    DifficultyLevel = db.Column(db.String(20))
    PhotoPath = db.Column(db.String(255))
    IsRepeated = db.Column(db.Boolean, default=False)
    RepeatCount = db.Column(db.Integer, default=0)
    Repeat1Date = db.Column(db.DateTime)
    Repeat2Date = db.Column(db.DateTime)
    Repeat3Date = db.Column(db.DateTime)
    IsCompleted = db.Column(db.Boolean, default=False)
    IsViewed = db.Column(db.Boolean, default=False)
    
    Category = db.relationship("Category", back_populates="Questions")

class Category(db.Model):
    __tablename__ = 'Categories'
    CategoryId = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(50))
    
    Questions = db.relationship("Question", back_populates="Category")

class Note(db.Model):
    __tablename__ = 'Notes'
    NoteId = db.Column(db.Integer, primary_key=True)
    QuestionId = db.Column(db.Integer, db.ForeignKey('Questions.QuestionId'))
    Content = db.Column(db.Text)

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
    Schedule = db.Column(db.DateTime)

class PasswordResetToken(db.Model):
    __tablename__ = 'PasswordResetTokens'
    TokenId = db.Column(db.Integer, primary_key=True)
    UserId = db.Column(db.Integer, db.ForeignKey('Users.UserId'), nullable=False)
    Token = db.Column(db.String(100), unique=True, nullable=False)
    ExpiresAt = db.Column(db.DateTime, nullable=False)
    IsUsed = db.Column(db.Boolean, default=False)
    
    user = db.relationship('User', backref='password_reset_tokens')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
@login_required
def index():
    categories = Category.query.all()
    return render_template('index.html', categories=categories)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        name = request.form.get('name')
        surname = request.form.get('surname')
        class_ = request.form.get('class')
        year_of_birth = request.form.get('year_of_birth')
        area = request.form.get('area')
        aim = request.form.get('aim')
        email = request.form.get('email')
        phone = request.form.get('phone')
        security_question = request.form.get('security_question')

        # Kullanıcı adı kontrolü
        if User.query.filter_by(UserName=username).first():
            flash('Bu kullanıcı adı zaten kullanılıyor.')
            return redirect(url_for('register'))

        # E-posta kontrolü
        if User.query.filter_by(Email=email).first():
            flash('Bu e-posta adresi zaten kullanılıyor.')
            return redirect(url_for('register'))

        # Şifreyi hashle
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        # Yeni kullanıcı oluştur
        new_user = User(
            UserName=username,
            PasswordHash=password_hash,
            Name=name,
            Surname=surname,
            Class=class_,
            YearOfBirth=year_of_birth,
            Area=area,
            Aim=aim,
            Email=email,
            PhoneNumber=phone,
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

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Şifre değişikliği kontrolü
        if current_password or new_password or confirm_password:
            if not current_password or not new_password or not confirm_password:
                flash('Şifre değiştirmek için tüm alanları doldurmalısınız.')
                return redirect(url_for('profile'))
            
            if new_password != confirm_password:
                flash('Yeni şifreler eşleşmiyor.')
                return redirect(url_for('profile'))
            
            if hashlib.sha256(current_password.encode()).hexdigest() != current_user.PasswordHash:
                flash('Mevcut şifre yanlış.')
                return redirect(url_for('profile'))
            
            current_user.PasswordHash = hashlib.sha256(new_password.encode()).hexdigest()

        # Diğer bilgileri güncelle
        current_user.Name = request.form.get('name')
        current_user.Surname = request.form.get('surname')
        current_user.Class = request.form.get('class')
        current_user.YearOfBirth = request.form.get('year_of_birth')
        current_user.Area = request.form.get('area')
        current_user.Aim = request.form.get('aim')
        current_user.Email = request.form.get('email')
        current_user.PhoneNumber = request.form.get('phone')

        try:
            db.session.commit()
            flash('Profil bilgileriniz başarıyla güncellendi.')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash('Profil güncellenirken bir hata oluştu. Lütfen tekrar deneyin.')
            return redirect(url_for('profile'))

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
            category_id = request.form.get('category_id')
            difficulty = request.form.get('difficulty')
            question_image = request.files.get('question_image')
            
            if not content or not category_id or not difficulty:
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
            
            # Tekrar tarihlerini hesapla
            now = datetime.now()
            repeat1_date = now  # Şu anki zaman
            repeat2_date = now + timedelta(days=10)    # 10 gün sonra
            repeat3_date = now + timedelta(days=15)    # 15 gün sonra
            
            # Soruyu ekle
            new_question = Question(
                UserId=current_user.UserId,
                Content=content,
                CategoryId=category_id,
                DifficultyLevel=difficulty,
                PhotoPath=image_path,
                IsCompleted=False,
                Repeat1Date=repeat1_date,
                Repeat2Date=repeat2_date,
                Repeat3Date=repeat3_date
            )
            
            db.session.add(new_question)
            db.session.commit()
            
            # Bildirimleri ekle
            for schedule in [repeat1_date, repeat2_date, repeat3_date]:
                notification = Notification(
                    UserId=current_user.UserId,
                    NotificationType="Tekrar",
                    Schedule=schedule
                )
                db.session.add(notification)
            
            db.session.commit()
            flash('Soru başarıyla eklendi.', 'success')
            return redirect(url_for('add_question'))
            
        except Exception as e:
            db.session.rollback()
            flash('Soru eklenirken bir hata oluştu: ' + str(e), 'error')
            return redirect(url_for('add_question'))
    
    categories = Category.query.all()
    return render_template('add_question.html', categories=categories)

@app.route('/edit_question/<int:question_id>', methods=['GET', 'POST'])
@login_required
def edit_question(question_id):
    question = Question.query.get_or_404(question_id)
    if question.UserId != current_user.UserId:
        flash('Bu soruyu düzenleme yetkiniz yok.')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        question.Content = request.form.get('content')
        question.CategoryId = request.form.get('category_id')
        question.DifficultyLevel = request.form.get('difficulty')
        
        try:
            db.session.commit()
            flash('Soru başarıyla güncellendi.')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash('Soru güncellenirken bir hata oluştu.')
            return redirect(url_for('edit_question', question_id=question_id))
    
    categories = Category.query.all()
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
    question.notes = notes
    
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

        note = Note(Content=data['content'], QuestionId=question_id)
        db.session.add(note)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

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
        
        return jsonify({
            'success': True,
            'message': 'Soru başarıyla silindi'
        })
    except Exception as e:
        db.session.rollback()
        print(f"Soru silme hatası: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Soru silinirken bir hata oluştu.'
        }), 500

@app.route('/mark_completed/<int:question_id>', methods=['POST'])
@login_required
def mark_completed(question_id):
    try:
        question = Question.query.get_or_404(question_id)
        if question.UserId != current_user.UserId:
            return jsonify({'success': False, 'error': 'Bu işlem için yetkiniz yok.'}), 403

        question.IsCompleted = True
        question.RepeatCount += 1
        question.Repeat1Date = datetime.utcnow() + timedelta(days=7)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Soru başarıyla tamamlandı olarak işaretlendi.'
        })
    except Exception as e:
        db.session.rollback()
        print(f"Soru tamamlama hatası: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Soru durumu güncellenirken bir hata oluştu.'
        }), 500

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/questions')
@login_required
def questions():
    categories = Category.query.all()
    questions = Question.query.filter_by(UserId=current_user.UserId).all()
    return render_template('questions.html', categories=categories, questions=questions)

@app.route('/category/<int:category_id>')
@login_required
def category_questions(category_id):
    category = Category.query.get_or_404(category_id)
    questions = Question.query.filter_by(
        UserId=current_user.UserId,
        CategoryId=category_id
    ).all()
    
    # Debug için soruları ve görsel yollarını yazdır
    for question in questions:
        print(f"Soru ID: {question.QuestionId}, Görsel Yolu: {question.PhotoPath}")
    
    return render_template('category_questions.html', category=category, questions=questions)

@app.route('/favorites')
@login_required
def favorites():
    try:
        # Kullanıcının favori sorularını getir
        favorite_questions = Question.query.join(
            Favorite,
            Question.QuestionId == Favorite.QuestionId
        ).filter(
            Favorite.UserId == current_user.UserId
        ).all()

        # Her soru için favori durumunu kontrol et
        for question in favorite_questions:
            question.is_favorite = True

        return render_template('favorites.html', questions=favorite_questions)
    except Exception as e:
        print(f"Favoriler sayfası hatası: {str(e)}")
        flash('Favoriler yüklenirken bir hata oluştu.', 'error')
        return redirect(url_for('index'))

@app.route('/toggle_favorite/<int:question_id>', methods=['POST'])
@login_required
def toggle_favorite(question_id):
    try:
        # Soruyu kontrol et
        question = Question.query.get_or_404(question_id)
        if not question:
            return jsonify({'success': False, 'error': 'Soru bulunamadı.'}), 404

        # Kullanıcı yetkisini kontrol et
        if question.UserId != current_user.UserId:
            return jsonify({'success': False, 'error': 'Bu işlem için yetkiniz yok.'}), 403

        # Favori durumunu kontrol et
        favorite = Favorite.query.filter_by(
            QuestionId=question_id,
            UserId=current_user.UserId
        ).first()

        if favorite:
            # Favoriden çıkar
            db.session.delete(favorite)
            message = 'Favorilerden çıkarıldı'
            is_favorite = False
        else:
            # Favorilere ekle
            new_favorite = Favorite(
                QuestionId=question_id,
                UserId=current_user.UserId
            )
            db.session.add(new_favorite)
            message = 'Favorilere eklendi'
            is_favorite = True

        db.session.commit()
        return jsonify({
            'success': True,
            'message': message,
            'is_favorite': is_favorite
        })

    except Exception as e:
        db.session.rollback()
        print(f"Favori işlemi hatası: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Favori durumu güncellenirken bir hata oluştu.'
        }), 500

@app.route('/notifications')
@login_required
def notifications():
    # Bugünün tarihini al
    today = datetime.now().date()
    
    # Bugün tekrar edilecek soruları bul
    today_questions = Question.query.filter(
        Question.UserId == current_user.UserId,
        Question.Repeat1Date == today,
        Question.IsCompleted == False
    ).all()
    
    # Geçmiş soruları bul
    past_questions = Question.query.filter(
        Question.UserId == current_user.UserId,
        Question.Repeat1Date < today,
        Question.IsCompleted == False
    ).all()
    
    # Bugün tamamlanan soruları bul
    completed_today = Question.query.filter(
        Question.UserId == current_user.UserId,
        Question.IsCompleted == True,
        Question.Repeat1Date == today
    ).all()
    
    return render_template('notifications.html',
                         today_questions=today_questions,
                         past_questions=past_questions,
                         completed_today=completed_today)

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

@app.route('/reminders')
@login_required
def reminders():
    # Geçmiş tekrar tarihi olan soruları getir
    reminders_query = text("""
        SELECT 
            q.QuestionId,
            q.Content,
            q.DifficultyLevel,
            q.PhotoPath,
            q.Repeat1Date,
            q.Repeat2Date,
            q.Repeat3Date,
            c.Name as CategoryName
        FROM Questions q
        JOIN Categories c ON q.CategoryId = c.CategoryId
        WHERE q.UserId = :user_id
        AND (
            q.Repeat1Date < GETDATE() OR
            q.Repeat2Date < GETDATE() OR
            q.Repeat3Date < GETDATE()
        )
        ORDER BY 
            CASE 
                WHEN q.Repeat1Date < GETDATE() THEN q.Repeat1Date
                WHEN q.Repeat2Date < GETDATE() THEN q.Repeat2Date
                ELSE q.Repeat3Date
            END DESC
    """)
    
    reminders = session.execute(
        reminders_query,
        {"user_id": current_user.UserId}
    ).fetchall()
    
    return render_template('reminders.html', reminders=reminders, now=datetime.now())

@app.route('/daily-questions')
@login_required
def daily_questions():
    today = datetime.now().date()
    questions = Question.query.filter(
        Question.UserId == current_user.UserId,
        db.func.date(Question.Repeat1Date) == today,  # Tarih karşılaştırmasını düzelttim
        Question.IsCompleted == False
    ).order_by(Question.Repeat1Date.asc()).all()
    
    return render_template('daily_questions.html', questions=questions)

@app.route('/past-questions')
@login_required
def past_questions():
    today = datetime.now().date()
    questions = Question.query.filter(
        Question.UserId == current_user.UserId,
        Question.Repeat1Date < today,  # Bugünden önceki sorular
        Question.IsCompleted == False
    ).order_by(Question.Repeat1Date.desc()).all()  # En eski sorular önce
    
    # Her soru için favori durumunu kontrol et
    for question in questions:
        question.is_favorite = Favorite.query.filter_by(
            QuestionId=question.QuestionId,
            UserId=current_user.UserId
        ).first() is not None
    
    return render_template('past_questions.html', questions=questions)

@app.route('/skip_question/<int:question_id>', methods=['POST'])
@login_required
def skip_question(question_id):
    try:
        question = Question.query.get_or_404(question_id)
        if question.UserId != current_user.UserId:
            return jsonify({'success': False, 'error': 'Bu işlem için yetkiniz yok.'}), 403

        # Soruyu bir sonraki güne atla
        question.Repeat1Date = datetime.utcnow() + timedelta(days=1)
        db.session.commit()

        # Bir sonraki soruyu bul
        next_question = Question.query.filter(
            Question.UserId == current_user.UserId,
            Question.Repeat1Date < question.Repeat1Date,
            Question.IsCompleted == False
        ).order_by(Question.Repeat1Date.desc()).first()

        return jsonify({
            'success': True,
            'message': 'Soru başarıyla atlandı',
            'next_question_id': next_question.QuestionId if next_question else None
        })

    except Exception as e:
        db.session.rollback()
        print(f"Soru atlama hatası: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Soru atlanırken bir hata oluştu.'
        }), 500

@app.route('/question_detail/<int:question_id>')
@login_required
def question_detail(question_id):
    question = Question.query.get_or_404(question_id)
    if question.UserId != current_user.UserId:
        flash('Bu soruyu görüntüleme yetkiniz yok.', 'error')
        return redirect(url_for('index'))
    
    # Kaynak sayfayı al
    source = request.args.get('source', 'revise')
    
    # Notları getir
    notes = Note.query.filter_by(QuestionId=question_id).order_by(Note.NoteId.desc()).all()
    question.notes = notes
    
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
    
    return render_template('question_detail.html', 
                         question=question, 
                         is_favorite=is_favorite,
                         repeat_status=repeat_status,
                         source=source)

def create_categories():
    categories = [
        {'name': 'Matematik', 'icon': 'math.png'},
        {'name': 'Fizik', 'icon': 'physics.png'},
        {'name': 'Kimya', 'icon': 'chemistry.png'},
        {'name': 'Biyoloji', 'icon': 'biology.png'},
        {'name': 'Tarih', 'icon': 'history.png'},
        {'name': 'Coğrafya', 'icon': 'geography.png'},
        {'name': 'Din', 'icon': 'religion.png'},
        {'name': 'Felsefe', 'icon': 'philosophy.png'}
    ]
    
    for category in categories:
        if not Category.query.filter_by(Name=category['name']).first():
            new_category = Category(Name=category['name'])
            db.session.add(new_category)
    
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()

# Geçici token depolama
reset_tokens = {}

def send_reset_email(user_email, reset_link):
    try:
        # SMTP sunucusuna bağlan
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.ehlo()  # Sunucu ile el sıkışma
        server.starttls()  # TLS şifreleme başlat
        server.ehlo()  # TLS sonrası tekrar el sıkışma
        
        # Gmail için özel ayarlar
        if app.config['MAIL_SERVER'] == 'smtp.gmail.com':
            server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        
        # E-posta içeriğini oluştur
        msg = MIMEMultipart()
        msg['From'] = app.config['MAIL_USERNAME']
        msg['To'] = user_email
        msg['Subject'] = 'ReviseMe - Şifre Sıfırlama'

        body = f"""
        Merhaba,

        Şifrenizi sıfırlamak için aşağıdaki bağlantıya tıklayın:
        {reset_link}

        Bu bağlantı 1 saat süreyle geçerlidir.

        Eğer bu işlemi siz talep etmediyseniz, bu e-postayı dikkate almayın.

        Saygılarımızla,
        ReviseMe Ekibi
        """

        msg.attach(MIMEText(body, 'plain', 'utf-8'))

        # E-postayı gönder
        server.send_message(msg)
        server.quit()
        return True
    except smtplib.SMTPAuthenticationError:
        print("SMTP kimlik doğrulama hatası: Kullanıcı adı veya şifre yanlış")
        return False
    except smtplib.SMTPConnectError:
        print("SMTP bağlantı hatası: Sunucuya bağlanılamıyor")
        return False
    except smtplib.SMTPException as e:
        print(f"SMTP hatası: {str(e)}")
        return False
    except Exception as e:
        print(f"Beklenmeyen hata: {str(e)}")
        return False

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(Email=email).first()
        
        if user:
            # Eski tokenları temizle
            for token, data in list(reset_tokens.items()):
                if data['user_id'] == user.UserId:
                    del reset_tokens[token]
            
            # Yeni token oluştur
            token = secrets.token_urlsafe(32)
            expires_at = datetime.utcnow() + timedelta(hours=1)
            
            reset_tokens[token] = {
                'user_id': user.UserId,
                'expires_at': expires_at,
                'is_used': False
            }
            
            # Sıfırlama bağlantısını oluştur
            reset_link = url_for('reset_password', token=token, _external=True)
            
            # E-posta gönder
            if send_reset_email(user.Email, reset_link):
                flash('Şifre sıfırlama bağlantısı e-posta adresinize gönderildi.', 'success')
            else:
                flash('E-posta gönderilirken bir hata oluştu. Lütfen tekrar deneyin.', 'error')
        else:
            flash('Bu e-posta adresi ile kayıtlı bir kullanıcı bulunamadı.', 'error')
        
        return redirect(url_for('forgot_password'))
    
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    token_data = reset_tokens.get(token)
    
    if not token_data:
        flash('Geçersiz veya süresi dolmuş şifre sıfırlama bağlantısı.', 'error')
        return redirect(url_for('login'))
    
    if token_data['is_used']:
        flash('Bu şifre sıfırlama bağlantısı daha önce kullanılmış.', 'error')
        return redirect(url_for('login'))
    
    if token_data['expires_at'] < datetime.utcnow():
        flash('Şifre sıfırlama bağlantısının süresi dolmuş.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Şifreler eşleşmiyor.', 'error')
            return redirect(url_for('reset_password', token=token))
        
        # Şifreyi güncelle
        user = User.query.get(token_data['user_id'])
        user.PasswordHash = hashlib.sha256(password.encode()).hexdigest()
        
        # Token'ı kullanıldı olarak işaretle
        token_data['is_used'] = True
        
        db.session.commit()
        
        flash('Şifreniz başarıyla güncellendi. Yeni şifrenizle giriş yapabilirsiniz.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

def remove_english_category():
    try:
        # İngilizce kategorisini bul
        english_category = Category.query.filter_by(Name='Yabancı Dil').first()
        
        if english_category:
            # İngilizce kategorisine ait tüm soruları sil
            Question.query.filter_by(CategoryId=english_category.CategoryId).delete()
            
            # İngilizce kategorisini sil
            db.session.delete(english_category)
            
            # Değişiklikleri kaydet
            db.session.commit()
            print("İngilizce kategorisi ve ilgili sorular başarıyla silindi.")
        else:
            print("İngilizce kategorisi bulunamadı.")
    except Exception as e:
        db.session.rollback()
        print(f"Hata oluştu: {str(e)}")

def remove_literature_category():
    try:
        # Edebiyat kategorisini bul
        literature_category = Category.query.filter_by(Name='Edebiyat').first()
        
        if literature_category:
            # Edebiyat kategorisine ait tüm soruları sil
            Question.query.filter_by(CategoryId=literature_category.CategoryId).delete()
            
            # Edebiyat kategorisini sil
            db.session.delete(literature_category)
            
            # Değişiklikleri kaydet
            db.session.commit()
            print("Edebiyat kategorisi ve ilgili sorular başarıyla silindi.")
        else:
            print("Edebiyat kategorisi bulunamadı.")
    except Exception as e:
        db.session.rollback()
        print(f"Hata oluştu: {str(e)}")

# Uygulama başlatıldığında temizleme işlemini yap
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        remove_english_category()  # İngilizce kategorisini temizle
        remove_literature_category()  # Edebiyat kategorisini temizle
    app.run(host='127.0.0.1', port=5000, debug=True)
