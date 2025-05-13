class Question(db.Model):
    __tablename__ = 'Questions'
    
    QuestionId = db.Column(db.Integer, primary_key=True)
    UserId = db.Column(db.Integer, db.ForeignKey('Users.UserId'), nullable=False)
    Title = db.Column(db.String(200), nullable=False)
    Content = db.Column(db.Text, nullable=False)
    Category = db.Column(db.String(50))
    Difficulty = db.Column(db.String(20))
    Status = db.Column(db.String(20), default='pending')
    CreatedAt = db.Column(db.DateTime, default=datetime.utcnow)
    UpdatedAt = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsHidden = db.Column(db.Boolean, default=False)
    
    # İlişkiler
    user = db.relationship('User', backref=db.backref('questions', lazy=True))
    favorites = db.relationship('Favorite', backref='question', lazy=True)
    reminders = db.relationship('Reminder', backref='question', lazy=True)
    question_times = db.relationship('QuestionTime', backref='question', lazy=True)
    
    def __repr__(self):
        return f'<Question {self.Title}>' 