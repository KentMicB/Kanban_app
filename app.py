from flask import Flask, render_template, request, redirect, flash, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import secrets
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///kanban.db'
app.config['SECRET_KEY'] = secrets.token_hex(16)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role not in roles:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    due_date = db.Column(db.Date, nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(50), default='Not Started')
    user = db.relationship('User', backref='tasks')  # Corrected

class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    type = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.String(255))
    user = db.relationship('User', backref='history')  # Corrected

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    """Render the home page."""
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handle user signup with role selection."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', '').strip()
        
        if not username or not password or not role:
            flash('Please fill out all fields.', 'danger')
            return redirect(url_for('signup'))

        if role not in ['leader', 'member']:
            flash('Invalid role. Please choose "leader" or "member".', 'danger')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        try:
            db.session.commit()
            flash('Account created successfully!', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Username already taken.', 'danger')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Authenticate user and log them in."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('Please enter both username and password.', 'danger')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your username and password.', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Render the dashboard with member list, tasks and history."""
    members = User.query.all()
    if current_user.role == 'leader':
        tasks = Task.query.all()
    else:
        tasks = Task.query.filter_by(assigned_to=current_user.id).all()
    history = History.query.order_by(History.timestamp.desc()).all()
    return render_template('dashboard.html', members=members, tasks=tasks, history=history)

@app.route('/assign_task', methods=['GET'])
@login_required
@roles_required('leader')
def assign_task_page():
    members = User.query.all()
    tasks = Task.query.all()
    return render_template('assign_task.html', members=members, tasks=tasks)
 
@app.route('/assign_task', methods=['POST'])
@login_required
@roles_required('leader')
def assign_task():
       """Assign a task to a member."""
       task_id = request.form.get('task_id')
       member_id = request.form.get('member_id')

       if not task_id or not member_id:
           flash('Task ID and Member ID are required.', 'danger')
           return redirect(url_for('dashboard'))

       task = Task.query.get(task_id)
       if not task:
           flash('Task not found.', 'danger')
           return redirect(url_for('dashboard'))

       member = User.query.get(member_id)
       if not member:
           flash('Member not found.', 'danger')
           return redirect(url_for('dashboard'))


       task.assigned_to = member.id
       db.session.commit()

       new_history = History(user_id=current_user.id, type="Task Assigned",
                             details=f"Assigned task '{task.title}' to {member.username}")
       db.session.add(new_history)
       db.session.commit()

       flash(f'Task "{task.title}" assigned to {member.username} successfully!', 'success')
       return redirect(url_for('dashboard'))

from datetime import datetime

@app.route('/create_task', methods=['POST'])
@login_required
@roles_required('leader')
def create_task():
    title = request.form['title'].strip()
    due_date_str = request.form['due_date']

    if not title or not due_date_str:
        flash('Both task title and due date are required.', 'danger')
        return redirect(url_for('assign_task_page'))

    try:
        due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
    except ValueError:
        flash('Invalid date format.', 'danger')
        return redirect(url_for('assign_task_page'))

    new_task = Task(title=title, due_date=due_date)
    db.session.add(new_task)
    db.session.commit()

    flash(f'Task "{title}" created with due date {due_date}.', 'success')
    return redirect(url_for('assign_task_page'))

@app.route('/your_task')
@login_required
def your_task():
    """Leaders see all tasks with usernames; members see only their tasks."""
    if current_user.role == 'leader':
        tasks = Task.query.all()
    else:
        tasks = Task.query.filter_by(assigned_to=current_user.id).all()
    return render_template('your_task.html', tasks=tasks)

@app.route('/update_status', methods=['POST'])
@login_required
def update_status():
    task_id = request.form.get('task_id')
    new_status = request.form.get('status')
    task = Task.query.get(task_id)

    if not task:
        flash('Task not found.', 'danger')
        return redirect(url_for('your_task'))

    old_status = task.status
    task.status = new_status
    db.session.commit()

    new_history = History(
        user_id=current_user.id,
        type="Task Status Updated",
        details=f"{current_user.username} changed status of '{task.title}' from '{old_status}' to '{new_status}'"
    )
    db.session.add(new_history)
    db.session.commit()

    flash('Task status updated.', 'success')
    return redirect(url_for('your_task'))

@app.route('/task_history')
@login_required
def task_history():
    """Display task history; all for leaders, user-specific for others."""
    if current_user.role == 'leader':
        history_entries = History.query.join(User).order_by(History.timestamp.desc()).all()
    else:
        history_entries = History.query.filter_by(user_id=current_user.id).join(User).order_by(History.timestamp.desc()).all()

    history = []
    for entry in history_entries:
        history.append({
            'type': entry.type,
            'details': entry.details,
            'timestamp': entry.timestamp,
            'username': entry.user.username  # relationship works here
        })

    return render_template('task_history.html', history=history)

@app.route('/update_task_status/<int:task_id>', methods=['POST'])
@login_required
def update_task_status(task_id):
    """Allow authorized user to update task status."""
    task = Task.query.get_or_404(task_id)
    
    if task.assigned_to != current_user.id and current_user.role != 'leader':
        flash('You are not authorized to update the status of this task.', 'danger')
        return redirect(url_for('dashboard'))

    new_status = request.form.get('status', '').strip()
    if not new_status:
        flash('Invalid status.', 'danger')
        return redirect(url_for('dashboard'))

    task.status = new_status
    db.session.commit()

    new_history = History(
        user_id=current_user.id,
        type="Task Status Updated",
        details=f"{current_user.username} updated task '{task.title}' status to '{new_status}'"
    )
    db.session.add(new_history)
    db.session.commit()

    flash('Task status updated successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/change_task_assignee/<int:task_id>', methods=['POST'])
@roles_required('leader')
def change_task_assignee(task_id):
    """Allow leaders to change the assignee of a task."""
    task = Task.query.get_or_404(task_id)
    new_assignee_id = request.form.get('assigned_to')
    if not new_assignee_id:
        flash('No assignee selected.', 'danger')
        return redirect(url_for('dashboard'))

    new_assignee = User.query.get(new_assignee_id)
    if not new_assignee:
        flash('Assignee user not found.', 'danger')
        return redirect(url_for('dashboard'))

    task.assigned_to = new_assignee.id
    db.session.commit()

    new_history = History(user_id=current_user.id, type="Task Reassigned",
                          details=f"Reassigned task '{task.title}' to {new_assignee.username}")
    db.session.add(new_history)
    db.session.commit()

    flash(f'Task reassigned to {new_assignee.username} successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    """Log out the current user."""
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        print(User)  # Check if User class is defined
        print(Task)  # Check if Task class is defined
        print(History)  # Check if History class is defined
        db.create_all() 
    app.run(debug=True)
