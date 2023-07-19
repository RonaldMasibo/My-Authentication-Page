from flask import Flask, render_template, request, flash, redirect, url_for, session, logging
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)
app.debug = True

#config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Ronnie254'
app.config['MYSQL_DB'] = 'MyAuth'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

#configure MySQL
mysql = MySQL(app)


@app.route('/')
def home():
    return render_template ('home.html')


#Register Form Class
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=3, max=100)])
    email = StringField('Email', [validators.Length(min=6, max=100)])
    username = StringField('Username', [validators.Length(min=4, max=100)])
    password = PasswordField('Password', [validators.DataRequired(),validators.EqualTo('confirm', message='The Passwords are not MATCHING!!')])
    confirm = PasswordField('Confirm Password')

#User register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        #creating cursor
        cur = mysql.connection.cursor()

        #Execute query
        cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)", (name, email, username, password))

        #commit to db
        mysql.connection.commit()

        #close connection
        cur.close()

        flash('You Are Now a Registered User & can now Log in', 'success')

        return redirect(url_for('login'))
    return render_template('register.html', form=form)



#User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        #Get form fields
        username = request.form['username']
        password_candidate = request.form['password']

        #Create cursor
        cur = mysql.connection.cursor()

        #Get user by username
        result = cur.execute("SELECT * FROM users WHERE username=%s", [username])
        if result > 0:
            #Get stored hash
            data = cur.fetchone()
            password = data['password']

            #compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                #Passed
                session['logged_in']=True
                session['username']=username

                flash('You are Now Logged in', 'Success')
                return redirect(url_for('view'))
            else:
                error = 'Invalid'
                return render_template('login.html', error=error)
            
            #Closing Connection
            cur.close()

        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')


#Check if User is logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please Login', 'danger')
            return redirect(url_for('login'))
    return wrap

#LogOut
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


#View
@app.route('/view')
@is_logged_in
def view():
    #Create Cursor
    cur = mysql.connection.cursor()

    return render_template ('view.html')
    
    #Close Connection
    cur.close()

if __name__ == '__main__':
    app.secret_key = 'secret123'
    app.run()