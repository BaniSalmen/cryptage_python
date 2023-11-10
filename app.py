import re
from flask import Flask, render_template, request, redirect, url_for, flash, session
from passlib.hash import sha256_crypt
from flask_mysqldb import MySQL
import MySQLdb.cursors
from datetime import datetime


from cryptography.fernet import Fernet

app = Flask(__name__)

app.secret_key = 'xyz'

#La longueur de la clé générée par Fernet est de 32 octets (256 bits)
key = Fernet.generate_key()



app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'app_reclamation'

mysql = MySQL(app)

reclamations = []
encrypted_message = ""

@app.route('/', methods=['GET', 'POST'])
def login():
    message = ''
    if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
        email = request.form['email']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user WHERE email = %s', (email,))
        user = cursor.fetchone()
        if user and sha256_crypt.verify(password, user['password']):
            # Mot de passe correct, vous pouvez créer la session de l'utilisateur
            session['loggedin'] = True
            session['id'] = user['id']
            session['firstname'] = user['firstname']
            session['email'] = user['email']
            session['role'] = user['role']
            message = 'Logged in successfully!'
            if user['role'].lower() == 'admin':
                return redirect(url_for('admin'))
            elif user['role'].lower() == 'manager':
                return redirect(url_for('manager'))
            else:
                return redirect(url_for('employee'))
        else:
            message = 'Please enter correct email / password!'
    return render_template('login.html', message=message)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    message = ''
    if request.method == 'POST' and 'firstname' in request.form and 'password' in request.form and 'email' in request.form:
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        number_phone = request.form['number_phone']
        post = request.form['post']
        grade = request.form['grade']
        password = request.form['password']
        hashed_password = sha256_crypt.hash(password)
        email = request.form['email']
        role = request.form['role']  # Récupérez le rôle depuis le formulaire
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM user WHERE email = %s', (email,))
        account = cursor.fetchone()
        if account:
            message = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            message = 'Invalid email address!'
        elif not firstname or not password or not email:
            message = 'Please fill out the form!'
        else:
            cursor.execute(
                'INSERT INTO user (firstname, lastname, number_phone, post, grade, email, role, password) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)',
                (firstname, lastname, number_phone, post, grade, email,role, hashed_password))
            mysql.connection.commit()
        message = 'You have successfully registered!'
    elif request.method == 'POST':
        message = 'Please fill out the form!'
    return render_template('register.html', message=message)




@app.route('/employee')
def employee():
    if 'loggedin' in session and session['role'].lower() == 'employee':
        return render_template('employee.html')
    return redirect(url_for('login'))




@app.route('/manager')
def manager():
    if 'loggedin' in session and session['role'].lower() == 'manager':
         # Récupérez les réclamations depuis la base de données
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT nom, encrypted_message FROM reclamations")
        reclamations_data = cursor.fetchall()
        cursor.close()
        return render_template('manager_complaints.html', reclamations=reclamations_data)
    return redirect(url_for('login'))


@app.route('/add_reclamation', methods=['GET', 'POST'])
def reclamation():
    if request.method == 'POST':
        nom = request.form['nom']
        message = request.form['message']

        fernet = Fernet(key)
        encrypted_message = fernet.encrypt(message.encode())

        # Ajout de la réclamation à la base de données avec la date de création
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO reclamations (nom, encrypted_message, date_creation) VALUES (%s, %s, %s)",
                       (nom, encrypted_message, datetime.now()))
        mysql.connection.commit()

        # Ajoutez la réclamation à la liste (facultatif)
        reclamations.append({'nom': nom, 'encrypted_message': encrypted_message})

    return render_template('reclamation.html')


@app.route('/admin')
def admin():
    if 'loggedin' in session and session['role'].lower() == 'admin':
        # Récupérez les réclamations depuis la base de données
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT id, nom, encrypted_message FROM reclamations")
        reclamations_data = cursor.fetchall()
        cursor.close()

        # Liste pour stocker les réclamations déchiffrées
        decrypted_reclamations = []

        # Déchiffrez les messages avec la commande OpenSSL
        for reclamation in reclamations_data:
            ciphertext = reclamation['encrypted_message']
            fernet = Fernet(key)

            try:
                decrypted_message = fernet.decrypt(ciphertext).decode()
            except Exception as e:
                print("Decryption Error:", str(e))
                decrypted_message = "Erreur de déchiffrement"

            decrypted_reclamations.append({'id': reclamation['id'], 'nom': reclamation['nom'], 'message': decrypted_message})

        return render_template('admin_complaints.html', reclamations=decrypted_reclamations)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)