import re
import subprocess
from flask import Flask, render_template, request, redirect, url_for, flash, session
from passlib.hash import sha256_crypt
from flask_mysqldb import MySQL
import MySQLdb.cursors
import os 

app = Flask(__name__)

app.secret_key = 'xyz'

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




@app.route('/admin')
def admin():
    if 'loggedin' in session and session['role'].lower() == 'admin':
        # Récupérez les réclamations depuis la base de données
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT nom, message FROM reclamations")
        reclamations_data = cursor.fetchall()
        cursor.close()

        return render_template('admin_complaints.html',  reclamations=reclamations_data)
    return redirect(url_for('login'))





@app.route('/add_reclamation', methods=['GET', 'POST'])
def reclamation():
    encrypted_message = ""
    if request.method == 'POST':
        nom = request.form['nom']
        message = request.form['message']
        


    # Générez une clé aléatoire de 32 octets (256 bits)
        encryption_key = os.urandom(32)
# Convertissez la clé en une forme que vous pouvez utiliser dans la commande OpenSSL
        encryption_key_hex = encryption_key.hex()

        cmd = f'echo -n "{message}" | openssl enc -aes-256-cbc -a -salt -pass pass:{encryption_key_hex}'

        # Chiffrement du message avec OpenSSL
        # cmd = f"echo '{message}' | openssl enc -aes-256-cbc -pass pass:0000 -base64"
        encrypted_message = subprocess.check_output(cmd, shell=True).decode().strip()




        # # Clé de déchiffrement
        # decryption_key = encryption_key  # Utilisez la même clé que celle utilisée pour le chiffrement
        # decryption_key_hex = decryption_key.hex()
        # # Utilisez OpenSSL pour déchiffrer le message
        # cmd1 = f'echo "{encrypted_message}" | openssl  -aes-256-cbc -d -a -pass pass:{decryption_key_hex}'
        # decrypted_message = subprocess.check_output(cmd1, shell=True ).decode().strip()


        # Enregistrez la réclamation dans la base de données
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO reclamations (nom, message, encrypted_message ) VALUES (%s, %s, %s)",
                       (nom,  message, encrypted_message))
        mysql.connection.commit()

        # Ajoutez la réclamation à la liste (facultatif)
        reclamations.append({'nom': nom, 'message': message, 'encrypted_message': encrypted_message })

    return render_template('reclamation.html')




@app.route('/delete_complaint/<int:complaint_id>', methods=['POST'])
def delete_complaint(complaint_id):
    if 'loggedin' in session and session['role'].lower() == 'admin':
        # Handle deleting complaints from admins
        # ...
        return redirect(url_for('admin'))
    return redirect(url_for('login'))



if __name__ == '__main__':
    app.run(debug=True)
