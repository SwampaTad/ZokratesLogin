from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
from .models import User
from . import db
from flask_login import login_user, login_required, logout_user, current_user
import hashlib
import ast
import json

auth = Blueprint('auth', __name__)

def hash_password_for_zokrates(password):
    hashed = hashlib.sha256(password.encode()).digest()
    part1 = int.from_bytes(hashed[:16], byteorder='big')
    part2 = int.from_bytes(hashed[16:], byteorder='big')

    string_list = [str(part1),str(part2)]

    return json.dumps(string_list)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            email = data.get('email')
            password = data.get('password')
        else:
            email = request.form.get('email')
            password = request.form.get('password')

        print(f"Login attempt for email: {email}") 

        user = User.query.filter_by(email=email).first()
        if user:
            stored_hash = ast.literal_eval(user.password)
            print(f"Stored hash for user: {stored_hash}") 
            if request.is_json:
                return jsonify({'stored_hash': stored_hash})
            else:
                login_user(user)
                return redirect(url_for('views.home'))
        else:
            error_message = 'Invalid email or password'
            print(error_message) 
            if request.is_json:
                return jsonify({'error': error_message}), 401
            else:
                flash(error_message, category='error')

    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':
        email = request.form.get('email')
        firstName = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists', category='error')
        elif len(email) <4:
            flash('Email must be greater than 3 characters', category='error')
        elif len(firstName) <2:
            flash('First name must be greater than 1 characters', category='error')
        elif password1 != password2:
            flash('Passwords are not matching.', category='error')
        elif len(password1) < 7:
            flash('Password must be greater than 6 characters', category='error')
        else:
            new_user = User(email=email, firstName=firstName, password=str(hash_password_for_zokrates(password1)))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account successfully created', category='success')
            return redirect(url_for('views.home'))

    return render_template("register.html", user=current_user)