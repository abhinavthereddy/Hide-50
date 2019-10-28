import csv
import urllib.request

from flask import redirect, render_template, request, session, url_for
from functools import wraps

MAX_KEY_SIZE = 26

def apology(error):
    return render_template("apology.html", error = error)

def login_required(f):           
    """
    Code borrowed from Pset 7 of CS50.
    Decorate routes to require login.

    http://flask.pocoo.org/docs/0.11/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function
    
    
def ciphertexter(plaintext1, key1):
    ciphertext1 = ''

    for symbol in plaintext1:
        if symbol.isalpha():
            num = ord(symbol)
            num += key1

            if symbol.isupper():
                if num > ord('Z'):
                    num -= 26
                elif num < ord('A'):
                    num += 26
            elif symbol.islower():
                if num > ord('z'):
                    num -= 26
                elif num < ord('a'):
                    num += 26

            ciphertext1 += chr(num)
        else:
            ciphertext1 += symbol
    return ciphertext1
    
def plaintexter(ciphertext2, key2):
    key2 = -key2
    plaintext2 = ''

    if (ciphertext2 == None):
        return apology("Uploaded image is not a stego image")
    else:
        for symbol in ciphertext2:
            if symbol.isalpha():
                num = ord(symbol)
                num += key2
    
                if symbol.isupper():
                    if num > ord('Z'):
                        num -= 26
                    elif num < ord('A'):
                        num += 26
                elif symbol.islower():
                    if num > ord('z'):
                        num -= 26
                    elif num < ord('a'):
                        num += 26
    
                plaintext2 += chr(num)
            else:
                plaintext2 += symbol
        return plaintext2