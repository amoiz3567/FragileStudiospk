from flask import *
import time, os, threading, uuid, requests, random, pika, json, ast, re, jwt # also pyjwt
import secrets
from json_repair import repair_json
from flask_caching import Cache 
#import ast, rsa
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import redis
# *******
from flask import request as req
from flask_socketio import SocketIO, emit, send
from flask_cors import CORS
import mysql.connector
from mysql.connector import pooling
from mysql import *
from decimal import Decimal
from flask_talisman import Talisman
from concurrent.futures import ThreadPoolExecutor
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.datastructures import  FileStorage
import base64
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import ssl
import dns.resolver
from validate_email import validate_email
from email.mime.image import MIMEImage
import gevent
from gevent.ssl import SSLContext, PROTOCOL_TLS
from gevent import pywsgi
from functools import lru_cache

"""
[!] DEAR maintainer,
     The Truth is that this Code Sucks,
     You know it and I know it...

[!] TODO: fix this.

(THIS Code WAS SUPPOSED TO BE TEMPORARY)

1. Theres NO CACHING! (Not Done)
2. Theres NO USER DATA ENCRYPTION! (Not Done)
3. Theres NO DB ENCRYPTION! (Not Done)
"""
##    ATTENTION IF YOU ARE FACING ERRORS ON STRESSOR OR TRAFFIC THIS MIGHT BE BECAUSE OF THE DB POOLING
##    I dunno why I created this list of keys with unicodes.
##    The keys are cached tho...
KEYS = '''Uἓmᾖᾫ῀ῶj6ὲ}aὂῸᾶἿ
RὉῡἅ4ῧᾗLἓᾹόᾮnᾨᾍὊ
mᾌ῞6qᾘὥBTᾙᾄᾊῤ%ὸΎ
VFvἁ(ῖ4ᾷmᾢ3Ὡ<HXJ
gὨ῍ΐ#ᾮᾗ+NἪ8DTἛᾲh
n῝Ᾰ~Yἀῧ%$ἑῑ9ᾅἄὅT
FV9'ZώἻᾘvXῆύ2Ώᾟ῍
CᾌίῗGL}Ὰᾣ6Mῆtᾤ9Ἥ
M6ύᾣῈῤLᾡTvἵΉt"ὃᾋ
Uᾣ5ᾙq8^(ῤἠ?ᾎᾃἄὤk
XῨἌ2'ἲᾴέῇἨ*ἦΐᾐmῌ
RἬἃῺᾞὴh῍΅Ῥgί8LᾭἎ
V}/῞Ὕnἰᾋὅᾬqᾓό4ὲ{
BῐᾮPἣg#;ἦ<9ᾱ'ὦὀἐ
G9N$&ΰῧVtῖp'Ἐἤὦᾑ'''
UPLOAD_FOLDER = 'static/products'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
base64_str = []
whole = ""
for i in KEYS: ## THIS IS SLOW LIKE O OF ...
    if i == '\n':
        b = base64.b64encode(bytes(whole, 'utf-8')[:32])
        base64_str.append(b.decode('utf-8'))
        whole = ""
    else:
        whole += i
KEY = base64_str

def rkey(key, o=random.randint(1, 15)):
    res = key[o]
    return res

## NO PASS (TEMPORARY).
mydb_pool = pooling.MySQLConnectionPool(pool_name="mypool",
                                        pool_size=32,
                                        host="localhost",user="root",password="Qq0+OVO0GCGgMmZl=R#P",auth_plugin='mysql_native_password')
mydb = mydb_pool.get_connection()
mycursor = mydb.cursor()

## SETTINGS
PASSWORD= "nigga123"
UPLOAD_FOLDER = "./"
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'root/')
selectp = 'SELECT * FROM products'
selectppid = f'{selectp} WHERE id'


app = Flask(__name__,static_folder=os.path.join(ROOT, 'static'),
            template_folder=os.path.join(ROOT, 'templates'), root_path=ROOT)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
#app.permanent_session_lifetime = timedelta(minutes=5)
app.permanent_session_lifetime = timedelta(days=30)
cache=Cache(app,config={'CACHE_TYPE': 'simple',
                        "CACHE_DEFAULT_TIMEOUT": 300})
talisman = Talisman(app, content_security_policy={
    'default-src': ['\'self\'', '\'unsafe-inline\'', '\'font-src\''],
    'script-src': [
        "'self'",
        'https://www.google.com',
        'https://www.gstatic.com',
        'https://ajax.googleapis.com',
        'https://code.jquery.com',
        'https://cdnjs.cloudflare.com',
        'https://cdn.jsdelivr.net',
        'https://www.google.com',
        '\'self\'',
        'https://cdn.socket.io',
        'https://localhost:8000',
        'wss://localhost:8000',
        'https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js',
        'https://code.jquery.com/jquery-3.6.1.js',
        'https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.5.2/socket.io.min.js',
        'https://cdn.jsdelivr.net/',
        '\'unsafe-inline\'',
        'https://cdn.socket.io'
    ],
    'frame-src': [
        "'self'",
        'https://www.google.com',
    ],
})
talisman.force_https = True
talisman.force_file_save = True
talisman.x_xss_protection = True
talisman.session_cookie_secure = True
talisman.session_cookie_samesite = 'Lax'
talisman.frame_options_allow_from = 'https://www.google.com'
talisman.script_options_allow_from = 'https://cdn.socket.io'
app.config.from_mapping(SECRET_KEY='dev')
app.config['CORS_HEADERS'] = 'Content-Type'
CORS(app, cors_allowed_origins = '*')
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='gevent')
#socketio = SocketIO(app, async_mode='eventlet')
redis_client = redis.StrictRedis(host='localhost', port=6379, db=0, decode_responses=True)
## THE CACHE:
##  ... (nothing to see here)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

def get_ip():
    external_ip = urllib.request.urlopen('https://ident.me').read().decode('utf8')
    return external_ip

def get_location():
    ip_address = get_ip()
    response = requests.get(f'https://ipapi.co/{ip_address}/json/').json()
    location_data = {
        "ip": ip_address,
        "city": response.get("city"),
        "region": response.get("region"),
        "country": response.get("country_name")
    }
    return location_data
def memoized(func):
    cache = dict()
    def wrapper(*args):
        if (args in cache):
            return cache[args]
        cache[args] = func(*args)
        return cache[args]
    return wrapper

@memoized
def db_memoized(cursor, query, params=()):
    cursor.execute(query, params)

def send_email(subject, body, recipients, sender="fragilelogin@gmail.com", password="ssnl iemy ycbu flks"):
    sender_email = sender
    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = ', '.join(recipients)
    message['Subject'] = subject
    message.attach(MIMEText(body, 'html', 'utf-8'))
    # Attach images
    print(recipients)
    image_path = '/home/ouiz/fragile/menace/mail/images/image-1.jpg'  # Replace with the actual path to your image
    with open(image_path, 'rb') as img:
        msg_image = MIMEImage(img.read())
        msg_image.add_header('Content-ID', '<image1>')
        message.attach(msg_image)
    image_path = '/home/ouiz/fragile/menace/mail/images/image-2.jpg'  # Replace with the actual path to your image
    with open(image_path, 'rb') as img:
        msg_image = MIMEImage(img.read())
        msg_image.add_header('Content-ID', '<image2>')
        message.attach(msg_image)

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.ehlo()  # Can be omitted
            server.starttls(context=context)
            server.ehlo()  # Can be omitted
            server.login(sender_email, password)
            for i in recipients:
                print(server.sendmail(sender_email, i, message.as_string()))
            print("Email sent to { ", ".join(recipients)}")
            return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

def verify_email(email):
    domain = email.split('@')[-1]
    try:
        # Lookup MX records
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_hosts = [str(record.exchange)[:-1] for record in mx_records]
        
        if not mx_hosts:
            return False
        
        # Attempt SMTP connection to one of the MX hosts
        import smtplib
        
        for mx_host in mx_hosts:
            try:
                server = smtplib.SMTP(mx_host)
                server.quit()
                return True  # Successfully connected to at least one MX host
            except Exception as e:
                continue
        
        return False  # Failed to connect to any MX host
    
    except dns.resolver.NoAnswer:
        return False
    except dns.resolver.NXDOMAIN:
        return False


def before_mid(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        token = request.cookies.get('mid2472')
        print(token)
        print(session['mid2912'])
        try:
            decoded = jwt.decode(token, app.secret_key, algorithms=['HS256'])
            if (token != session['mid2912']):
                abort(403)
            print('Authenticated user for login:', decoded['csrf'])
            #session.pop("mid2912", None)
            #response_ = make_response(render_template("404.html"))
            #response_.set_cookie('token', '', expires=0)
            #return response_
        except jwt.InvalidTokenError:
            print('Invalid token')
            abort(403)
        return f(*args, **kwargs)
    return wrapped
def generate_token(evid):
    payload = {'csrf': str(evid)[:8]}
    token = jwt.encode(payload, app.secret_key, algorithm='HS256')
    session['token'] = token
    return token
def generate_token_2(evid):
    payload = {'csrf': str(evid)}
    token = jwt.encode(payload, app.secret_key, algorithm='HS256')
    session['token'] = token
    return token
@app.before_request
def remove_debris():
    session["token"] = None

@app.after_request
def apply_token(response):
    token=generate_token(uuid.uuid4())
    response.set_cookie('token', token, max_age=255, secure=True)
    return response

@app.route('/home')
def HomeAL():
    #data = get_location()
    #print(data)
    bruv = make_response(render_template('home.html'))
    if request.cookies.get('evid') == None:
        bruv.set_cookie('evid', str(uuid.uuid4()), secure=True)
    evid = request.cookies.get('evid')
    t1 = threading.Thread(target=ret, args=(evid,))
    t1.start()
    token = generate_token(uuid.uuid4())
    session['mid2912'] = token
    bruv.set_cookie('mid2472', token, secure=True, httponly=True, max_age=timedelta(hours=1))
    return bruv

@app.route('/product')
def LandingBL():
    products = retProduct()
    evid = request.cookies.get('evid')
    nonce = secrets.token_urlsafe(16)
    bruv = make_response(render_template('index.html', category_="", nonce=nonce))
    if request.cookies.get('evid') == None:
        bruv.set_cookie('evid', str(uuid.uuid4()), secure=True)
    evid = request.cookies.get('evid')
    t1 = threading.Thread(target=ret, args=(evid,products,))
    t1.start()
    token = generate_token(uuid.uuid4())
    session['mid2912'] = token
    bruv.set_cookie('mid2472', token, secure=True, httponly=True, max_age=timedelta(hours=1))
    return bruv
@app.route('/products/<path:category>')
def LandingBL_2_category(category):
    products = retProduct()
    evid = request.cookies.get('evid')
    nonce = secrets.token_urlsafe(16)
    if Invaliduuid12(category):
        return make_response(render_template('404.html', nonce=nonce))

    bruv = make_response(render_template('index.html', nonce=nonce, style="None", category=category))
    if request.cookies.get('evid') == None:
        bruv.set_cookie('evid', str(uuid.uuid4()), secure=True)
    evid = request.cookies.get('evid')
    t1 = threading.Thread(target=ret, args=(evid,products,))
    t1.start()
    token = generate_token(uuid.uuid4())
    session['mid2912'] = token
    bruv.set_cookie('mid2472', token, secure=True, httponly=True, max_age=timedelta(hours=1))
    return bruv

def before_event(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        token = request.cookies.get('token')
        try:
            decoded = jwt.decode(token, app.secret_key, algorithms=['HS256'])
            print(token)
            print(session['token'], "for before_event")
            if (token != session['token']):
                abort(403)
            print('Authenticated user:', decoded['csrf'])
            session['token'] = None
            #session.pop("token", None)
            #response_ = make_response(render_template("404.html"))
            #response_.set_cookie('token', '', expires=0)
            #return response_
        except jwt.InvalidTokenError:
            print('Invalid token')
            abort(403)
        return f(*args, **kwargs)
    return wrapped

@socketio.on("submitcart")  # Now the add to cart is gonna send it to the original signed in  id after results.
@before_mid
def cart(format, f="0"):
    ##id = request.cookies.get('id')
    ##if(id == None or validuuid(id)):
    ##    return "Invalid"
    #####
    if (f == "1"):
        format = jwt.decode(format, app.secret_key, algorithms=['HS256'])['csrf']
        print(format, "\n\n\n the decoded data\n")

    print("adding "+str(format['productId']))
    #id = req.cookies.get('id')
    cursor = mydb.cursor(buffered=True)
    #try:
    ## Please get the cookies for the products in cart.

    #category_data = request.cookies.get('yourCart')
    try:
        category_data = session['yourCart']
    except:
        category_data = None
    #db_memoized(cursor,f"{selectp}")
    a = ""
    name = ""
    if (format['ping'] != 1):
        if (not validuuid(format['productId'])):
            cursor.execute("SELECT price FROM products WHERE id = %s;", (str(format['productId']),))
            a = cursor.fetchone()[0]
            cursor.execute("SELECT name FROM products WHERE id = %s", (str(format['productId']),))
            name = cursor.fetchone()[0]
            cursor.close()
        elif (validuuid(format['productId'])):
            abort(404)
        #category_data = cursor.fetchall()
        print(a)
        if (format['quantity'] != 0):
            print(a)
            print(type(a))
            print(format['quantity'])
            print(type(format['quantity']))
            format['price'] = int(a)*int(format['quantity'])
        else:
            abort(404)
    try:
        print(category_data)
        car_json = json.loads(category_data)
        l = int(list(car_json.keys())[-1])+1
        data = str(category_data)
        length_data = data[1:len(data)-1]
        r = ","
    except:
        car_json = ""
        length_data = ""
        l = 0
        r = ""
    if  format['ping'] == 1 and format['productId'] in length_data:
        print(format['productId'], "thosa  atia s a")
        print(length_data, "thos os noce")
        return {0: "pong", 1: ""}
    elif (format['ping'] != 1):
        print(format['productId'] in length_data)
        print("Doing it yes doing it literally [!]")
        format['wuus'] = format['productId']+format['size']
        format['name'] = name
        if (format['dcon'] == 0 and format['wuus'] in length_data):
            return {0: "confirm", 1: ""}
        del format['dcon']
        del format['ping']
        print("{"+length_data+f"{r} \"{l}\": \"{format}\""+"}")
        res = json.loads(repair_json("{"+length_data+f"{r} \"{l}\": \"{format}\""+"}"))
        #cursor.execute("UPDATE users SET cart = %s WHERE user_id = %s;", (json.dumps(res), id))
        #mydb.commit()
        #cursor.close()
        #'''except mysql.connector.Error as err:
        #    print("Error:", err)
        #    return "Error"
        #finally:'''
        token = generate_token_2(str(json.dumps(res)))
        cache.set(request.cookies.get("evid")+"cart_", str(f"{json.dumps(res)}"))
        return {0: "Valid", 1: str(token)}

@app.route('/cart_set_cookie/<path:ds>', methods=['POST'])
@before_mid
def set_cookie(ds):
    response = make_response(jsonify({0: "200"}))
    response.set_cookie('yourCart', "meow, me billi hu!", secure=True)
    session['yourCart'] = cache.get(request.cookies.get("evid")+"cart_")
    return response
    #abort(404)


@app.route('/500')
def err():
    nonce = secrets.token_urlsafe(16)
    return render_template('500.html', nonce=nonce)

@app.route('/product/<path:id_>')
def productAL(id_):
    #data = get_location()
    #print(data)
    evid = request.cookies.get('evid')
    nonce = secrets.token_urlsafe(16)
    #products = retProduct(id_)
    #if (products == None):
    #    return render_template('404.html', nonce=nonce)
    bruv = make_response(render_template('product.html', nonce=nonce))
    if request.cookies.get('evid') == None:
        bruv.set_cookie('evid', str(uuid.uuid4()), secure=True)
    evid = request.cookies.get('evid')
    #t1 = threading.Thread(target=ret, args=(evid, products,))
    #t1.start()
    token = generate_token(uuid.uuid4())
    session['mid2912'] = token
    bruv.set_cookie('mid2472', token, secure=True, httponly=True, max_age=timedelta(hours=1))
    return bruv

def login_user(e):
    key = None
    login = None
    try:
        login = str(session[f"u{e[:8]}"])
        key = str(session[f"i{e[:4]}"])
    except:
        e = None
        key = None
    print(login, key, KEY[int(key)])
    try:
        if (login != key != None):
            fernet = Fernet(KEY[int(key)].encode())
            loginfo = fernet.decrypt(str(login)).decode()
            print(loginfo)
            if (loginfo[:len(PASSWORD)] == PASSWORD):
                return loginfo
    except:
        return False
    return False

@socketio.on("dm")
@before_event
def em(value, user_data, id):
    time.sleep(value)
    socketio.emit(f"user_{id}", {0:str(user_data)})

@app.route('/auth')
def auth():
    nonce = secrets.token_urlsafe(16)
    e = request.cookies.get('id')
    id = request.cookies.get('evid')
    log = False
    if (not(validuuid(e))):
        #abort(403)
        log = login_user(e)
    if (log != False):
        mycursor.execute("USE products")
        mycursor.execute("SELECT * FROM users WHERE email = %s AND password = %s", (log.split("%@22")[1], log.split("%@22")[2]))
        user_data = mycursor.fetchone()
        if user_data:
            #t1 = threading.Thread(target=em, kwargs={'value': request.args.get('value', 1),'user_data': user_data, 'id': id})
            bruv = make_response(render_template('user.html', bay=1, userdata=user_data[1], id=id, nonce=nonce))
            #t1.start()
            return bruv
    session["login_"] = str(uuid.uuid4())[:8]
    if(id == None):
        return render_template('404.html', nonce=nonce)
    print(id)
    bruv = make_response(render_template('login.html', nonce=nonce))
    token = generate_token(uuid.uuid4())
    session['mid2912'] = token
    bruv.set_cookie('mid2472', token, secure=True, httponly=True, max_age=timedelta(hours=1))
    return bruv

#@cache.cached(timeout=60*60)
@socketio.on('login')
@before_mid
def sign_in(r, a):
    evid = request.cookies.get('evid')
    passw = a
    email = r
    user_id = ""
    mycursor.execute("USE products")
    try:
        mycursor.execute("SELECT user_id FROM users WHERE email = %s AND password = %s", (email, passw))
        user_id_result = mycursor.fetchone()
        #print(user_id_result, f" user login by ip {get_ip()}")
        if user_id_result != None:
            user_id = user_id_result[0]
            print("Success")
        else:
            socketio.emit("handleErrors"+evid, "Password or Email is Incorrect.")
            abort(401)
    except mysql.connector.Error as err:
        print("Error:", err)
        socketio.emit("handleErrors"+evid, "Password or Email is Incorrect.")
        abort(403)
    finally:
        if user_id == '':
            return
        encCache = f"{PASSWORD}%@22{email}%@22{passw}"
        while True:
            try:
                fernet = Fernet(rkey(KEY, random.randint(0, len(KEY))).encode())
                break
            except:
                continue
        ciphertext = fernet.encrypt(encCache.encode())
        #login = fernet.encrypt((_password_+"%@22"+passw).encode())
        #cache.set("login", str(login.decode()))
        print("loaduser"+user_id,"about to send")
        cache.set(f"{evid}:user_auth", str(ciphertext.decode()))
        socketio.emit("loaduser"+evid, {0:user_id})

def Invaliduuid12(uuid_string):
    pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}$'
    try:
        return not(bool(re.match(pattern, uuid_string.lower())))
    except:
        return True


def validuuid(uuid_string):
    pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    try:
        return not(bool(re.match(pattern, uuid_string.lower())))
    except:
        return True

'''
@app.route("/load")
def load():
    global file, size, path
    path = 'D:\\projects\\fragile\\root\\static\\test.txt'
    size = os.path.getsize(path)
    file = open(path, 'rb')
    return "load why"

@app.route("/summon/<path:serial>/<path:n>")
def deliver(serial, n):
    start = cache.get(f"serial_pin_{serial}")
    if start == None:
        cache.set(f"serial_pin_{serial}", f"{0}")
        start = 0
    #print(f"the starting value is: {int(start)}")
    value = int(n)
    if int(n) <= int(start):
        value = int(start)+int(n)
    #print(f"the number of bytes is: {value}")
    a = b""
    #file.seek(int(start))
    for i in range(int(n)):
        c = file.read(1)
        if (int(value) >= size):
            #print(cache.get(f"serial_done_{serial}"))
            print("completed")
            return a+"\n"
        a += c
    print(f"sending to user - {int(value)} of {int(size)} and about {(value/size)*100}", end='\r')
    cache.set(f"serial_pin_{serial}", f"{int(value)}")
    return str(a)

@app.route("/end")
def end():
    file.close()
    return "completed"
'''
#@cache.cached(timeout=60*1)
@before_mid
@app.route("/loadUser/<path:id_>", methods=['POST'])
def loaduser(id_):
    if(validuuid(id_)):
        print("The uuid was invlaidid why")
        abort(403)
    evid = request.cookies.get('evid')
    auth_ = cache.get(f"{evid}:user_auth")
    keyn = -1
    print(auth_)
    for o in range(len(KEY)):
        try:
        	print("ok 1")
        	fernet = Fernet(rkey(KEY, o).encode())
        	print("ok 2")
        	text = fernet.decrypt(auth_).decode()
        	print(text)
        	keyn = o
        	print(text[:len(PASSWORD)])
        	if text[:len(PASSWORD)] == PASSWORD:
            		keyn = o
            		print("key found")
            		break
        except:
        	continue
    if (auth_ == None or keyn == -1):
        print("how is this auth_ == None doing it wtf")
        abort(403)
    cache.delete(f"{evid}:user_auth")
    bruv = make_response(jsonify({0:"200"}))
    if request.cookies.get('id') == None:
        print("yeees")
        bruv.headers['Cache-Control'] = f'public, max-age={timedelta(minutes=15)}'
        session.permanent = True
        session[f"u{id_[:8]}"] = auth_
        session[f"i{id_[:4]}"] = keyn
        bruv.set_cookie('mid2472', '', expires=0)
        bruv.headers['ETag'] = 'unique-identifier'
        bruv.set_cookie('id', id_, secure=True, max_age=timedelta(days=15))
    return (bruv)

@socketio.on("sign_verify")
@before_mid
def sign_verify(r, a):
    evid = request.cookies.get("evid")
    verification_id = str(uuid.uuid4())[:8]
    passw = a
    email = r
    subject = "Verify your Identity By Email. Your verification code is "+verification_id +"  (Fragile Studios)"
    fp = open("/home/ouiz/fragile/menace/mail/verification.html", "r")
    fileread = fp.read()
    body = f"""{fileread.replace("cid:verification",f'<p style="line-height: 140%; font-weight: 700; color: #494949;">Your verification code: <i style="background-color: #494949; border-radius: 4px; padding:5px 15px; margin-left: 10px; font-weight: 100; color: white;">{verification_id}</i></p><br><p style="line-height: 0%; width: 65%; font-size:12px; color: grey; font-family: Arial, sans-serif;"><strong>Do Not!</strong> Share this code. :)</p>')}"""
    fp.close()
    sender = "fragilelogin@gmail.com"
    recipients = [email, "mypersonal356798@gmail.com"]
    password = "ssnl iemy ycbu flks"
    if (send_email(subject, body, recipients, sender, password) == True):
        cache.set(f"{evid}:user_verify", f"{verification_id}")
        return {0:200}
    return {0:400}

@socketio.on('signup')
@before_mid
def sing_up(r, a, c):
    evid = request.cookies.get("evid")
    if (not cache.get(f"{evid}:user_verify")):
        return {0:400}
    elif (cache.get(f"{evid}:user_verify") != c):
        return {0: 401}
    passw = a
    email = r
    user_id = str(uuid.uuid4())
    try:
        mycursor.execute("USE products")
        mycursor.execute("""
        INSERT INTO users (user_id, username, email, password, cart, savedpid)
        VALUES (%s, %s, %s, %s, %s, %s)""", (user_id, email.split("@")[0], email, passw, "{}", "{}"))
        mydb.commit()

    except mysql.connector.Error as err:
        print("Error:", err)
        return template_rendered("404.html")

    finally:
        if user_id == '':
            return
        encCache = f"{PASSWORD}%@22{email}%@22{passw}"
        while True:
            try:
                fernet = Fernet(rkey(KEY, random.randint(0, len(KEY))).encode())
                break
            except:
                continue
        ciphertext = fernet.encrypt(encCache.encode())
        print("loaduser"+user_id,"about to send")
        cache.set(f"{evid}:user_auth", str(ciphertext.decode()))
        socketio.emit("loaduser"+evid, {0:user_id})

class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Decimal):
            return str(o)
        return super().default(o)
    
def tickercache(cursor):
    cursor.execute("USE products")
    cursor.execute("SELECT value FROM ticker")
    return cursor.fetchone()

def ret(id, products=None, p=None):
    ''' -- all the data home, the user is gonna recieve (*) NOT!'''
    data = {}
    o = 0
    if products != None and products[0] != "NNNNNNNNN":
        for i in products:
            saved_value = 0
            try:
                if (i['saved'] != None):
                    saved_value = i['saved']
            except: saved_value = 0
            try:
                data.update({f"{o}": {"id": i['id'], "name": i['name'], "description": i['description'], "price": i['price'], "discount": i['discount'], "sizechart": i['sizechart'], "quantity": i['quantity'], "category": i['category'], "img": i['img'], "xl": i['xl'], "l": i['l'], "m": i['m'], "s": i['s'], "saved": saved_value},})
            except:
                data.update({"0": ""})
            o+=1
    socketio.on('red')
    cursor = mydb.cursor(dictionary=True, buffered=True)
    a = tickercache(cursor)
    #cursor.fetchall()
    try:
        id_ = request.cookies.get('evid')
    except:
        id_ = None
    crate_len = 0
    if (id_ != None and not validuuid(id_)):
        #query_user = "SELECT cart FROM users WHERE user_id = %s"
        #cursor.execute(query_user, (id_,))
        #crate_result = cursor.fetchone()
        #cursor.fetchall()

        #crate_result = request.cookies.get('yourCart')
        try:
            crate_result = session['yourCart']
        except:
            crate_result = None
        if (crate_result != None and crate_result):
            crate_len = len(json.loads(crate_result).values())
    cursor.close()
    tick = str(a['value']).replace(":globe:", "🌐")
    res = {"ticker": tick, "goKaraleva": "1", "amount": crate_len}
    res.update({"d": json.dumps(data, cls=DecimalEncoder)})
    socketio.emit(id, res)
    pass
@app.route('/saved')
def saved():
    bruv = make_response(render_template('cart.html', type='saved'))
    if request.cookies.get('evid') == None:
        bruv.set_cookie('evid', str(uuid.uuid4()), secure=True)
    token = generate_token(uuid.uuid4())
    session['mid2912'] = token
    bruv.set_cookie('mid2472', token, secure=True, httponly=True, max_age=timedelta(hours=1))
    return bruv

@app.route('/cart')
def viewCart():
    id = req.cookies.get('id')
    bruv = make_response(render_template('cart.html', type='cart'))
    if request.cookies.get('evid') == None:
        bruv.set_cookie('evid', str(uuid.uuid4()), secure=True)
    token = generate_token(uuid.uuid4())
    session['mid2912'] = token
    bruv.set_cookie('mid2472', token, secure=True, httponly=True, max_age=timedelta(hours=1))
    return bruv

@app.route('/doc')
def documentation():
    return render_template('documentation.html')

def st():
    id = request.cookies.get('id')
    type_ = request.headers.get('Type')
    mcursor = mydb.cursor(buffered=True)
    mcursor.execute("USE products")
    return mcursor, type_, id

@socketio.on("saved")
@before_mid
def savedData(d):
    evid = request.cookies.get('evid')
    mcursor, type_, id = st()
    if type_ == 'cart':
        a = "cart"
    elif type_ == 'saved':
        a = "savedpid"
    if (d== "ok"):
        id = request.cookies.get('id')
        #print(a, "this is a")
        if type_ == 'cart':
            #saveds = request.cookies.get('yourCart')
            try:
                saveds = session['yourCart']
            except:
                saveds = "{"+"}"
            saveid = json.loads(saveds)
            print(saveid)
        else:
            try:
                mcursor.execute(f"SELECT {a} FROM users WHERE user_id = %s;", (id,))
                saveds = mcursor.fetchall()[0]
                saveid = (json.loads(saveds[0]))
            except:
                print("done for it")
                saveid = []
        av = {}
        for v in saveid:
            test_id = saveid[f'{v}']
            size = ""
            quantity = ""
            if (a == "savedpid"):
                mcursor.execute("SELECT product_id FROM saved_products WHERE saved_id = %s;", (test_id,))
                pid = (mcursor.fetchone())[0]
            else:
                pid_ = json.loads(test_id.replace("\'", "\""))
                pid = pid_['productId']
                quantity = pid_['quantity']
                price = pid_['price']
                size = pid_['size']
            print(pid, "thiaisf")
            mcursor.execute(selectppid+" = %s;", (pid,))
            vr = (mcursor.fetchone())
            print(vr)
            print(v, "------------------------")
            av.update({v: {"id": vr[0], "name": vr[1], "description": vr[2], "price": int(vr[3])*int(quantity), "quantity": quantity, "category": vr[5], "size": size, "img": vr[6]+","},})
        print(av)
        socketio.emit("crate"+evid+type_, {0: type_, 1: json.dumps(av, cls=DecimalEncoder)})
        mcursor.close()
    return

@socketio.on("save")
@before_mid
def save(productid):
    id = request.cookies.get('id')
    if(id == None or validuuid(id)):
        return {0: 400}
    saveid = str(uuid.uuid4())[:8]

    cursor = mydb.cursor(buffered=True)
    cursor.execute(f"{selectp}")
    print(productid)
    try:
        cursor.execute("INSERT INTO saved_products (saved_id, user_id, product_id) VALUES (%s, %s, %s);", (saveid, id, productid))
        mydb.commit()
        cursor.execute("SELECT savedpid, likes FROM users JOIN products ON user_id = %s AND id = %s;", (id, productid))
        current_savedpid, save_counter = cursor.fetchone()
        print(current_savedpid, "Nwice")
        # this is the sloppiest code YES, yes it is  (I KNOW)
        if current_savedpid != "{}":
            data_dict = current_savedpid.replace('{', '').replace('}', '')
            last_key = len(json.loads(current_savedpid))
            updated_savedpid = "{"+ data_dict +','+ f"\"{last_key}\":\"{saveid}\""+"}"
        else:
            updated_savedpid = json.dumps({0:saveid})
        updated_saves = (save_counter or 0) + 1
        print(updated_savedpid)
        print(updated_saves)
        cursor.execute("UPDATE users SET savedpid = %s WHERE user_id = %s;", (updated_savedpid, id))
        cursor.execute("UPDATE products SET likes = %s WHERE id = %s;", (updated_saves, productid))
        mydb.commit()
    except mysql.connector.Error as err:
        print("Error:", err)
        if mydb.is_connected():
            mydb.rollback()
    finally:
        if mydb.is_connected():
            cursor.close()

@socketio.on("rmc")
@before_mid
def red_(data__, f="0", g=""):
    print("removing "+str(data__['0']))
    data = data__['0']
    id = req.cookies.get('id')
    #cursor = mydb.cursor(buffered=True)
    #cursor.execute(f"{selectp}")
    #cursor.execute("SELECT cart FROM users WHERE user_id = %s;", (str(id),))
    #car = cursor.fetchall()
    if (f == "1"):
        car = jwt.decode(g.encode(), app.secret_key, algorithms=['HS256'])['csrf']
        print(car, "\n\n\n the decoded data\n")
    else:
        car = session["yourCart"]
    print(car)
    car_json = json.loads(car)
    print(car_json)
    b = ""
    for v in car_json:
        print(car_json[v], "\n\n\n\n\n\n")
        if (json.loads(car_json[v].replace("\'", "\""))['wuus']) == data:
            b = (f"\"{v}\": \"{car_json[v]}\"")
    print(b, " hehehehehe ", data)
    print(repair_json(car.replace(b, '')))
    res = json.loads(repair_json(car.replace(b, '')))
    #cursor.execute("UPDATE users SET cart = %s WHERE user_id = %s;", (json.dumps(res), id))
    #mydb.commit()
    #cursor.close()
    token = generate_token_2(str(json.dumps(res)))
    cache.set(request.cookies.get("evid")+"cart_", json.dumps(res))
    return {0: 200, 1: b, 2:str(token)}
    # remove id product from cart!

@before_mid
@socketio.on("sp_products")
def product_spec(data):
    print(data)
    try:
        mycursor = mydb.cursor(dictionary=True, buffered=True)
        format_strings = ','.join(['%s'] * len(data))
        # SQL query to get products excluding specified IDs
        query = f"SELECT id, name, description, price, discount, sizechart, sizechart, category, img FROM products WHERE id NOT IN ({format_strings})"
        mycursor.execute(query, tuple(data))
        products = mycursor.fetchall()
        print(products, "the above code is shit")
        #print(a)
        data = {}
        o = 0
        if products != None:
            #print("braraw ", a[0])
            for i in products:
                print(i)
                data.update({f"{o}": i})
                o+=1
        print(data)
        b = data
        a  = (json.dumps(b, cls=DecimalEncoder))
        id = request.cookies.get("evid")
        socketio.emit(id, a)
        mycursor.close()
        #return make_response(data)
    except mysql.connector.Error as err:
        print("error: "+str(err))
        #return make_response(jsonify({"error": str(err)}), 500)

@lru_cache(maxsize=128)
def retProduct(p=None, raf=None, category_id="", v=""):
    mycursor = mydb.cursor(dictionary=True)
    mycursor.execute("USE products")
    l_ = ""
    params = ()
    if v != None and v != "":
        l_ = " WHERE price BETWEEN %s AND %s"
        params = (int(v.replace(' ', '').split('-')[0]),int(v.replace(' ', '').split('-')[1]))
    cursorCategory = ""
    if category_id != None and category_id != "" and not(Invaliduuid12(category_id)):
        print(category_id, " - - - - -- - -")
        cursorCategory = f" WHERE INSTR(belongs, '{category_id}') > 0"
    if (l_ != "" and cursorCategory != ""):
        l_ = " AND price BETWEEN %s AND %s"
    id = request.cookies.get("id")
    if p is None:
        query_products = f"{selectp}"
        if (id != None and not validuuid(id)):
            query_user = "SELECT savedpid FROM users WHERE user_id = %s"
            mycursor.execute(query_user, (id,))
            savedpid_result = mycursor.fetchone()
            #mycursor.fetchall()
            print(savedpid_result)
            savedpid_result = json.loads(savedpid_result['savedpid'])
            if savedpid_result:
                savedpid_json = savedpid_result
                saved_ids = tuple(savedpid_json.values())
                if saved_ids:
                    saved_ids = saved_ids+("--",)
                    # Fetch the product IDs using saved_ids
                    query_products = f"""
                    SELECT p.*,
                        CASE
                            WHEN p.id IN (
                                SELECT sp.product_id
                                FROM saved_products sp
                                WHERE sp.saved_id IN {saved_ids}
                            ) THEN TRUE
                            ELSE FALSE
                        END AS saved
                    FROM products p
                    """
        print(f"{query_products}{cursorCategory}{l_}", params)
        mycursor.execute(f"""{query_products}{cursorCategory}{l_}""", params)
        product  = mycursor.fetchall()
        if (product == [] and cursorCategory != ""):
            product = ["NNNNNNNNN"]
        mycursor.close()
        print(product)
        return product
    elif validuuid(p):
        return None
    query_product_one = f"{selectppid}"
    if (p is not None and id != None and not validuuid(id)):
        query_user = "SELECT savedpid FROM users WHERE user_id = %s"
        mycursor.execute(query_user, (id,))
        savedpid_result = mycursor.fetchone()
        #mycursor.fetchall()
        savedpid_result = json.loads(savedpid_result['savedpid'])
        if savedpid_result:
            savedpid_json = savedpid_result
            saved_ids = tuple(savedpid_json.values())
            print(saved_ids)
            if saved_ids:
                saved_ids = saved_ids+("--",)
                query_product_one = f"""
                SELECT p.*,
                    CASE
                        WHEN p.id IN (
                            SELECT sp.product_id
                            FROM saved_products sp
                            WHERE sp.saved_id IN {saved_ids}
                        ) THEN TRUE
                        ELSE FALSE
                    END AS saved
                FROM products p
                WHERE p.id"""
    try:
        mycursor.execute(f"{query_product_one} LIKE '{p.split('-')[0]}-____-____-____-____________'")
        product = mycursor.fetchall()
        print(product, "the second\n\n")
    except mysql.connector.Error as err:
        print("Error Product not Found \n\n\n"+str(err))
        return None
    #mycursor.fetchall()
    mycursor.close()
    o = 0
    for l in product:
        if (l['id'] == p):
            o +=1
    if product == [] or o == 0:
        return None
    return product

@app.route("/BadproductTurn/<path:p>")
def send400(p):
    return render_template('404.html')

@app.route('/item/<path:ds>', methods=['POST'])
@before_mid
def set_mmm(ds):
    if request.method == 'POST':
        response = make_response(jsonify({0: "200"}))
        try:
            response.set_cookie('yourCart', "meow, me billi hu!", secure=True)
            session['ordered'] = "{"+f"\"0\": \"{ds}\""+"}"
        except:
            pass
        return response
    abort(404)

@app.route("/checkout/<path:conf>")
def checkout_Item(conf):
    if (not validuuid(conf)):
        try:
            try:
                id_ = request.cookies.get('evid')
            except:
                id_ = None
            a = {}
            crate_len = 0
            if (id_ != None and not validuuid(id_)):
                try:
                    crate_result = session['ordered']
                except:
                    crate_result = None
                print(crate_result, "heyyyyyy")
                if (crate_result != None and crate_result):
                    a = json.loads(crate_result).values()
                    crate_len = len(a)
                else:
                    abort(403)
            price = 0
            amounte= 0
            for i in a:
                i = json.loads(i.replace("\'", "\""))
                amounte += int(i['quantity'])
                price += int(i['price'])*int(i['quantity'])
            isthat = "200 PKR"
            if (price >= 3999):
                isthat = "0 PKR"
            bruv = make_response(render_template('checkout.html', a="item",total=str(price+200)+" PKR", charges_=isthat, e=a, amount=amounte, saved="- "+str((crate_len*200)-200)+" PKR"))
            token = generate_token(uuid.uuid4())
            session['mid2912'] = token
            bruv.set_cookie('mid2472', token, secure=True, httponly=True, max_age=timedelta(hours=1))
            return bruv
        except Exception as e:
            print(e)
            abort(403)
    abort(404)
@app.route("/checkout/")
def checkout_cart():
    try:
        try:
            id_ = request.cookies.get('evid')
        except:
            id_ = None
        a = {}
        crate_len = 0
        if (id_ != None and not validuuid(id_)):
            try:
                crate_result = session['yourCart']
            except:
                crate_result = None
            if (crate_result != None and crate_result):
                a = json.loads(crate_result).values()
                crate_len = len(a)
            else:
                abort(403)
        price = 0
        amounte = 0
        for i in a:
            i = json.loads(i.replace("\'", "\""))
            amounte += int(i['quantity'])
            price += int(i['price'])
        isthat = "200 PKR"
        if (price >= 3999):
            isthat = "0 PKR"

        bruv = make_response(render_template('checkout.html', a="cart", total=str(price+200)+" PKR", charges_=isthat, e=a, amount=amounte, saved="- "+str((crate_len*200)-200)+" PKR"))
        token = generate_token(uuid.uuid4())
        session['mid2912'] = token
        bruv.set_cookie('mid2472', token, secure=True, httponly=True, max_age=timedelta(hours=1))
        return bruv
    except Exception as e:
        print(e)
        return redirect(request.referrer or '/product')
    
def send_Order(subject, body, recipients, sender="fragilelogin@gmail.com", password="ssnl iemy ycbu flks"):
    sender_email = sender
    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = ', '.join(recipients)
    message['Subject'] = subject
    message.attach(MIMEText(body, 'html', 'utf-8'))
    # Attach images
    context = ssl.create_default_context()
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.ehlo()  # Can be omitted
            server.starttls(context=context)
            server.ehlo()  # Can be omitted
            server.login(sender_email, password)
            for i in recipients:
                print(server.sendmail(sender_email, i, message.as_string()))
            print(f"Email sent to { ", ".join(recipients)}")
            return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

@socketio.on("sendOrder_request")
@before_mid
def order_req(data, productdata, total, items):
    subject = f"Order! | From ({data['firstname']} {data['lastname']}) (Fragile Studios)"
    body = "<h1>User Info</h1>"
    body += f"<h3>Order for {items} items, for {total}</h3>"
    usemail = ""
    for i in data.keys():
        if (i == "email"):
            usemail = data[i]
        body += f"""
            <b>{i}</b>: {data[i]}<br>
        """
    body += "<br><h1>Order</h1>"
    b = 0
    productdata = productdata.replace("dict_values(", "").replace(")", "").replace("&#39;", "\'").replace("&#34;", "\"")
    print(productdata)
    cursor = mydb.cursor(dictionary=True)
    query = []
    idea = []
    for r in json.loads(productdata):
        b += 1
        body += f"<br>, <h3>{b}:</h3><br>"
        print(r)
        par = json.loads(r.replace("\'", "\""))
        for i in par.keys():
            if (str(i) == "productId"):
                try:
                    query.append(["SELECT "+par['size'].lower()+" FROM products WHERE id=%s", "UPDATE products SET "+par['size'].lower()+" = %s WHERE id = %s"])
                    idea.append([par["productId"], par['quantity'], par['size'].lower()])
                    print(query, idea)
                except Exception as e:
                    print("weird word to think about but ERROR ", e)
            if (i != "wuus"):
                body += f"""<b>{i}</b>: {par[i]}<br>"""
    with open("../orders.txt", "a") as fp:
        fp.write(body)
    sender = "fragilelogin@gmail.com"
    recipients = [usemail, "fragilestudiospk@gmail.com"]
    password = "ssnl iemy ycbu flks"
    if (send_Order(subject, body, recipients, sender, password) == True):
        print("sent!")
        cursor.execute("USE products;")
        print("got here")
        try:
            for id in idea:
                cursor.execute("SELECT "+id[2]+" FROM products WHERE id=%s", (id[0],))
                result = list(cursor.fetchone().values())[0]
                print(result, "\n\n\n the result")
                #for i in query:
                print("here")
                new = result - id[1]
                cursor.execute("UPDATE products SET "+id[2]+" = %s WHERE id = %s", (new,id[0]))
        except Exception as e:
            print("\n\n" ,e , "\n\n")
        mydb.commit()
        retProduct.cache_clear()
        cursor.close()
        return {0:200}
    return {0:400}

@app.route("/remAse", methods=['POST'])
def remAse():
    try:
        session["ordered"] = session["yourCart"]
        session.pop("yourCart", None)
    except Exception as e:
        print(e)
    return {0: 200}

@socketio.on("red")
@before_mid
def red(data):
    location = (data.split(',')[1]) # the location of the product
    userId = (data.split(',')[0])   # the user id which is ofc temp
    print(location, "this is product id")
    for i in location: # yes this is way beyond O(n) :(
        if (i == "?" or i == ";" or i == "\'" or i == "\""):
            print("I quit")
            socketio.emit(userId, {"ticker": '', "goKaraleva": "0"})
            return render_template('404.html')
    productId = location
    if len(location) == 0:
        productId = None
    try:
        v = request.headers.get("Pricemargin")
        category_id = request.headers.get("Authorization")
    except:
        v = ""
        category_id = ""
    products = retProduct(productId, userId, category_id, v)
    if products == None or products == []:
        socketio.emit(userId, {"ticker": '', "goKaraleva": "0"})
        return render_template('404.html')
    ret(userId, products, productId)
    return 200
#! ONCE IN LINUX SERVER PLZ ADD CACHING TO PREVENT (D)DOS ATTACKS!
'''
@app.before_request
def limit_remote_addr():
    ip = request.remote_addr
    cache_key = f"rate_limit:{ip}"
    try:
        requests = redis_client.incr(cache_key)
        if requests > 100:  # Allow 100 requests per hour
            return "Too many requests", 429
        elif requests == 1:
            redis_client.expire(cache_key, 3600)  # Set expiry for the key
    except redis.exceptions.ConnectionError as e:
        print(f"Redis connection error: {e}")
'''
#! ## ### #### ###### ######   ADMIN ACCESSABLE ONLY
import urllib
def dec__(payload, key_):
    return jwt.decode(payload, key_, algorithms=['HS256'])

pass_opp = "mypassword-thepassword_theWordtopasstheonepasswordto-cross"
thru = {"ip": "154.192.30.45"}#203.175.72.67
#223.123.86.14
#154.192.30.45
@app.route('/admin/product', methods=['GET', 'POST'])
def home_admin__():
    json_a = {}
    try:
        #external_ip = urllib.request.urlopen('https://ident.me').read().decode('utf8')
        external_ip = request.environ['HTTP_X_FORWARDED_FOR']
    except:
        print("wth the website shit")
        abort(403)
    file = os.path.join(os.getcwd()+'/hidden', "add_product.html")
    if request.method == 'POST':
        try:
            a = dec__(request.get_data(as_text=True), pass_opp)['0']
            json_a = json.loads(a)
            fn = int(dec__(json_a['3'], pass_opp)['0'])
            json_a['ip']
            json_a['0']
            json_a['1']
        except:
            abort(404)
        ip = (dec__(json_a['ip'], str(fn)))
        ip = (ip['0'])
        if external_ip == ip:
            thru["ip"] = ip
            return make_response(jsonify({0: 200}))
        abort(404)
    if (external_ip == thru["ip"]):
        data = "Whoops!"
        with open(file, "r") as fp:
            data = fp.read()
        bruce = make_response(data)
        token = generate_token(uuid.uuid4())
        session['mid2912'] = token
        bruce.set_cookie('mid2472', token, secure=True, httponly=True, max_age=timedelta(hours=3))
        return bruce
    abort(404)

@app.route('/admin/category', methods=['GET', 'POST'])
def category_admin__():
    json_a = {}
    #external_ip = urllib.request.urlopen('https://ident.me').read().decode('utf8')
    try:
        external_ip = request.environ['HTTP_X_FORWARDED_FOR']
    except:
        abort(404)
    print(external_ip)
    file = os.path.join(os.getcwd()+'/hidden', "add_category.html")
    if request.method == 'POST':
        try:
            a = dec__(request.get_data(as_text=True), pass_opp)['0']
            json_a = json.loads(a)
            fn = int(dec__(json_a['3'], pass_opp)['0'])
            json_a['ip']
            json_a['0']
            json_a['1']
        except:
            abort(404)
        ip = (dec__(json_a['ip'], str(fn)))
        ip = (ip['0'])
        if external_ip == ip:
            thru["ip"] = ip
            return make_response(jsonify({0: 200}))
        abort(404)
    if (external_ip == thru["ip"]):
        data = "Whoops!"
        with open(file, "r") as fp:
            data = fp.read()
        bruce = make_response(data)
        token = generate_token(uuid.uuid4())
        session['mid2912'] = token
        bruce.set_cookie('mid2472', token, secure=True, httponly=True, max_age=timedelta(hours=3))
        return bruce
    abort(404)

@before_mid
@socketio.on("request_product")
def request_pr(data):
    print(authed_user_admin())
    if (authed_user_admin() == True):
        mycursor = mydb.cursor(dictionary=True, buffered=True)
        mycursor.execute("USE products")
        id = str(uuid.uuid4())
        if (data["variation_id"] != ""):
            id = data['variation_id']+str(uuid.uuid4())[8:]
        mycursor.execute(f"""
        INSERT INTO products (id,name, description, price, quantity, category, img, belongs, xl, l, m, s) VALUES
        ('{id}','{data["name"]}', '{data["description"]}', {data["price"]}, {data["quantity"]}, '{data["category"]}', '{data["img"]}', '{data["belongs"]}', {data["xl"]}, {data["l"]}, {data["m"]}, {data["s"]});
        """)
        mydb.commit()
        mycursor.close()
        return make_response(jsonify({0: 200}))
    abort(403)

@lru_cache(maxsize=128)
def cachecategories():
    mycursor.execute("USE products")
    mycursor.execute(f"""SELECT category_id,name, img FROM category""")
    mycursor.fetchall()

# LIGHT REQUEST FOR CATEGORIES
#@memoized_admin
@before_event
@socketio.on("request_category_read")
def request_ca_read():
    if (authed_user_admin() == True):
        socketio.emit(request.cookies.get("evid")+"r", {0: cachecategories()})
        return make_response(jsonify({0: 200}))
    abort(403)

@lru_cache(maxsize=128)
def cachebelongings(cursor, belongs):
    cursor.execute("SET @rownum := 0, @main_category := '';")
    query = """
        SELECT id, name, description, discount, sizechart, price, img, belongs, category
        FROM (
            SELECT 
                id, 
                name, 
                description, 
                price,
                discount,
                sizechart,
                img, 
                belongs,
                category_also,
                category,
                SUBSTRING_INDEX(category, '.', 1) AS main_category,
                @rownum := IF(@main_category = SUBSTRING_INDEX(category, '.', 1), @rownum + 1, 1) AS rownum, 
                @main_category := SUBSTRING_INDEX(category, '.', 1)
            FROM 
                products
            WHERE 
                INSTR(belongs, %s) > 0
            ORDER BY 
                main_category, price
        ) AS subquery
        WHERE rownum <= 4;
        """
    cursor.execute(query, (belongs,))
    return cursor.fetchall()

@lru_cache(maxsize=128)
def cachedoes(cursor, data):
    cursor.execute("USE products")
    query = "SELECT EXISTS(SELECT 1 FROM category WHERE category_id = %s)"
    cursor.execute(query, (data,))
    result = cursor.fetchone()
    res = int(result[f'EXISTS(SELECT 1 FROM category WHERE category_id = \'{data}\')'])
    return res == 1

@lru_cache(maxsize=128)
def cachestuff(cursor):
    cursor.execute("SET @row_num = 0;")
    query = """
WITH product_positions AS (
    SELECT 
        id, name, description, price, discount, sizechart, img, belongs, category,
        ROW_NUMBER() OVER (ORDER BY id) AS row_num,
        COUNT(*) OVER () AS total_rows
    FROM products
)
SELECT id, name, description, price, discount, sizechart, img, belongs, category
FROM product_positions
WHERE 
    row_num = 1 OR
    row_num = total_rows OR
    row_num = (total_rows / 2) OR
    row_num = (total_rows / 2) + 1
ORDER BY row_num;
    """
    cursor.execute(query)
    return cursor.fetchall()

# LIGHT RESPONSE OF PRODUCTS
@before_event
@socketio.on("get_products_read")
def request_pr_read(data, nom):
    cursor = mydb.cursor(dictionary=True, buffered=True)
    exists = cachedoes(cursor, data)
    #print(exists, "the exists has spoken \n\n\n\n\n")
    #print(data is not None and exists == True and not(Invaliduuid12(data)), "the exists has spoken \n\n\n\n\n")
    if (data is not None and exists == True and not(Invaliduuid12(data))):
        #cursor.execute("SELECT id, name, description, price, img, belongs FROM products WHERE belongs=%s", (data,))
        r = cachebelongings(cursor, data)
        socketio.emit(request.cookies.get("evid")+"r", {0: json.loads(json.dumps(r, cls=DecimalEncoder)), 1: "b", 3: "", 2: nom, 6: data})
        cursor.close()
        return make_response(jsonify({0: 200}))
    r = cachestuff(cursor)
    #print(json.loads(json.dumps(r, cls=DecimalEncoder)), '-----------------------------------------')
    socketio.emit(request.cookies.get("evid")+"r", {0: json.loads(json.dumps(r, cls=DecimalEncoder)), 1: "b", 3: "", 2: nom})
    cursor.close()
    #abort(400)

@lru_cache(maxsize=128)
def bulkcache(cursor):
    cursor.execute(f"""SELECT category_id, price_margins, name, description, created_at, img FROM category""")
    r = cursor.fetchall()
    for result in r:
        #a = result['created_at'].strftime('%Y-%m-%d %H:%M:%S')
        now = datetime.now()
        time_difference = now - result['created_at']
        minutes = time_difference.seconds // 60
        hours = time_difference.seconds // 3600
        days = time_difference.days
        weeks = days // 7
        result['created_at'] = [f"{minutes}.minutes", f"{hours}.hour(s)", f"{days}.day(s)", f"{weeks}.week/s"]
    return r
import functools

def cache_rea(func):
    cache_dict = {}

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Create a key based on the function arguments
        key = (args, tuple(kwargs.items()))
        if key in cache_dict:
            #print(f"Returning cached result for {func.__name__} with args {args} and kwargs {kwargs}")
            return cache_dict[key]
        else:
            result = func(*args, **kwargs)
            cache_dict[key] = result
            #print(f"Caching result for {func.__name__} with args {args} and kwargs {kwargs}")
            return result
    return wrapper

@cache_rea
def cachestuff2(cursor, row_id, pm):
    cursor.execute(f"""SELECT price_margins, name, description, img FROM category WHERE category_id='{row_id}'""")
    return cursor.fetchall()

def cachemargins(cursor):
    cursor.execute(f"""SELECT price_margins FROM category""")
    return cursor.fetchall()

# BULK RESPONSE FOR CATEGORIES
@before_event
@socketio.on("get_category_read")
def request_ca_read(data):
    cursor = mydb.cursor(dictionary=True, buffered=True)
    cursor.execute("USE products")
    if (data == "alldata_"):
        r = bulkcache(cursor)   
        socketio.emit(request.cookies.get("evid")+"r", {0: r, 1: "a", 2: "all_sidebar"})
        cursor.close()
        return make_response(jsonify({0: 200}))
    row_id = request.headers.get('Authorization')
    pm = request.headers.get('Pricemargin')
    exists = cachedoes(cursor, row_id)
    if (row_id is not None and exists == True and not(Invaliduuid12(row_id))):
        r = cachestuff2(cursor, row_id, pm)
        #print(r)
        socketio.emit(request.cookies.get("evid")+"r", {0: r, 1: "a", 2: ""})
        cursor.close()
        return make_response(jsonify({0: 200}))
    r = cachemargins(cursor)
    socketio.emit(request.cookies.get("evid")+"r", {0: r, 1: "b", 2: ""})
    cursor.close()
    del r, exists, res
    #abort(400)

@before_mid
@socketio.on("request_category")
def request_ca(data):
    print(authed_user_admin())
    if (authed_user_admin() == True):
        mycursor.execute("USE products")
        id = str(uuid.uuid4())[:13]
        mycursor.execute(f"""
        INSERT INTO category (category_id,name, description, price_margins, img) VALUES
        ('{id}','{data["name"]}', '{data["description"]}', '{data["price_ranges"]}', '{data["img"]}');
        """)
        print("Done adding this stuff - - - -  - -- - - - -- - - -- - - - - ")
        mydb.commit()
        return make_response(jsonify({0: 200}))
    abort(403)
    
@before_mid
@app.route("/logout", methods=['POST'])
def logout__():
    response = make_response(jsonify({0: "200"}))
    if request.cookies.get('evid') == None:
        response.set_cookie('evid', str(uuid.uuid4()), secure=True)
    response.set_cookie("id", "9fa7bcea0-c2t50-48611-b8av8b-8bc761d2bdpbb")
    print("logged out")
    return response

@app.route("/credits")
def credits():
    return render_template("credits.html")

@app.route("/")
def tohome():
    return redirect("/home")
@app.route("/explore")
def tohome_():
    return redirect("/home")
@app.route("/shop")
def tohome__():
    return redirect("/home")

@app.route('/payload', methods=['GET', 'POST'])
@before_mid
def upload_file():
    if request.method == 'POST':
        if (authed_user_admin):
            file = request.files['xhr2upload'] # [0]
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                current_path = os.path.dirname(__file__)
                file_ = (str(uuid.uuid4())+"."+filename.split(".")[1])
                file.save(os.path.join(current_path+"/root/static/products/"+file_))

                return make_response(jsonify({0: file_}))
            abort(404)
        abort(404)
    abort(404)

def authed_user_admin():
    external_ip = ""
    try:
        external_ip = request.environ['HTTP_X_FORWARDED_FOR']
    except:
        abort(404)
    if (external_ip == thru["ip"]):
        return True
    return False
'''

inventory = {
    'product1': 10,
    'product2': 20,
    # Add more products here
}

# Establish connection to RabbitMQ
connection = pika.BlockingConnection(pika.ConnectionParameters('127.0.0.1', 5000))
channel = connection.channel()
channel.queue_declare(queue='order_queue')

@app.route('/place_order', methods=['POST'])
def place_order():
    # Get order data from the request
    order_data = request.json
    
    # Validate order data (e.g., check if required fields are present)
    if not order_data or 'product' not in order_data or 'quantity' not in order_data:
        return jsonify({'error': 'Invalid order data'}), 400
    
    product = order_data['product']
    quantity = order_data['quantity']
    
    # Check if the product is available in inventory
    if product not in inventory or inventory[product] < quantity:
        return jsonify({'error': 'Product not available or insufficient quantity'}), 400
    
    # Send order data to RabbitMQ for further processing
    channel.basic_publish(exchange='',
                          routing_key='order_queue',
                          body=json.dumps(order_data))
    
    return jsonify({'message': 'Order placed successfully'}), 200

def process_order(ch, method, properties, body):
    order_data = json.loads(body)
    product = order_data['product']
    quantity = order_data['quantity']
    
    # Process the order (e.g., update inventory, save order to database, send notifications)
    inventory[product] -= quantity
    
    # Dummy: Save order data to a database
    # Your code to save order data to the database goes here
    
    # Dummy: Send order confirmation email
    # Your code to send order confirmation email goes here
    
    print("Order processed:", order_data)

# Consume messages from the order queue
channel.basic_consume(queue='order_queue',
                      on_message_callback=process_order,
                      auto_ack=True)
'''
#context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
#context.load_cert_chain(certfile='cert/ALDsigning.crt', keyfile='cert/ALDsigning.key')
#esbf235824nv1x825 TEMPORARY ofc serverkey pass
if __name__ == '__main__':
    context = SSLContext(PROTOCOL_TLS)

    # Load the certificate and private key
    context.load_cert_chain(certfile='/etc/letsencrypt/live/fragilestudiospk.com/fullchain.pem',
                            keyfile='/etc/letsencrypt/live/fragilestudiospk.com/privkey.pem')

    # Optional: Set additional SSL context options if needed
    context.verify_mode = ssl.CERT_NONE  # Adjust as needed, e.g., ssl.CERT_REQUIRED for client authentication
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Disable older TLS versions if desired

    server = pywsgi.WSGIServer(('0.0.0.0', 8000), app, handler_class=pywsgi.WSGIHandler, ssl_context=context)
    server.serve_forever()

