from flask import Flask, request, jsonify, json, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash,check_password_hash
from functools import wraps
import jwt
import datetime
from uuid import uuid4

db = SQLAlchemy()
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root@localhost/taskApi'
app.config['SECRET_KEY'] = '004f2af45d3a4e161a7dd2d17fdae47f'
db.init_app(app)

def token_required(f):
   @wraps(f)
   def decorator(*args, **kwargs):
       token = None
       if 'authorization' in request.headers:
           token = request.headers['authorization'].split(' ')[1]
 
       if not token:
           return jsonify({'message': 'a valid token is missing'})
       try:
           data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
           current_user = User.query.filter_by(public_id=data['public_id']).first()
       except:
           return jsonify({'message': 'token is invalid'})
 
       return f(current_user, *args, **kwargs)
   return decorator

class User(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  public_id = db.Column(db.Integer)
  username = db.Column(db.String(60), unique=True, nullable=False)
  password = db.Column(db.String(255), nullable=False)

with app.app_context():
  db.create_all()

@app.errorhandler(HTTPException)
def handle_exception(e):
    """Return JSON instead of HTML for HTTP errors."""
    # start with the correct headers and status code from the error
    response = e.get_response()
    # replace the body with JSON
    response.data = json.dumps({
        "code": e.code,
        "name": e.name,
        "description": e.description,
    })
    response.content_type = "application/json"
    return response

@app.route('/')
def index():
  return jsonify({
    'name': 'status',
    'message': 'Ok'
  }), 200

@app.route('/register', methods=['POST'])
def register():
  request_data = request.get_json()
  hashed_password = generate_password_hash(request_data['password'], method='sha256')
  user = User(
    public_id=str(uuid4()),
    username=request_data['username'],
    password=hashed_password,
  )
  db.session.add(user)
  db.session.commit()
  return jsonify({}), 201

@app.route('/login', methods=['POST']) 
def login_user():
   auth = request.get_json()
   user = User.query.filter_by(username=auth['username']).first()
   if check_password_hash(user.password, auth['password']):
       token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=45)}, app.config['SECRET_KEY'], "HS256")
 
       return jsonify({'token' : token})
 
   return make_response('could not verify',  401, {'Authentication': '"login required"'})

@app.route('/protected', methods=['GET'])
@token_required
def protected(current_user):
  return make_response('Ok', 200)

app.run(debug=True)