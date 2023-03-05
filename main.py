"""
import all required modal :

"""

from flask import Flask, jsonify, make_response, request
from werkzeug.security import generate_password_hash,check_password_hash
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import uuid
import jwt
import datetime



"""

setup my server : 

"""

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='sqlite://///bookstore.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

my_db = SQLAlchemy(app)



"""
Create My  database models / tables : 

"""

class Users(my_db.Model):
	id = my_db.Column(my_db.Integer,primary_key=True)
	public_id = my_db.Column(my_db.Integer)
	name = my_db.Column(my_db.String(50))
	password = my_db.Column(my_db.String(50))
	admin = my_db.Column(my_db.Boolean)



class Books(my_db.Model):
	id = my_db.Column(my_db.Integer,primary_key=True)
	user_id = my_db.Column(my_db.Integer,my_db.ForeignKey('users.id'),nullable=False)
	name = my_db.Column(my_db.String(50),nullable=False,unique=True)
	Author = my_db.Column(my_db.String(50), unique=True, nullable=False)
	Publisher = my_db.Column(my_db.String(50), nullable=False)
	book_prize = my_db.Column(my_db.Integer)


# add function to validate token : 
def token_required(f):
	@wraps(f)
	def decorator(*args, **kwargs):
		token = None
		if 'x-access-tokens' in request.headers:
			token = request.headers['x-access-tokens']
		if not token:
			return jsonify({'message': 'a valid token is missing'})
		try:
			data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
			current_user = Users.query.filter_by(public_id=data['public_id']).first()
		except:
			return jsonify({'message': 'token is invalid'})
		return f(current_user, *args, **kwargs)
	return decorator


# All Users Routers :    



@app.route('/register', methods=['POST'])
def signup_user(): 
	data = request.get_json() 
	hashed_password = generate_password_hash(
				data['password'],
				method='sha256'
	)
	new_user = Users(public_id=str(uuid.uuid4()), 
					name=data['name'], 
					password=hashed_password, 
					admin=False)
	my_db.session.add(new_user) 
	my_db.session.commit()   
	return jsonify({'message': 'registered successfully'})


@app.route('/login', methods=['POST']) 
def login_user():
	auth = request.authorization  
	if not auth or not auth.username or not auth.password: 
		return make_response('could not verify', 401, {'Authentication': 'login required"'})   
	user = Users.query.filter_by(name=auth.username).first()  
	if check_password_hash(user.password, auth.password):
		token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=45)}, app.config['SECRET_KEY'], "HS256")
		return jsonify({'token' : token})
	return make_response('could not verify',  401, {'Authentication': '"login required"'})


@app.route('/users', methods=['GET'])
def get_all_users(): 
	users = Users.query.all()
	result = []  
	for user in users:  
		user_data = {}  
		user_data['public_id'] = user.public_id 
		user_data['name'] = user.name
		user_data['password'] = user.password
		user_data['admin'] = user.admin
		result.append(user_data)  
	return jsonify({'users': result})



# All Books Routers : 

@app.route('/book', methods=['POST'])
@token_required
def create_book(current_user):
	# get data : 
	data = request.get_json()
	# create new Book instance : 
	new_books = Books(name=data['name'], Author=data['Author'], Publisher=data['Publisher'], book_prize=data['book_prize'], user_id=current_user.id) 
	# add to database : 
	my_db.session.add(new_books)
	# save :  
	my_db.session.commit() 
	return jsonify({'message' : 'new books created'})




@app.route('/books',methods=['GET'])
@token_required
def get_books(current_user):
	books = Books.query.filter_by(user_id=current_user.id).all()
	output = []
	for book in books:
		book_data = {}
		book_data['id'] = book.id
		book_data['name'] = book.name
		book_data['Author'] = book.Author
		book_data['Publisher'] = book.Publisher
		book_data['book_prize'] = book.book_prize
		output.append(book_data)
	return jsonify({'list_of_books' : output})


@app.route('/books/<book_id>', methods=['DELETE'])
@token_required
def delete_book(current_user, book_id):
	book = Books.query.filter_by(id=book_id, user_id=current_user.id).first()  
	if not book:  
		return jsonify({'message': 'book does not exist'})  
	my_db.session.delete(book) 
	my_db.session.commit()  
	return jsonify({'message': 'Book deleted'})





# setup : 
if __name__ == '__main__':
	# run our server : 
	app.config['SECRET_KEY']='004f2af45d3a4e161a7dd2d17fdae47f'
	app.config['SESSION_TYPE'] = 'filesystem'
	with app.app_context():
		my_db.create_all()
	app.run(debug=True)