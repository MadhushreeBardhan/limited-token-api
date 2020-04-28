"""
Registaration of user 0 tokens
each user gets 10 tokens
store a sentence on our database for 1 token
Retrieve his stored sentence on our database for 1 token
"""
from flask import Flask,jsonify,request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
from flask_bcrypt import Bcrypt

app = Flask(__name__)
api = Api(app)
client = MongoClient("mongodb://localhost:27017/")
db = client.SentencesDatabase                          # create a new DB named as aNewDB
users = db["users"]

class Register(Resource):
    def post(self):
#step1 is to get the posted data by the user
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]
#hash(password + salt) = djhghgdhbfhgwefg
        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
# store username and pw into the database

        users.insert({
            "Username": username,
            "Password": hashed_pw,
            "sentence": "",
            "Tokens":6
        })
        retJson = {
            "status": 200,
            "msg": "you successfully signed up for the Api"
        }
        return jsonify(retJson)
def verifyPw(username,password):
    hashed_pw = users.find({
        "Username":username
    })[0]["Password"]
    if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
        return True
    else:
        return False
def countTokens(username):
    tokens = users.find({
        "Username":username
    })[0]["Tokens"]
    return tokens


class Store(Resource):
    def post(self):
#         step 1 get the posted data
        postedData = request.get_json()
#         step to to read the data
        username = postedData["username"]
        password = postedData["password"]
        sentence = postedData["sentence"]

        # step 3 verify the username and the password matching
        correct_pw = verifyPw(username, password)
        if not correct_pw:
            retJson = {
                "status":302
            }
            return jsonify(retJson)
        #  step 4 varify user has enough token

        num_tokens = countTokens(username)
        if  num_tokens <= 0:
            retJson = {
                "status":301
            }
            return jsonify(retJson)
#         step5 store the sentense and return 200k
        users.update({
            "Username":username
        },{
            "$set":{"Sentence":sentence,
                    "Tokens":num_tokens-1
                    }
        } )
        retJson = {
            "status":200,
            "msg":"sentence saved successfully"
        }
        return jsonify(retJson)

class Get(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]
        correct_pw = verifyPw(username, password)
        if not correct_pw:
            retJson = {
                "status": 302
            }
            return jsonify(retJson)

        num_tokens = countTokens(username)
        if num_tokens <= 0:
            retJson = {
                "status": 301
            }
            return jsonify(retJson)
        # make the user pay
        users.update({
            "Username": username
        }, {
            "$set": {
                     "Tokens": num_tokens - 1
                     }
        })


        sentence = users.find({
            "Username":username,
        })[0]["sentence"]
        retJson = {
            "status":200,
            "sentence": "this is a super secret sentence"
        }
        return jsonify(retJson)


api.add_resource(Register, '/register')
api.add_resource(Store,'/store')
api.add_resource(Get,'/get')
if __name__ == "__main__":
    app.run(debug=True,port=1234)

