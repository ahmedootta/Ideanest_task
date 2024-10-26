from flask import Flask, render_template, request
from pymongo import MongoClient
from dotenv import load_dotenv
import os

app = Flask(__name__)

load_dotenv()

# Directly use the MongoDB URI
MONGO_URI = os.environ["MONGO_URI"]
client = MongoClient(MONGO_URI, ssl=True, tls=True)

# Uncomment this to see all databases in your cluster
for db_name in client.list_database_names():
    print(db_name)    

@app.route('/')  # Corrected the typo here
def index():
    return render_template("index.html")  

@app.route('/signup')  # Corrected the typo here
def signup():
    return render_template("signup.html")  

@app.route('/signin')  # Corrected the typo here
def signin():
    return render_template("signin.html")  



if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=8080)  # Run on port 8080 and bind to all interfaces

