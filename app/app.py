from flask import Flask, render_template, request, url_for, flash, redirect, session, jsonify
from pymongo import MongoClient
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token
from flask_jwt_extended import jwt_required, get_jwt_identity
from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash
from bson import ObjectId
import json
import datetime
import os


app = Flask(__name__)
app.secret_key = "IdeanestTask"
app.config['JWT_SECRET_KEY'] = os.environ['SECRET_KEY']

# Initialize JWTManager **AFTER** setting the configuration
jwt = JWTManager(app)


load_dotenv()

# Directly use the MongoDB URI
MONGO_URI = os.environ["MONGO_URI"]
client = MongoClient(MONGO_URI, ssl=True, tls=True)

db = client.Ideanest
members_collection = db.members
organizations_collection = db.organizations

@app.route('/') 
def index():
    return render_template("index.html")  

# ----------------------------------------------------------

@app.route('/signup', methods=['GET', 'POST'])  
def signup():
    if request.method == "POST":
        # TEST THROUGH POSTMAN
        if request.is_json:
            data = request.get_json()
            name = data.get('name')
            email = data.get('email')
            password = data.get('password')
            r_password = data.get('r_password')
            access_level = data.get('role')
            if password == r_password:
                exist_user = members_collection.find_one({'email': email})
                if exist_user:
                    return jsonify({"Error": "User already exists!"})

                else:    
                    new_member = {
                        'name': name,
                        'email': email,
                        'password': generate_password_hash(password),
                        'access_level': access_level
                    }
                
                    try:
                        members_collection.insert_one(new_member)
                        return("You are successfully registered!", 'success')
                    except Exception as e:
                        return("An error occurred while registering: {}".format(str(e)), 'error')

            else:
                return jsonify({"Error": "Password-confirmation doesn't match password!"})
        
# -----------------------------------------------------------------------------------------------------------
        # TEST THROUGH HTML PAGES "frontend"
        else:    
            name = request.form.get('name')
            email = request.form.get('email')
            password = request.form.get('password')
            r_password = request.form.get('r_password')
            access_level = request.form.get('role')
            if password == r_password:
                exist_user = members_collection.find_one({'email': email})
                if exist_user:
                    flash("User already exists!", 'error')
                    return redirect(url_for('signup'))  
                else:    
                    new_member = {
                        'name': name,
                        'email': email,
                        'password': generate_password_hash(password),
                        'access_level': access_level
                    }
                
                    # members_collection.insertOne(new_member) 
                    try:
                        members_collection.insert_one(new_member)
                        flash("You are successfully registered!", 'success')
                        return redirect(url_for('signin'))  # Redirect to sign-in after successful registration
                    except Exception as e:
                        flash("An error occurred while registering: {}".format(str(e)), 'error')
                        return redirect(url_for('signup')) 

            else:
                flash("Password-confirmation doesn't match password!", 'error')
                return redirect(url_for('signup'))   
    else:    
        return render_template("signup.html")  
    
# ----------------------------------------------------------------------------------

@app.route('/signin', methods=['GET', 'POST'])  
def signin():
    if request.method == "POST":
        # Test in postman through json-format
        if request.is_json:
            data = request.get_json()
            email = data.get('email')
            password = data.get('password')
        else:
            # For form submission through HTML pages
            email = request.form.get('email')
            password = request.form.get('password')

        # Check if user exists
        user = members_collection.find_one({'email': email})
        
        if user and check_password_hash(user['password'], password):  
            # Generate tokens (example using JWT)
            access_token = create_access_token(identity=str(user['_id']), expires_delta=datetime.timedelta(minutes=30))
            refresh_token = create_refresh_token(identity=str(user['_id']), expires_delta=datetime.timedelta(days=30))
            
            return jsonify({
                "message": "Login successful!",
                "access_token": access_token,
                "refresh_token": refresh_token,
                "status": "success"
            }), 200
        else:
            return jsonify({
                "message": "Invalid email or password!",
                "status": "error"
            }), 401  # Unauthorized status code
    else:    
        return render_template("signin.html")   

@app.route('/refresh-token', methods=['POST'])
@jwt_required(refresh=True)  # Ensure only a refresh token can access this endpoint
def refresh_token():
    # Step 1: Extract user identity from the refresh token
    current_user_id = get_jwt_identity()  # This gets the user_id from the token's "sub" claim
    
    # Step 2: Generate new access and refresh tokens
    new_access_token = create_access_token(identity=current_user_id)
    new_refresh_token = create_refresh_token(identity=current_user_id)
    
    # Step 3: Return the new tokens in JSON format
    return jsonify({
        "message": "Tokens refreshed successfully",
        "access_token": new_access_token,
        "refresh_token": new_refresh_token
    }), 200
          
#-----------------------------------------------------------------------------------------------
#-----------------------------------------------------------------------------------------------

@app.route('/organization', methods=['POST'])
@jwt_required()  # Ensure only a refresh token can access this endpoint
def create_organization():
   ...
   if request.method == "POST":
        # Test in postman through json-format
        if request.is_json:
            data = request.get_json()
            name = data.get('name')
            description = data.get('description')
            # Optional field, set to an empty list if not provided
            organization_members = data.get('organization_members', [])

            # Create new organization document
            new_organization = {
                "name": name,
                "description": description,
                "organization_members": organization_members  # Can be empty
            }
            
            try:
                organization_id = organizations_collection.insert_one(new_organization).inserted_id
                return jsonify({
                        "organization_id": str(organization_id),
                        "message": "Organization created successfully!"
                    }), 201
            except Exception as e:
                return (f"Error: {str(e)}")


@app.route('/organization/<id>', methods=['GET'])
@jwt_required()
def get_organization(id):
    try:    
        target_organization = organizations_collection.find_one({'_id': ObjectId(id)})
        organization_members_Ids = target_organization['organization_members']
        organization_members_dics = []
        for id in organization_members_Ids:
            user = members_collection.find_one({"_id": ObjectId(id)})
            user_dic = {
                "name": user['name'],
                "email": user['email'],
                "access_level": user['access_level'],
            }
            organization_members_dics.append(user_dic)
            
        return jsonify({
            "Target_organization": {
                "id": str(target_organization['_id']),
                "name": target_organization.get('name'),
                "description": target_organization.get('description'),
                "organization_members": organization_members_dics
            },
        })
    except Exception as e:
        return (f"Error: {str(e)}")    
    

@app.route('/organization', methods=['GET'])
@jwt_required()
def get_all_organizations():
    try:    
        all_organizations = organizations_collection.find()
        final_result = []
        for organization in all_organizations:
            ...
            organization_members_Ids = organization['organization_members']
            organization_members_dics = []
            for id in organization_members_Ids:
                user = members_collection.find_one({"_id": ObjectId(id)})
                user_dic = {
                    "name": user['name'],
                    "email": user['email'],
                    "access_level": user['access_level'],
                }
                organization_members_dics.append(user_dic)

            organize_dic = {
                "id": str(organization['_id']),
                "name": organization.get('name'),
                "description": organization.get('description'),
                "organization_members": organization_members_dics
            }

            final_result.append(organize_dic)   


        return jsonify({
            "All_organizationa": final_result,
        })
    except Exception as e:
        return (f"Error: {str(e)}")    
    


@app.route('/organization/<id>', methods=['DELETE'])
@jwt_required()
def delete_organization(id): # delete organization if user-role: 'Admin' only.....besides Access token
    current_user_id = get_jwt_identity()
    logged_user = members_collection.find_one({"_id": ObjectId(current_user_id)})
    if logged_user['access_level'] == 'Admin':
        try:
            organizations_collection.delete_one({"_id": ObjectId(id)})
            return jsonify({
                    "message": "Organization deleted!"
                }), 201
        except Exception as e:
            return (f"Error: {str(e)}")
    else:
        return jsonify({
                "error": "Unauthourized to delete organization!"
            }), 201            


@app.route('/organization/<id>', methods=['PUT'])
@jwt_required()
def update_organization(id): # delete organization if user-role: 'Admin' only.....besides Access token

    current_user_id = get_jwt_identity()
    logged_user = members_collection.find_one({"_id": ObjectId(current_user_id)})

    if logged_user['access_level'] == 'Admin':
        if request.is_json:
            data = request.get_json()
            updated_data = {
                'name': data.get('name'),
                'description': data.get('description'),
            }
        try:
            result = organizations_collection.update_one(
                {'_id': ObjectId(id)}, 
                {'$set': updated_data}  
            )
            updated_organization = organizations_collection.find_one({'_id': ObjectId(id)})
            return jsonify({
                "updated_organization": {
                    "id": str(updated_organization['_id']),
                    "name": updated_organization.get('name'),
                    "description": updated_organization.get('description')
                },
                "message": "Organization updated successfully!"
            }), 201
        except Exception as e:
            return (f"Error: {str(e)}")
    else:
        return jsonify({
                "error": "Unauthourized to update organization!"
            }), 201            

@app.route("/organization/<id>/invite", methods=['POST'])
@jwt_required()
def invite(id):
    if request.is_json:
        data = request.get_json() 

    invited_user = members_collection.find_one({"email": data.get('user_email')})  
    target_organization = organizations_collection.find_one({'_id': ObjectId(id)})  
    if invited_user:
        return f"{invited_user['name']} Have been invited to {target_organization['name']}"



if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=8080)  # Ensure debug is set to True


