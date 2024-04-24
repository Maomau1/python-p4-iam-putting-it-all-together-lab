#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError


from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    
    def post(self):
        try:
            new_user = User(
                username = request.get_json().get('username'),
                image_url = request.get_json().get('image_url'), 
                bio = request.get_json().get('bio'),
            )
            new_user.password_hash = request.get_json()['password']
            # breakpoint()
            db.session.add(new_user)
            db.session.commit()
            
            session['user_id']=new_user.id
             
            return (new_user.to_dict(), 201)
        except:
                return {'errors':['user not valid']}, 422

class CheckSession(Resource):
    
    def get(self):
        user_id = session['user_id']
        if user_id:
                user = User.query.filter(User.id == session['user_id']).first()
                # breakpoint()
                if user:
                    return user.to_dict()
                return {'message': '401: Not Authorized'}, 401
        else:
            return {}, 401

class Login(Resource):
    
    def post(self):
        username = request.get_json().get('username')
        user = User.query.filter(
            User.username == username).first()
        password = request.get_json().get('password')
        # breakpoint()
        if user:
            if user.authenticate(password):
                session['user_id'] = user.id
                return user.to_dict(), 200
        
        return('message:invalid user', 401)


class Logout(Resource):
     
    def delete(self):
        if session['user_id']:
            session['user_id'] = None
            return {}, 204 
        return {}, 401 

# @app.before_request
# def check_if_logged_in(): 
#     if not session.get('user_id'):
#         return {'error': 'Unauthorized'}, 401

class RecipeIndex(Resource):
        
    def get(self):

        if not session.get('user_id'):
            return {'error':'Unauthorized'}, 401
        
        recipes = Recipe.query.all()
        return [recipe.to_dict() for recipe in recipes], 200
    
    def post(self):
        if not session.get('user_id'):
            return {'error': 'Unauthorized'}, 401
        try:
            new_recipe = Recipe(
                title = request.get_json().get('title'),
                instructions = request.get_json().get('instructions'),
                minutes_to_complete = request.get_json().get('minutes_to_complete'),
                user_id = session['user_id'],
            )
            db.session.add(new_recipe)
            db.session.commit()
            new_recipe.user = User.query.filter(
                User.id == session['user_id']).first()
            # breakpoint()
            return new_recipe.to_dict(),201
        except:
            return {'errors':['user not valid']}, 422

        


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)