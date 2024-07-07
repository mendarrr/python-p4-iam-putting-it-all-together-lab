#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

@app.before_request
def before_request():
    open_access_list=[
        'signup',
        'login',
        'check_session'
    ]

    if request.endpoint not in open_access_list and (not session.get('user_id')):
        return {'error': '401 Unauthorized'}, 401

class Signup(Resource):
    def post(self):
        request_json = request.get_json()

        username = request_json.get('username')
        password = request_json.get('password')
        image_url = request_json.get('image_url')
        bio = request_json.get('bio')

        user = User(
            username=username,
            image_url=image_url,
            bio=bio
        )

        # the setter will encrypt this
        user.password_hash = password

        try:
            db.session.add(user)
            db.session.commit()

            session['user_id'] = user.id

            return user.to_dict(), 201

        except IntegrityError:
            return {'error': '422 Unprocessable Entity'}, 422

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'No active session'}, 401

        with db.session.no_autoflush:
            user = db.session.get(User, user_id)
            if not user:
                return {'error': 'User not found'}, 404

        return user.to_dict(), 200

class Login(Resource):
    def post(self):
        request_json = request.get_json()
        if not request_json:
            return {'error': 'Missing request data'}, 400

        username = request_json.get('username')
        password = request_json.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200
        else:
            return {'error': '401 Unauthorized'}, 401

class Logout(Resource):
    def delete(self):
        session['user_id'] = None
        return {}, 204

class RecipeIndex(Resource):

    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Not logged in'}, 401

        try:
            with db.session.no_autoflush:
                user = db.session.get(User, user_id)
                if not user:
                    return {'error': 'User not found'}, 404

            recipes = [recipe.to_dict() for recipe in user.recipes]
            return {'recipes': recipes}, 200
        except Exception as e:
            return {'error': str(e)}, 500

    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Not logged in'}, 401

        try:
            with db.session.no_autoflush:
                user = db.session.get(User, user_id)
                if not user:
                    return {'error': 'User not found'}, 404

            data = request.get_json()
            title = data.get('title')
            instructions = data.get('instructions')
            minutes_to_complete = data.get('minutes_to_complete')

            if not title or not instructions or not minutes_to_complete:
                return {'error': 'Title, instructions, and minutes_to_complete are required'}, 422

            if len(instructions) < 50:
                return {'error': 'Instructions must be at least 50 characters long'}, 422

            recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user=user
            )

            db.session.add(recipe)
            db.session.commit()

            return recipe.to_dict(), 201

        except ValueError as e:
            return {'error': str(e)}, 422
        except Exception as e:
            return {'error': str(e)}, 500


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
