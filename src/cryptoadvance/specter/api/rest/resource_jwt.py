import jwt
from flask import current_app as app
from flask_restful import Api, abort, reqparse
from cryptoadvance.specter.api.rest.base import (
    BaseResource,
    rest_resource,
    AdminResource,
)
import uuid
import datetime
import logging
from ...user import *
from .base import *

from .. import auth

logger = logging.getLogger(__name__)

parser = reqparse.RequestParser()
parser.add_argument("jwt_token_description", type=str, help="JWT token description", required = True)

def generate_jwt(user):
    """ Generate a JWT for the user """
    payload = {
        "user": user.username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1),
    }
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")

def generate_token_id():
    """ Generate a random token id """
    return str(uuid.uuid4())

@rest_resource
class ResourceJWT(SecureResource):
    """
      A Resource to manage JWT tokens in order to authenticate against the REST-API
      Other then the other Resources, this endpoint uses BasicAuth to avoid the chicken egg problem
      This one is only to create a token. The other Resource for getting and deleting.
      This violates the REST principles but only on the implementation-side. Happy for improvements here.
    """
    endpoints = ["/v1alpha/token/"]

    def post(self):
        # An endpoint to get all JWT tokens created by the user
        user = auth.current_user()
        user_details = app.specter.user_manager.get_user(user)
        jwt_token_descriptions = user_details.jwt_token_descriptions
        return_dict = {
            "jwt_token_descriptions": jwt_token_descriptions,
        }
        return_dict["jwt_token_descriptions"]=user_details.get_all_jwt_token_descriptions()
        jwt_token_descriptions = return_dict["jwt_token_descriptions"]
        if len(jwt_token_descriptions) == 0:
            return {"message": "Token does not exist"}, 404
        return {"message": "Tokens exists", "jwt_token_descriptions": jwt_token_descriptions}, 200

    def post(self):
        user = auth.current_user()
        data = parser.parse_args()
        user_details = app.specter.user_manager.get_user(user)
        jwt_token = user_details.jwt_token
        jwt_token_id = user_details.jwt_token_id
        jwt_token_description = user_details.jwt_token_description
        jwt_token_descriptions = user_details.jwt_token_descriptions
        return_dict = {
            "username": user_details.username,
            "id": user_details.id,
            "jwt_token_id": jwt_token_id,
            "jwt_token": jwt_token,
            "jwt_token_description": jwt_token_description,
            "jwt_token_descriptions": jwt_token_descriptions,
        }
        return_dict["jwt_token_id"] = generate_token_id()
        return_dict["jwt_token"] = generate_jwt(user_details)
        return_dict["jwt_token_description"] = data["jwt_token_description"]
        jwt_token_id = return_dict["jwt_token_id"]
        jwt_token = return_dict["jwt_token"]
        jwt_token_description = return_dict["jwt_token_description"]
        jwt_token_descriptions = return_dict["jwt_token_descriptions"]

        user_details.save_jwt_token(jwt_token_id, jwt_token, jwt_token_description)
        user_details.append_jwt_token(jwt_token_id, jwt_token)
        user_details.append_jwt_token_description(jwt_token_id, jwt_token_description)
            
        return {
                "message": "Token generated",
                "username": user_details.username,
                "created_jwt_token_id": jwt_token_id,
                "created_jwt_token": jwt_token,
                "jwt_token_description": jwt_token_description,  
            }, 201

@rest_resource
class ResourceJWTById(SecureResource):
    """ A Resource to manage individual JWT token
    """
    endpoints = ["/v1alpha/token/<jwt_token_id>/"]

    def post(self, jwt_token_id):
        user = auth.current_user()
        user_details = app.specter.user_manager.get_user(user)
        jwt_token_descriptions = user_details.jwt_token_descriptions
        return_dict = {
            "jwt_token_descriptions": jwt_token_descriptions,
        }
        return_dict["jwt_token_descriptions"]=user_details.get_all_jwt_token_descriptions()
        jwt_token_descriptions = return_dict["jwt_token_descriptions"]
        if jwt_token_descriptions[jwt_token_id] is None:
            return {"message": "Token does not exist"}, 404
        return {"message": "Tokens exists", "jwt_token_description": jwt_token_descriptions[jwt_token_id]}, 200

    def delete(self, jwt_token_id):
        user = auth.current_user()
        user_details = app.specter.user_manager.get_user(user)
        jwt_tokens = user_details.jwt_tokens
        if jwt_tokens[jwt_token_id] is None:
            return {"message": "Token does not exist"}, 404
        user_details.delete_jwt_token(jwt_token_id)
        return {"message": "Token deleted"}, 200
