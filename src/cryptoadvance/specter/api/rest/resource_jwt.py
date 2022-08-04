import jwt
from flask import current_app as app
from flask_restful import Api, abort, reqparse
from cryptoadvance.specter.api.rest.base import (
    BaseResource,
    BasicAuthResource,
    SecureResource,
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

# Initialize the parser
parser = reqparse.RequestParser()
parser.add_argument(
    "jwt_token_description", type=str, help="JWT token description", required=True
)


def generate_jwt(user, jwt_token_id, jwt_token_description):
    # Generates a JWT token for the user
    payload = {
        "user": user.username,
        "jwt_token_id": jwt_token_id,
        "description": jwt_token_description,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1),
    }
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")


def generate_token_id():
    # Generates a unique token id
    return str(uuid.uuid4())


@rest_resource
class ResourceJWT(BasicAuthResource):
    """
    A Resource to manage JWT tokens in order to authenticate against the REST-API
    Other then the other Resources, this endpoint uses BasicAuth to avoid the chicken egg problem
    This one is only to create a token. The other Resource for getting and deleting.
    This violates the REST principles but only on the implementation-side. Happy for improvements here.
    """

    endpoints = ["/v1alpha/token/"]

    def get(self):
        # An endpoint to get all JWT tokens' information created by the user
        user = auth.current_user()
        user_details = app.specter.user_manager.get_user(user)
        jwt_tokens = user_details.get_all_jwt_token_ids_and_descriptions()
        if len(jwt_tokens) == 0:
            return {"message": "Token does not exist"}, 404
        return {"message": "Tokens exists", "jwt_tokens": jwt_tokens}, 200

    def post(self):
        # An endpoint to create a JWT token
        user = auth.current_user()
        data = parser.parse_args()
        user_details = app.specter.user_manager.get_user(user)
        jwt_token_id = generate_token_id()
        jwt_token_description = data["jwt_token_description"]
        jwt_token = generate_jwt(user_details, jwt_token_id, jwt_token_description)
        if user_details.unique_jwt_token_description(jwt_token_description):
            user_details.add_jwt_token(jwt_token_id, jwt_token, jwt_token_description)
            return {
                "message": "Token generated",
                "jwt_token_id": jwt_token_id,
                "jwt_token": jwt_token,
                "jwt_token_description": jwt_token_description,
            }, 201
        else:
            return {
                "message": "Token description already exists, please enter a new one"
            }, 400


@rest_resource
class ResourceJWTById(SecureResource):
    """
    A Resource to manage individual JWT token
    """

    endpoints = ["/v1alpha/token/<jwt_token_id>/"]

    def get(self, jwt_token_id):
        # An endpoint to get a JWT token by id
        user = auth.current_user()
        user_details = app.specter.user_manager.get_user(user)
        jwt_tokens = user_details.jwt_tokens
        jwt_token = user_details.get_jwt_token(jwt_token_id)

        if (
            not user_details.verify_jwt_token_id_and_jwt_token(jwt_token_id, jwt_token)
            and jwt_tokens[jwt_token_id] is None
        ):
            return {
                "message": "Token does not exist, make sure to enter correct token id"
            }, 404
        return {"message": "Tokens exists", "jwt_token_description": jwt_token}, 200

    def delete(self, jwt_token_id):
        # An endpoint to delete a JWT token by id
        user = auth.current_user()
        user_details = app.specter.user_manager.get_user(user)
        jwt_tokens = user_details.jwt_tokens
        jwt_token = user_details.get_jwt_token(jwt_token_id)

        if (
            not user_details.verify_jwt_token_id_and_jwt_token(jwt_token_id, jwt_token)
            and jwt_tokens[jwt_token_id] is None
        ):
            return {
                "message": "Token does not exist, make sure to enter correct token id"
            }, 404

        user_details.delete_jwt_token(jwt_token_id)
        return {"message": "Token deleted"}, 200
