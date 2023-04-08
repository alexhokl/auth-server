// Code generated by swaggo/swag. DO NOT EDIT.

package docs

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "contact": {},
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/.well-known/openid-configuration": {
            "get": {
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "OpenID"
                ],
                "summary": "OpenID configuration endpoint",
                "responses": {}
            }
        },
        "/.well-known/openid-configuration/jwks": {
            "get": {
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "OpenID"
                ],
                "summary": "JSON web key set endpoint",
                "responses": {}
            }
        },
        "/.well-known/webfinger": {
            "get": {
                "produces": [
                    "application/jrd+json"
                ],
                "tags": [
                    "OpenID"
                ],
                "summary": "WebFinger endpoint",
                "responses": {}
            }
        },
        "/authorize": {
            "get": {
                "consumes": [
                    "application/x-www-form-urlencoded"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "OAuth"
                ],
                "summary": "Authorize and redirect to the redirect_uri",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Response type (e.g. code)",
                        "name": "response_type",
                        "in": "query",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "Client ID",
                        "name": "client_id",
                        "in": "query",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "Redirect URI",
                        "name": "redirect_uri",
                        "in": "query",
                        "required": true
                    }
                ],
                "responses": {}
            }
        },
        "/clients/": {
            "get": {
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "clients"
                ],
                "summary": "Lists clients",
                "responses": {}
            },
            "post": {
                "description": "Adds a OAuth client",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "clients"
                ],
                "summary": "Adds a client",
                "parameters": [
                    {
                        "description": "Client details",
                        "name": "body",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/api.ClientCreateRequest"
                        }
                    }
                ],
                "responses": {}
            },
            "patch": {
                "description": "Patches a OAuth client (not implemented yet)",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "clients"
                ],
                "summary": "Patches a client",
                "responses": {}
            }
        },
        "/signin": {
            "post": {
                "consumes": [
                    "application/x-www-form-urlencoded"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "user"
                ],
                "summary": "Starts a sign in session with a user",
                "parameters": [
                    {
                        "type": "string",
                        "example": "alex@test.com",
                        "name": "email",
                        "in": "formData",
                        "required": true
                    }
                ],
                "responses": {}
            }
        },
        "/signin/challenge": {
            "post": {
                "consumes": [
                    "application/x-www-form-urlencoded"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "user"
                ],
                "summary": "Signs in a user with a password",
                "parameters": [
                    {
                        "type": "string",
                        "example": "P@ssw0rd",
                        "name": "password",
                        "in": "formData",
                        "required": true
                    }
                ],
                "responses": {}
            }
        },
        "/signout": {
            "post": {
                "description": "Signs out a user and deletes its email from session. Note that the session cookie would not be deleted.",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "user"
                ],
                "summary": "Signs out a user",
                "responses": {}
            }
        },
        "/signup": {
            "post": {
                "description": "Creates a new user but it does not verify the email address yet",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "user"
                ],
                "summary": "Creates a new user",
                "parameters": [
                    {
                        "description": "User sign up request",
                        "name": "body",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/api.UserSignUpRequest"
                        }
                    }
                ],
                "responses": {}
            }
        },
        "/token": {
            "post": {
                "consumes": [
                    "application/x-www-form-urlencoded"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "OAuth"
                ],
                "summary": "Issues a token",
                "parameters": [
                    {
                        "type": "string",
                        "example": "cli",
                        "name": "client_id",
                        "in": "formData",
                        "required": true
                    },
                    {
                        "type": "string",
                        "example": "P@ssw0rd",
                        "name": "client_secret",
                        "in": "formData",
                        "required": true
                    },
                    {
                        "type": "string",
                        "example": "code",
                        "name": "code",
                        "in": "formData",
                        "required": true
                    },
                    {
                        "type": "string",
                        "example": "authorization_code",
                        "name": "grant_type",
                        "in": "formData",
                        "required": true
                    },
                    {
                        "type": "string",
                        "example": "http://localhost:8088",
                        "name": "redirect_uri",
                        "in": "formData",
                        "required": true
                    }
                ],
                "responses": {}
            }
        }
    },
    "definitions": {
        "api.ClientCreateRequest": {
            "type": "object",
            "required": [
                "client_id",
                "client_secret",
                "redirect_uri",
                "user_email"
            ],
            "properties": {
                "client_id": {
                    "type": "string",
                    "example": "cli"
                },
                "client_secret": {
                    "type": "string",
                    "example": "P@ssw0rd"
                },
                "redirect_uri": {
                    "type": "string",
                    "example": "http://localhost:8080/callback"
                },
                "user_email": {
                    "type": "string",
                    "example": "alex@test.com"
                }
            }
        },
        "api.UserSignUpRequest": {
            "type": "object",
            "required": [
                "email",
                "password"
            ],
            "properties": {
                "email": {
                    "type": "string",
                    "example": "alex@test.com"
                },
                "password": {
                    "type": "string",
                    "example": "P@ssw0rd"
                }
            }
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "0.0.1",
	Host:             "",
	BasePath:         "",
	Schemes:          []string{},
	Title:            "Auth Server API",
	Description:      "This API provides authentication and authorization services.",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}
