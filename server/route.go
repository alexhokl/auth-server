package server

import (
	"crypto/ecdsa"

	"github.com/alexhokl/auth-server/api"
	"github.com/alexhokl/auth-server/docs"
	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/server"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func GetRouter(oauthService *server.Server, privateKey *ecdsa.PrivateKey) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	docs.SwaggerInfo.BasePath = "/"
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))

	r.POST("/signin", api.SignIn)
	r.POST("/signup", api.SignUp)
	r.POST("/token", gin.WrapF(api.GetTokenRequestHandler(oauthService)))

	r.POST("/signout", api.RequiredAuthenticated(), api.SignOut)
	r.GET("/authorize", api.RequiredAuthenticated(), gin.WrapF(api.GetAuthorizationRequestHandler(oauthService)))
	r.GET("/.well-known/openid-configuration", api.GetOpenIDConfiguration)
	r.GET("/.well-known/openid-configuration/jwks", api.GetJSONWebKeySetHandler(privateKey))
	r.GET("/.well-known/webfinger", api.GetWebFingerConfiguration)

	clients := r.Group("/clients")
	clients.Use(api.RequiredAdminAccess())
	clients.POST("", api.CreateClient)
	clients.PATCH(":client_id", api.UpdateClient)
	clients.GET("", api.ListClients)

	r.StaticFile("/signin", "./assets/login.html")
	r.StaticFile("/assets/scripts.js", "./assets/scripts.js")
	r.StaticFile("/assets/styles.css", "./assets/styles.css")

	return r
}
