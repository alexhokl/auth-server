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

func GetRouter(oauthService *server.Server, privateKey *ecdsa.PrivateKey, fidoService *api.FidoService, enableFrontendEndpoints bool) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	docs.SwaggerInfo.BasePath = "/"
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))

	r.POST("/signin", api.SignIn)
	r.POST("/signin/challenge", api.SignInPasswordChallenge)
	r.POST("/signup", api.SignUp)
	r.POST("/token", gin.WrapF(api.GetTokenRequestHandler(oauthService)))

	r.POST("/signout", api.RequiredAuthenticated(), api.SignOut)
	r.GET("/authorize", api.RequiredAuthenticated(), gin.WrapF(api.GetAuthorizationRequestHandler(oauthService)))
	r.GET("/.well-known/openid-configuration", api.GetOpenIDConfiguration)
	r.GET("/.well-known/openid-configuration/jwks", api.GetJSONWebKeySetHandler(privateKey))
	r.GET("/.well-known/webfinger", api.GetWebFingerConfiguration)

	fidoGroup := r.Group("/fido")
	fidoGroup.POST("/register/challenge", api.RequiredAuthenticated(), fidoService.RegisterChallenge)
	fidoGroup.POST("/register", api.RequiredAuthenticated(), fidoService.Register)
	fidoGroup.POST("/signin/challenge", fidoService.LoginChallenge)
	fidoGroup.POST("/signin", fidoService.Login)
	fidoGroup.GET("/credentials", api.RequiredAuthenticated(), fidoService.GetCredentials)
	fidoGroup.DELETE("/credential/:id", api.RequiredAuthenticated(), fidoService.DeleteCredential)
	fidoGroup.PATCH("/credential/:id", api.RequiredAuthenticated(), fidoService.UpdateCredential)

	clients := r.Group("/clients")
	clients.Use(api.RequiredAdminAccess())
	clients.POST("", api.CreateClient)
	clients.PATCH(":client_id", api.UpdateClient)
	clients.GET("", api.ListClients)

	if enableFrontendEndpoints {
		r.StaticFile("/signin", "./assets/signin.html")
		r.GET("/signin/challenge", api.HasEmailInSession, api.SignInChallengeUI)
		r.StaticFile("/assets/signin.js", "./assets/signin.js")
		r.StaticFile("/assets/styles.css", "./assets/styles.css")
		r.StaticFile("/assets/authenticated.js", "./assets/authenticated.js")
		r.StaticFile("/assets/http.js", "./assets/http.js")
		r.GET("/authenticated", api.RequiredAuthenticated(), api.AuthenticatedUI)
		r.StaticFile("/", "./assets/home.html")
	}

	return r
}
