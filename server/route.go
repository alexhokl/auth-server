package server

import (
	"github.com/alexhokl/auth-server/api"
	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/alexhokl/auth-server/docs"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func GetRouter(srv *server.Server) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	docs.SwaggerInfo.BasePath = "/"
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))

	r.POST("/signin", api.SignIn)
	r.POST("/signup", api.SignUp)
	r.POST("/token", gin.WrapF(api.GetTokenRequestHandler(srv)))

	r.POST("/signout", api.RequiredAuthenticated(), api.SignOut)
	r.GET("/authorize", api.RequiredAuthenticated(), gin.WrapF(api.GetAuthorizationRequestHandler(srv)))
	r.GET("/.well-known/openid-configuration", api.GetOpenIDConfiguration)

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
