package server

import (
	"crypto/ecdsa"
	"fmt"
	"net/http"

	"github.com/alexhokl/auth-server/api"
	"github.com/alexhokl/auth-server/docs"
	"github.com/alexhokl/auth-server/store"
	"github.com/alexhokl/helper/database"
	"github.com/gin-gonic/gin"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	oauthredis "github.com/go-oauth2/redis/v4"
	oauthredisopts "github.com/go-redis/redis/v8"
	sessionredis "github.com/go-session/redis/v3"
	"github.com/go-session/session/v3"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"gorm.io/gorm"
)

// MailConfig describes how notification mails are sent.
type MailConfig struct {
	ResendAPIKey           string
	From                   string
	FromName               string
	ConfirmationSubject    string
	PasswordChangedSubject string
	PasswordResetSubject   string
}

// RouterConfig describes the configurable values of the router.
//
// Note that the fields are deliberately named rather than passed positionally
// as several of them share the same type.
type RouterConfig struct {
	RedisHost                string
	RedisPassword            string
	RedisTokenDatabaseName   string
	RedisSessionDatabaseName string
	EnforcePKCE              bool
	EnableFrontendEndpoints  bool
	EnableOIDC               bool
	ExpirationPeriod         int64
	Domain                   string
	SessionCookieName        string
	KeyID                    string
	Mail                     MailConfig
}

func GetRouter(dialector gorm.Dialector, tokenGenerator oauth2.AccessGenerate, privateKey *ecdsa.PrivateKey, fidoService *api.FidoService, cfg RouterConfig) (*gin.Engine, error) {
	dbConn, err := database.GetDatabaseConnection(dialector)
	if err != nil {
		return nil, err
	}
	setupSessionManager(cfg.EnableOIDC, cfg.SessionCookieName, cfg.RedisHost, cfg.RedisPassword, cfg.RedisSessionDatabaseName)
	oauthService := getOAuthService(dbConn, tokenGenerator, cfg.RedisHost, cfg.RedisPassword, cfg.RedisTokenDatabaseName, cfg.EnforcePKCE)

	withMail := api.WithMail(
		cfg.Mail.ResendAPIKey,
		cfg.Mail.From,
		cfg.Mail.FromName,
		cfg.Mail.ConfirmationSubject,
		cfg.Mail.PasswordChangedSubject,
		cfg.Mail.PasswordResetSubject,
	)

	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	r.LoadHTMLFiles(
		"./assets/signin.html",
		"./assets/new_password.tmpl",
	)

	docs.SwaggerInfo.BasePath = "/"
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))

	r.POST("/signin", api.SignIn)
	r.POST("/signin/challenge", api.WithDatabaseConnection(dialector), api.SignInPasswordChallenge)
	if cfg.EnableOIDC {
		r.GET(
			fmt.Sprintf("/:action/:oidc_name/%s", api.OIDC_START_ENDPOINT),
			api.WithDatabaseConnection(dialector),
			api.RedirectToOIDCEndpoint,
		)
		r.GET(
			fmt.Sprintf("/signin/:oidc_name/%s", api.OIDC_CALLBACK_ENDPOINT),
			api.WithDatabaseConnection(dialector),
			api.OIDCCallback,
		)
	}
	r.POST(
		"/signup",
		api.WithDatabaseConnection(dialector),
		api.WithExpirationPeriod(cfg.ExpirationPeriod),
		withMail,
		api.WithDomain(cfg.Domain),
		api.SignUp,
	)
	r.POST("/token", gin.WrapF(api.GetTokenRequestHandler(oauthService)))
	r.GET("/confirm/:otp", api.WithDatabaseConnection(dialector), api.Confirm)
	r.POST("/changepassword",
		api.RequiredAuthenticated(),
		api.WithDatabaseConnection(dialector),
		withMail,
		api.WithDomain(cfg.Domain),
		api.ChangePassword,
	)
	r.POST("/resetpassword",
		api.WithDatabaseConnection(dialector),
		api.WithExpirationPeriod(cfg.ExpirationPeriod),
		withMail,
		api.WithDomain(cfg.Domain),
		api.ResetPassword)
	r.GET("/confirmresetpassword/:otp", api.WithDatabaseConnection(dialector), api.ConfirmResetPassword)
	r.POST("/confirmresetpassword/:otp",
		api.WithDatabaseConnection(dialector),
		withMail,
		api.WithDomain(cfg.Domain),
		api.NewPassword)

	r.POST("/signout", api.RequiredAuthenticated(), api.SignOut)
	r.GET("/authorize", api.RequiredAuthenticated(), gin.WrapF(api.GetAuthorizationRequestHandler(oauthService)))
	r.GET("/.well-known/openid-configuration", api.WithDatabaseConnection(dialector), api.GetOpenIDConfiguration)
	r.GET("/.well-known/openid-configuration/jwks", api.GetJSONWebKeySetHandler(cfg.KeyID, privateKey))
	r.GET("/.well-known/webfinger", api.GetWebFingerConfiguration)
	r.GET("/.well-known/change-password", api.RedirectToChangePasswordUI)

	fidoGroup := r.Group("/fido")
	fidoGroup.Use(api.WithDatabaseConnection(dialector))
	fidoGroup.POST("/signin/challenge", fidoService.LoginChallenge)
	fidoGroup.POST("/signin", fidoService.Login)
	fidoRegister := fidoGroup.Group("/register")
	fidoRegister.Use(api.RequiredAuthenticated())
	fidoRegister.POST("challenge", fidoService.RegisterChallenge)
	fidoRegister.POST("", fidoService.Register)
	fidoCredentials := fidoGroup.Group("/credentials")
	fidoCredentials.Use(api.RequiredAuthenticated())
	fidoCredentials.GET("", fidoService.GetCredentials)
	fidoCredentials.DELETE(":id", fidoService.DeleteCredential)
	fidoCredentials.PATCH(":id", fidoService.UpdateCredential)

	clients := r.Group("/clients")
	clients.Use(api.WithDatabaseConnection(dialector), api.RequiredAdminAccess())
	clients.POST("", api.CreateClient)
	clients.PATCH(":client_id", api.UpdateClient)
	clients.GET("", api.ListClients)
	clientScopes := clients.Group("/:client_id/scopes")
	clientScopes.GET("", api.ListClientScopes)
	clientScopes.POST("", api.CreateClientScope)
	clientScopes.DELETE(":scope", api.DeleteClientScope)

	scopes := r.Group("/scopes")
	scopes.Use(api.WithDatabaseConnection(dialector), api.RequiredAdminAccess())
	scopes.POST("", api.CreateScope)
	scopes.DELETE(":scope", api.DeleteScope)

	users := r.Group("/users")
	users.Use(api.WithDatabaseConnection(dialector), api.RequiredAdminAccess())
	users.GET("", api.ListUsers)

	oidc := r.Group("/oidcclients")
	oidc.Use(api.WithDatabaseConnection(dialector), api.RequiredAdminAccess())
	oidc.GET("", api.ListOIDCCLients)
	oidc.POST("", api.CreateOIDCClient)
	oidc.PUT(":name", api.UpdateOIDCClient)
	oidc.DELETE(":name", api.DeleteOIDCClient)

	if cfg.EnableFrontendEndpoints {
		r.GET("/signin", api.WithDatabaseConnection(dialector), api.WithOIDC(cfg.EnableOIDC), api.SignInUI)
		r.GET("/signin/challenge", api.HasEmailInSession, api.SignInChallengeUI)
		r.StaticFile("/assets/signin.js", "./assets/signin.js")
		r.StaticFile("/assets/styles.css", "./assets/styles.css")
		r.StaticFile("/assets/authenticated.js", "./assets/authenticated.js")
		r.StaticFile("/assets/http.js", "./assets/http.js")
		r.GET("/authenticated", api.RequiredAuthenticated(), api.AuthenticatedUI)
		r.StaticFile("/", "./assets/home.html")
		r.StaticFile("/signup", "./assets/signup.html")
		r.StaticFile("/assets/signup.js", "./assets/signup.js")
		r.StaticFile("/signup_continue", "./assets/signup_email.html")
		r.StaticFile("/assets/changepassword.js", "./assets/changepassword.js")
		r.GET("/changepassword", api.RequiredAuthenticated(), api.ChangePasswordUI)
		r.StaticFile("/changepassword_completed", "./assets/changepassword_completed.html")
		r.StaticFile("/resetpassword", "./assets/reset_password.html")
		r.StaticFile("/assets/new_password.js", "./assets/new_password.js")
	}

	return r, nil
}

func getOAuthService(dbConn *gorm.DB, tokenGenerator oauth2.AccessGenerate, redisHost, redisPassword, redisDatabaseName string, enforcePKCE bool) *server.Server {
	clientStore := store.NewClientStore(dbConn)
	tokenStore := oauthredis.NewRedisStore(
		&oauthredisopts.Options{
			Addr:     redisHost,
			Password: redisPassword,
		},
		redisDatabaseName,
	)

	manager := manage.NewDefaultManager()
	manager.MapClientStorage(clientStore)
	manager.MapTokenStorage(tokenStore)
	manager.MapAccessGenerate(tokenGenerator)

	srv := server.NewDefaultServer(manager)
	srv.Config.ForcePKCE = enforcePKCE
	srv.SetAllowGetAccessRequest(false)
	srv.SetAllowedResponseType(
		oauth2.Code,
		oauth2.Token,
	)
	srv.SetAllowedGrantType(
		oauth2.AuthorizationCode,
		oauth2.ClientCredentials,
		oauth2.Refreshing,
	)

	srv.SetInternalErrorHandler(api.HandleInternalError)
	// srv.SetResponseErrorHandler(api.HandleErrorResponse)
	srv.SetUserAuthorizationHandler(api.GetUserIdInAuthorizationRequest)
	srv.SetClientInfoHandler(api.HandleClientInfoInTokenRequest)

	return srv
}

func setupSessionManager(enableOIDC bool, cookieName, redisHost, redisPassword, redisDatabaseName string) {
	sessionStore := sessionredis.NewRedisStore(
		&sessionredis.Options{
			Addr:     redisHost,
			Password: redisPassword,
		},
		redisDatabaseName,
	)

	sameSiteMode := http.SameSiteStrictMode
	if enableOIDC {
		// Without using OIDC, SameSite can be set to Srtict.
		// However, with OIDC, SameSite has to be set to None so that it
		// supports redirection to an external OIDC provider.
		// See https://github.com/aspnet/AspNetKatana/issues/386#issuecomment-709420241
		sameSiteMode = http.SameSiteNoneMode
	}

	session.InitManager(
		session.SetSameSite(sameSiteMode),
		session.SetSecure(true),
		session.SetStore(sessionStore),
		session.SetCookieName(cookieName),
	)
}
