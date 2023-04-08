package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alexhokl/auth-server/api"
	"github.com/alexhokl/auth-server/db"
	"github.com/alexhokl/auth-server/jwthelper"
	authserver "github.com/alexhokl/auth-server/server"
	"github.com/alexhokl/auth-server/store"
	"github.com/alexhokl/helper/cli"
	"github.com/alexhokl/helper/iohelper"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	oauthredis "github.com/go-oauth2/redis/v4"
	oauthredisopts "github.com/go-redis/redis/v8"
	"github.com/go-session/redis/v3"
	"github.com/go-session/session/v3"
	"github.com/golang-jwt/jwt"
	"github.com/spf13/viper"
	"golang.org/x/exp/slog"
	"gorm.io/gorm"
)

//	@title			Auth Server API
//	@version		0.0.1
//	@description	This API provides authentication and authorization services.

const defaultPort = 8080
const tokenGarbageCollectionIntervalInSeconds = 600

func main() {
	setDefaultSettings()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger := slog.New(slog.NewJSONHandler(os.Stdout))
	// applies logger to both slog and log
	slog.SetDefault(logger)

	cli.ConfigureViper("", "auth", true, "auth")

	dbConn, err := db.GetDatabaseConnection()
	if err != nil {
		slog.Error(
			"Unable to connect to database",
			slog.String("error", err.Error()),
		)
		os.Exit(1)
	}
	slog.Info("Database connection established")
	dbConn.AutoMigrate(&db.User{})
	dbConn.AutoMigrate(&db.Client{})
	slog.Info("Database migration completed")

	ecdsaPrivateKey, err := jwthelper.LoadEcdsaPrivateKey(
		viper.GetString("private_key_path"),
		viper.GetString("private_key_password_file_path"),
	)
	if err != nil {
		slog.Error(
			"Unable to load private key",
			slog.String("error", err.Error()),
		)
		os.Exit(1)
	}
	slog.Info(
		"Private key loaded",
		// slog.String("name", ecdsaPrivateKey.Params().Name),
		// slog.String("x", ecdsaPrivateKey.X.String()),
		// slog.String("y", ecdsaPrivateKey.Y.String()),
	)
	jwtGenerator := jwthelper.NewEcKeyJWTGenerator(
		viper.GetString("key_id"),
		ecdsaPrivateKey,
		jwt.SigningMethodES256,
	)

	redisServer := viper.GetString("redis_host")
	redisPasswordFilePath := viper.GetString("redis_password_file_path")
	redisPassword, err := iohelper.ReadFirstLineFromFile(redisPasswordFilePath)
	if err != nil {
		slog.Error(
			"Unable to read Redis password from file",
			slog.String("error", err.Error()),
		)
		os.Exit(1)
	}

	srv := getOAuthService(
		dbConn,
		jwtGenerator,
		redisServer,
		redisPassword,
		viper.GetString("redis_session_db"),
		viper.GetBool("enforce_pkce"),
	)

	router := authserver.GetRouter(srv, ecdsaPrivateKey)

	setupSessionManager(
		redisServer,
		redisPassword,
		viper.GetString("redis_token_db"),
	)

	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", viper.GetInt("port")),
		Handler: router,
	}

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Unable to start server", slog.String("error", err.Error()))
		}
	}()

	<-ctx.Done()

	stop()
	slog.Info("shutting down gracefully, press Ctrl+C again to force")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		slog.Error("Server forced to shutdown: ", slog.String("error", err.Error()))
	}

	slog.Info("Server exiting")
}

func setDefaultSettings() {
	viper.SetDefault("port", defaultPort)
	viper.SetDefault("shutdown_timeout", 5*time.Second)
	viper.SetDefault("enforce_pkce", true)
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

func setupSessionManager(redisHost, redisPassword, redisDatabaseName string) {
	sessionStore := redis.NewRedisStore(
		&redis.Options{
			Addr:     redisHost,
			Password: redisPassword,
		},
		redisDatabaseName,
	)
	session.InitManager(
		session.SetSameSite(http.SameSiteStrictMode),
		session.SetStore(sessionStore),
	)
}
