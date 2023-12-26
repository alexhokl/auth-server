package main

import (
	"context"
	"fmt"
	"log/slog"
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
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt"
	"github.com/spf13/viper"
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

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	// applies logger to both slog and log
	slog.SetDefault(logger)

	cli.ConfigureViper("", "auth", true, "auth")

	isDebug := !viper.GetBool("release")

	dbConn, err := db.GetDatabaseConnection()
	if err != nil {
		slog.Error(
			"Unable to connect to database",
			slog.String("error", err.Error()),
		)
		os.Exit(1)
	}
	slog.Info("Database connection established")
	db.Migrate(dbConn)
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
	slog.Info("Private key loaded")
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

	fidoService, err := getFidoService(
		viper.GetString("domain"),
		viper.GetString("application_name"),
		isDebug,
	)
	if err != nil {
		slog.Error(
			"Unable to create FIDO service",
			slog.String("error", err.Error()),
		)
		os.Exit(1)
	}

	router := authserver.GetRouter(srv, ecdsaPrivateKey, fidoService, viper.GetBool("frontend_endpoints"))

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

func getFidoService(domain string, displayName string, isDebug bool) (*api.FidoService, error) {
	config := &webauthn.Config{
		Debug:         isDebug,
		RPDisplayName: displayName,
		RPID:          domain,
		RPOrigins: []string{
			fmt.Sprintf("https://%s", domain),
			fmt.Sprintf("http://%s:%d", domain, viper.GetInt("port")),
		},
		// see https://www.w3.org/TR/webauthn/#enum-attestation-convey
		AttestationPreference: protocol.PreferDirectAttestation,
		// see https://www.w3.org/TR/webauthn/#dictionary-authenticatorSelection
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			// see https://www.w3.org/TR/webauthn/#enum-attachment
			AuthenticatorAttachment: protocol.CrossPlatform,
			// see https://www.w3.org/TR/webauthn/#enum-residentKeyRequirement
			ResidentKey: protocol.ResidentKeyRequirementDiscouraged,
			// RequireResidentKey: false,
			// see https://www.w3.org/TR/webauthn/#enumdef-userverificationrequirement
			UserVerification: protocol.VerificationRequired,
		},
	}
	w, err := webauthn.New(config)
	if err != nil {
		return nil, err
	}

	return &api.FidoService{
		W: w,
	}, nil
}
