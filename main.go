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
	"github.com/alexhokl/helper/cli"
	"github.com/alexhokl/helper/iohelper"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt"
	"github.com/spf13/viper"
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

	dialector, err := db.GetDatabaseDailector()
	if err != nil {
		slog.Error(
			"Unable to get database dailector",
			slog.String("error", err.Error()),
		)
		os.Exit(1)
	}

	dbConn, err := db.GetDatabaseConnection(dialector)
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

	ok, err := db.HasUsers(dbConn)
	if err != nil {
		slog.Error(
			"Unable to check if there are any existing users",
			slog.String("error", err.Error()),
		)
		os.Exit(1)
	}
	if ok {
		slog.Info("Skipping user import as database has existing users")
	} else {
		importFilename := viper.GetString("seed_users_file_path")
		if importFilename == "" {
			slog.Error(
				"Unable to import seed users as file path is not set",
			)
			os.Exit(1)
		}
		seedUsers, seedRoles, err := api.GetSeedUsers(importFilename)
		if err != nil {
			slog.Error(
				"Unable to read seed users",
				slog.String("error", err.Error()),
			)
			os.Exit(1)
		}
		for _, r := range seedRoles {
			if err := db.CreateRole(dbConn, &r); err != nil {
				slog.Error(
					"Unable to create role",
					slog.String("error", err.Error()),
					slog.String("name", r.Name),
				)
				os.Exit(1)
			}
		}
		for _, u := range seedUsers {
			if err := db.CreateUser(dbConn, &u); err != nil {
				slog.Error(
					"Unable to create user",
					slog.String("error", err.Error()),
					slog.String("email", u.Email),
				)
				os.Exit(1)
			}
		}
	}

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

	router, err := authserver.GetRouter(
		dialector,
		jwtGenerator,
		redisServer,
		redisPassword,
		viper.GetString("redis_session_db"),
		viper.GetString("redis_token_db"),
		viper.GetBool("enforce_pkce"),
		ecdsaPrivateKey,
		fidoService,
		viper.GetBool("frontend_endpoints"),
		viper.GetInt64("expiration_period"),
		viper.GetString("resend_api_key"),
		viper.GetString("mail_from"),
		viper.GetString("mail_from_name"),
		viper.GetString("confirmation_mail_subject"),
		viper.GetString("domain"),
		viper.GetString("password_changed_mail_subject"),
	)
	if err != nil {
		slog.Error(
			"Unable to create router",
			slog.String("error", err.Error()),
		)
		os.Exit(1)
	}

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
