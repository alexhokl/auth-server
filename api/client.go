package api

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/alexhokl/auth-server/db"
	"github.com/alexhokl/auth-server/store"
	"github.com/gin-gonic/gin"
)

// CreateClient adds a client
//
//	@Summary		Adds a client
//	@Description	Adds a OAuth client
//	@Tags			clients
//	@Accept			json
//	@Produce		json
//	@Param			body	body	api.ClientCreateRequest	true	"Client details"
//	@Router			/clients/ [post]
func CreateClient(c *gin.Context) {
	var req ClientCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	user, err := db.GetUser(dbConn, req.UserEmail)
	if err != nil {
		slog.Error(
			"Error in retrieving user",
			slog.String("email", req.UserEmail),
			slog.String("error", err.Error()),
		)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	if user == nil {
		slog.Error(
			"Unable to find user",
			slog.String("email", req.UserEmail),
		)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	client := store.NewClient(req.ClientID, req.ClientSecret, req.RedirectUri, user.Email, false)

	clientStore := store.NewClientStore(dbConn)
	existingClient, err := clientStore.GetByID(context.TODO(), client.GetID())
	if err != nil {
		slog.Error(
			"Error in retrieving client",
			slog.String("client_id", client.GetID()),
		)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	if existingClient != nil {
		slog.Error(
			"Client already exists",
			slog.String("client_id", client.GetID()),
		)
		c.AbortWithStatusJSON(
			http.StatusBadRequest,
			gin.H{"error": "Client already exists"},
		)
		return
	}

	clientStore.Create(context.TODO(), client)
}

// UpdateClient patches a client
//
//	@Summary		Patches a client
//	@Description	Patches a OAuth client (not implemented yet)
//	@Tags			clients
//	@Accept			json
//	@Produce		json
//	@Router			/clients/ [patch]
func UpdateClient(c *gin.Context) {
	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}
	client, err := db.GetClient(dbConn, c.Param("client_id"))
	if err != nil {
		slog.Warn(
			"Error in retrieving client",
			slog.String("client_id", c.Param("client_id")),
			slog.String("error", err.Error()),
		)
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	var req ClientUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.ClientSecret != nil {
		client.ClientSecret = *req.ClientSecret
	}
	if req.RedirectUri != nil {
		client.RedirectURI = *req.RedirectUri
	}
	if req.UserEmail != nil {
		client.UserEmail = *req.UserEmail
	}
	if err := db.UpdateClient(dbConn, client); err != nil {
		slog.Error(
			"Error in updating client",
			slog.String("client_id", client.ClientID),
			slog.String("error", err.Error()),
		)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, ClientResponse{
		ClientID:    client.ClientID,
		RedirectUri: client.RedirectURI,
		UserEmail:   client.UserEmail,
	})
}

// ListClients lists clients
//
//	@Summary	Lists clients
//	@Tags		clients
//	@Produce	json
//	@Router		/clients/ [get]
func ListClients(c *gin.Context) {
	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}

	clients, err := db.GetClients(dbConn)
	if err != nil {
		slog.Error(
			"Unable to list clients",
			slog.String("error", err.Error()),
		)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	clientResponses := make([]ClientResponse, len(clients))
	for i, client := range clients {
		clientResponses[i] = *ToClientResponse(client)
	}

	c.JSON(http.StatusOK, clientResponses)
}

func ListClientScopes(c *gin.Context) {
	clientID := c.Param("client_id")
	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}
	scopes, err := db.ListClientScopes(dbConn, clientID)
	if err != nil {
		slog.Error(
			"Unable to list scopes for client",
			slog.String("client_id", clientID),
			slog.String("error", err.Error()),
		)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.JSON(http.StatusOK, scopes)
}

func CreateClientScope(c *gin.Context) {
	clientID := c.Param("client_id")
	var req ScopeCreationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}
	isScopeExists, err := db.IsScopeExist(dbConn, req.Name)
	if err != nil {
		slog.Error(
			"Unable to check if scope exists",
			slog.String("scope", req.Name),
			slog.String("error", err.Error()),
		)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	if !isScopeExists {
		c.JSON(http.StatusConflict, gin.H{"error": "Scope does not exist"})
		return
	}
	errCreate := db.CreateClientScope(dbConn, clientID, req.Name)
	if errCreate != nil {
		slog.Error(
			"Unable to create scope for client",
			slog.String("client_id", clientID),
			slog.String("error", errCreate.Error()),
		)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.Status(http.StatusCreated)
}

func DeleteClientScope(c *gin.Context) {
	clientID := c.Param("client_id")
	scope := c.Param("scope")
	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}
	err := db.DeleteClientScope(dbConn, clientID, scope)
	if err != nil {
		slog.Error(
			"Unable to delete scope for client",
			slog.String("client_id", clientID),
			slog.String("scope", scope),
			slog.String("error", err.Error()),
		)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.Status(http.StatusNoContent)
}
