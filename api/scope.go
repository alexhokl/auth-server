package api

import (
	"net/http"

	"github.com/alexhokl/auth-server/db"
	"github.com/gin-gonic/gin"
)

func CreateScope(c *gin.Context) {
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
	isScopeExist, err := db.IsScopeExist(dbConn, req.Name)
	if err != nil {
		handleInternalError(c, err, "Unable to check if scope exists")
		return
	}
	if isScopeExist {
		c.JSON(http.StatusConflict, gin.H{"error": "Scope already exists"})
		return
	}
	errCreate := db.CreateScope(dbConn, req.Name)
	if errCreate != nil {
		handleInternalError(c, errCreate, "Unable to create scope")
		return
	}

	c.Status(http.StatusCreated)
}

func DeleteScope(c *gin.Context) {
	dbConn, ok := getDatabaseConnectionFromContext(c)
	if !ok {
		handleInternalError(c, nil, "Missing configuration for database")
		return
	}
	scopeName := c.Param("scope")

	isScopeInUse, err := db.IsScopeInUse(dbConn, scopeName)
	if err != nil {
		handleInternalError(c, err, "Unable to check if scope is in use")
		return
	}
	if isScopeInUse {
		c.JSON(http.StatusConflict, gin.H{"error": "Scope is in use"})
		return
	}

	errDelete := db.DeleteScope(dbConn, scopeName)
	if errDelete != nil {
		handleInternalError(c, errDelete, "Unable to delete scope")
		return
	}

	c.Status(http.StatusNoContent)
}
