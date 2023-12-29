package api

import (
	"slices"

	"github.com/alexhokl/auth-server/db"
	"github.com/alexhokl/helper/iohelper"
	"github.com/alexhokl/helper/jsonhelper"
)

func GetSeedUsers(pathToImportFile string) ([]db.User, []db.Role, error) {
	configStr, err := iohelper.ReadStringFromFile(pathToImportFile)
	if err != nil {
		return nil, nil, err
	}
	var importUsers []ImportUser
	if err := jsonhelper.ParseJSONString(configStr, &importUsers); err != nil {
		return nil, nil, err
	}
	var seedusers []db.User
	var seedRoleNames []string
	for _, u := range importUsers {
		dbUser := db.User{
			Email:    u.Email,
			DisplayName: u.DisplayName,
			PasswordHash: getPasswordHash(u.Password),
			Roles:    []db.Role{},
		}
		if u.Roles != nil {
			for _, r := range u.Roles {
				dbUser.Roles = append(dbUser.Roles, db.Role{
					Name: r,
				})
				if !slices.Contains(seedRoleNames, r) {
					seedRoleNames = append(seedRoleNames, r)
				}
			}
		}
		seedusers = append(seedusers, dbUser)
	}

	var seedRoles []db.Role
	for _, r := range seedRoleNames {
		seedRoles = append(seedRoles, db.Role{
			Name: r,
		})
	}

	return seedusers, seedRoles, nil
}
