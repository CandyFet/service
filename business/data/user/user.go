// Package user contains user related CRUD functionality.
package user

import (
	"context"
	"database/sql"
	"log"
	"time"

	"github.com/CandyFet/service/business/auth"
	"github.com/CandyFet/service/foundation/database"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

var (
	//ErrNotFound is used when a specific User is requested but does not exist.
	ErrNotFound = errors.New("not found")

	// ErrInvalidID occurs when an id is not in valid form.
	ErrInvalidID = errors.New("ID is not in its proper form")

	// ErrAuthenticationFailure occurs when a user attempts to authenticate but
	// anything goes wrong.
	ErrAuthenticationFailure = errors.New("authentication failed")

	// ErrForbidden occurs when when a user tries to do something that is forbidden to them according to roles.
	ErrForbidden = errors.New("attempted action is not allowed")
)

// User manages the set of API's for user access.
type User struct {
	log *log.Logger
	db  *sqlx.DB
}

// New constructs a User for api access.
func New(log *log.Logger, db *sqlx.DB) User {
	return User{
		log: log,
		db:  db,
	}
}

// Create inserts a new user into the database.
func (u User) Create(ctx context.Context, traceID string, nu NewUser, now time.Time) (Info, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(nu.Password), bcrypt.DefaultCost)
	if err != nil {
		return Info{}, errors.Wrap(err, "generating password hash")
	}

	usr := Info{
		ID:           uuid.New().String(),
		Name:         nu.Name,
		Email:        nu.Email,
		PasswordHash: hash,
		Roles:        nu.Roles,
		DateCreated:  now.UTC(),
		DateUpdated:  now.UTC(),
	}

	const q = `INSERT INTO users
		(user_id, name, email, password_hash, roles, date_created, date_updated)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	u.log.Printf("%s : %s : query : %s", traceID, "user.Create",
		database.Log(q, usr.ID, usr.Name, usr.Email, usr.PasswordHash, usr.Roles, usr.DateCreated, usr.DateUpdated))

	if _, err := u.db.ExecContext(ctx, q, usr.ID, usr.Name, usr.Email, usr.PasswordHash, usr.Roles, usr.DateCreated, usr.DateUpdated); err != nil {
		return Info{}, errors.Wrap(err, "inserting user")
	}

	return usr, nil
}

// Update replaces a user document in the database.
func (u User) Update(ctx context.Context, traceID string, claims auth.Claims, userID string, uu UpdateUser, now time.Time) error {
	usr, err := u.QueryByID(ctx, traceID, claims, userID)
	if err != nil {
		return err
	}

	if uu.Name != nil {
		usr.Name = *uu.Name
	}
	if uu.Email != nil {
		usr.Email = *uu.Email
	}
	if uu.Roles != nil {
		usr.Roles = uu.Roles
	}
	if uu.Password != nil {
		pw, err := bcrypt.GenerateFromPassword([]byte(*uu.Password), bcrypt.DefaultCost)
		if err != nil {
			return errors.Wrap(err, "generating password hash")
		}
		usr.PasswordHash = pw
	}
	usr.DateUpdated = now

	const q = `UPDATE users SET
		"name" = $2,
		"email" = $3,
		"roles" = $4,
		"password_hash" = $5,
		"date_updated" = $6
		WHERE user_id = $1`

	u.log.Printf("%s : %s : query : %s", traceID, "user.Update",
		database.Log(q, usr.ID, usr.Name, usr.Email, usr.PasswordHash, usr.Roles, usr.DateCreated, usr.DateUpdated))

	if _, err := u.db.ExecContext(ctx, q, usr.ID, usr.Name, usr.Email, usr.Roles, usr.PasswordHash, usr.DateUpdated); err != nil {
		return errors.Wrap(err, "updating user")
	}

	return nil
}

// Delete removes a user form the database.
func (u User) Delete(ctx context.Context, traceID string, userID string) error {
	if _, err := uuid.Parse(userID); err != nil {
		return ErrInvalidID
	}

	const q = `DELETE FROM users WHERE user_id = $1`

	u.log.Printf("%s : %s : query : %s", traceID, "user.Delete",
		database.Log(q, userID))

	if _, err := u.db.ExecContext(ctx, q, userID); err != nil {
		return errors.Wrapf(err, "deleteing user %s", userID)
	}

	return nil
}

// Query retrieves a list of exsisting users from the database.
func (u User) Query(ctx context.Context, traceID string, pageNumber int, rowsPerPage int) ([]Info, error) {
	const q = `SELECT * FROM users ORDER BY user_id OFFSET $1 ROWS FETCH NEXT $2 ROWS ONLY`
	offset := (pageNumber - 1) * rowsPerPage

	u.log.Printf("%s : %s : query : %s", traceID, "user.Query", database.Log(q, offset, rowsPerPage))

	users := []Info{}
	if err := u.db.SelectContext(ctx, &users, q, offset, rowsPerPage); err != nil {
		return nil, errors.Wrap(err, "selecting users")
	}

	return users, nil
}

// QueryByID gets the specified use rfrom the database.
func (u User) QueryByID(ctx context.Context, traceID string, claims auth.Claims, userID string) (Info, error) {
	if _, err := uuid.Parse(userID); err != nil {
		return Info{}, ErrInvalidID
	}

	// If you are not an admin and looking to retrieve someone othe than yourself,
	if !claims.Authorized(auth.RoleAdmin) && claims.Subject != userID {
		return Info{}, ErrForbidden
	}

	const q = `SELECT * FROM users WHERE user_id = $1`

	u.log.Printf("%s : %s : query : %s", traceID, "user.QueryByID", database.Log(q, userID))

	var usr Info

	if err := u.db.GetContext(ctx, &usr, q, userID); err != nil {
		if err == sql.ErrNoRows {
			return Info{}, ErrNotFound
		}
		return Info{}, errors.Wrapf(err, "select user %q", userID)
	}

	return usr, nil
}

// QueryByEmail gets the specified use rfrom the database.
func (u User) QueryByEmail(ctx context.Context, traceID string, claims auth.Claims, email string) (Info, error) {
	const q = `SELECT * FROM users WHERE email = $1`

	u.log.Printf("%s : %s : query : %s", traceID, "user.QueryByEmail", database.Log(q, email))

	var usr Info

	if err := u.db.GetContext(ctx, &usr, q, email); err != nil {
		if err == sql.ErrNoRows {
			return Info{}, ErrNotFound
		}
		return Info{}, errors.Wrapf(err, "select user %q", email)
	}

	// If you are not an admin and looking to retrieve someone othe than yourself,
	if !claims.Authorized(auth.RoleAdmin) && claims.Subject != usr.ID {
		return Info{}, ErrForbidden
	}

	return usr, nil
}

func (u User) Authenticate(ctx context.Context, traceID string, now time.Time, email, password string) (auth.Claims, error) {
	const q = `SELECT * FROM users WHERE email = $1`

	u.log.Printf("%s : %s : query : %s", traceID, "user.QueryByEmail", database.Log(q, email))

	var usr Info

	if err := u.db.GetContext(ctx, &usr, q, email); err != nil {
		if err == sql.ErrNoRows {
			return auth.Claims{}, ErrNotFound
		}
		return auth.Claims{}, errors.Wrapf(err, "select user %q", email)
	}

	if err := bcrypt.CompareHashAndPassword(usr.PasswordHash, []byte(password)); err != nil {
		return auth.Claims{}, ErrAuthenticationFailure
	}

	claims := auth.Claims{
		StandardClaims: jwt.StandardClaims{
			Subject:   usr.ID,
			Issuer:    "service project",
			ExpiresAt: time.Now().UTC().Add(time.Hour).Unix(),
			IssuedAt:  time.Now().UTC().Unix(),
		},
		Roles: usr.Roles,
	}

	return claims, nil
}
