package tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/CandyFet/service/app/sales-api/handlers"
	"github.com/CandyFet/service/business/auth"
	"github.com/CandyFet/service/business/data/user"
	"github.com/CandyFet/service/business/tests"
	"github.com/google/go-cmp/cmp"
)

// UserTests holds methods for each user subset. This type allows passing
// dependencies for tests while still providing a convenent syntax when
// subtests are registered.
type UserTests struct {
	app        http.Handler
	kid        string
	userToken  string
	adminToken string
}

// TestUsers is the entry point for testing user management functions.
func TestUsers(t *testing.T) {
	test := tests.NewIntegration(t)
	t.Cleanup(test.Teardown)

	shutdown := make(chan os.Signal, 1)
	tests := UserTests{
		app:        handlers.API("develop", shutdown, test.Log, test.Auth, test.DB),
		kid:        test.KID,
		userToken:  test.Token(test.KID, "user@example.com", "gophers"),
		adminToken: test.Token(test.KID, "admin@example.com", "gophers"),
	}

	t.Run("crudUser", tests.crudUser)
	t.Run("getToken401", tests.getToken401)
	t.Run("getToken200", tests.getToken200)
	t.Run("postUser400", tests.postUser400)
	t.Run("postUser401", tests.postUser401)
	t.Run("postUser403", tests.postUser403)
	t.Run("getUser400", tests.getUser400)
	t.Run("getUser403", tests.getUser403)
	t.Run("getUser404", tests.getUser404)
	t.Run("deleteUserNotFound", tests.deleteUserNotFound)
	t.Run("putUser404", tests.putUser404)
}

// crudUser performs a complete test of CRUD afainst the api.
func (ut *UserTests) crudUser(t *testing.T) {
	nu := ut.postUser201(t)
	defer ut.deleteUser204(t, nu.ID)

	ut.getUser200(t, nu.ID)
	ut.putUser204(t, nu.ID)
	ut.putUser403(t, nu.ID)
}

// postUser201 validates a user can be created with the endpoint.
func (ut *UserTests) postUser201(t *testing.T) user.Info {
	nu := user.NewUser{
		Name:            "John Doe",
		Email:           "johndoe@test.com",
		Roles:           []string{auth.RoleAdmin},
		Password:        "gophers",
		PasswordConfirm: "gophers",
	}

	body, err := json.Marshal(&nu)
	if err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodPost, "/users", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	r.Header.Set("Authorization", "Bearer "+ut.adminToken)
	ut.app.ServeHTTP(w, r)

	// This needs to be returned for other tests.
	var got user.Info

	t.Log("Given the need to create a new user with the users endpoint.")
	{
		testID := 0
		t.Logf("\tTest %d:\tWhen using the declared user value.", testID)
		{
			if w.Code != http.StatusCreated {
				t.Fatalf("\t%s\tTest %d\tShould receive a status code of 201 for the response : %v", tests.Failed, testID, w.Code)
			}
			t.Logf("\t%s\tTest %d:\tShould receive a status code of 201 for the response.", tests.Success, testID)

			if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
				t.Fatalf("\t%sTest %d:\tShould be able to unmarshal the response : %v", tests.Failed, testID, err)
			}

			// Define that we wanted to receive. We will just trust the generated
			// fields like ID and Dates so we copy u.
			exp := got
			exp.Name = "John Doe"
			exp.Email = "johndoe@test.com"
			exp.Roles = []string{auth.RoleAdmin}

			if diff := cmp.Diff(got, exp); diff != "" {
				t.Fatalf("\t%s\tTest %d:\tShould get the expected result. Diff:\n%s", tests.Failed, testID, diff)
			}
			t.Logf("\t%s\tTest %d:\tShould get the expected result.", tests.Success, testID)
		}
	}
	return got
}

// deleteUser204 validates deleting a user that does exist.
func (ut *UserTests) deleteUser204(t *testing.T, id string) {
	r := httptest.NewRequest(http.MethodDelete, "/users/"+id, nil)
	w := httptest.NewRecorder()

	r.Header.Set("Authorization", "Bearer "+ut.adminToken)
	ut.app.ServeHTTP(w, r)

	t.Log("Given the need to validate deleteing a user that does exist.")
	{
		testID := 0
		t.Logf("\tTest %d:\tWhen using the new user %s.", testID, id)
		{
			if w.Code != http.StatusNoContent {
				t.Fatalf("\t%s\tTest %d:\tShould receive a status code of 204 for the response : %v", tests.Failed, testID, w.Code)
			}
			t.Logf("\t%s\tTest %d:\tShould receive a status code of 204 for the response.", tests.Success, testID)
		}
	}
}

// getUser200 validates a user request for an existing user.
func (ut *UserTests) getUser200(t *testing.T, id string) {
	r := httptest.NewRequest(http.MethodGet, "/users/"+id, nil)
	w := httptest.NewRecorder()

	r.Header.Set("Authorization", "Bearer "+ut.adminToken)
	ut.app.ServeHTTP(w, r)

	t.Log("Given the need to validate requesting a user that does exist.")
	{
		testID := 0
		t.Logf("\tTest %d:\tWhen using the new user %s.", testID, id)
		{
			if w.Code != http.StatusOK {
				t.Fatalf("\t%s\tTest %d:\tShould receive a status code of 200 for the response : %v", tests.Failed, testID, w.Code)
			}
			t.Logf("\t%s\tTest %d:\tShould receive a status code of 200 for the response.", tests.Success, testID)
		}

		var got user.Info
		if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
			t.Fatalf("\t%s\tTest %d:\tShould be able to unmarshal the response : %v", tests.Failed, testID, err)
		}

		// Define that we wanted to receive. We will just trust the generated
		// fields like ID and Dates so we copy u.
		exp := got
		exp.Name = "John Doe"
		exp.Email = "johndoe@test.com"
		exp.Roles = []string{auth.RoleAdmin}

		if diff := cmp.Diff(got, exp); diff != "" {
			t.Fatalf("\t%s\tTest %d:\tShould get the expected result. Diff:\n%s", tests.Failed, testID, diff)
		}
		t.Logf("\t%s\tTest %d:\tShould get the expected result.", tests.Success, testID)
	}
}

// putUser204 calidates updating a user that does exist.
func (ut *UserTests) putUser204(t *testing.T, id string) {
	body := `{"name": "Doe John"}`

	r := httptest.NewRequest(http.MethodPut, "/users/"+id, strings.NewReader(body))
	w := httptest.NewRecorder()

	r.Header.Set("Authorization", "Bearer "+ut.adminToken)
	ut.app.ServeHTTP(w, r)

	t.Log("Given the need to validate updating a user with the users endpoint.")
	{
		testID := 0
		t.Logf("\tTest %d:\tWhen using the modified user valies.", testID)
		{
			if w.Code != http.StatusNoContent {
				t.Fatalf("\t%s\tTest %d:\tShould receive a status code of 204 for the response : %v", tests.Failed, testID, w.Code)
			}
			t.Logf("\t%s\tTest %d:\tShould receive a status code of 204 for the response.", tests.Success, testID)

			r := httptest.NewRequest(http.MethodGet, "/users/"+id, nil)
			w := httptest.NewRecorder()

			r.Header.Set("Authorization", "Bearer "+ut.adminToken)
			ut.app.ServeHTTP(w, r)

			if w.Code != http.StatusOK {
				t.Fatalf("\t%s\tTest %d:\tShould receive a status code of 200 for the retrieve : %v", tests.Failed, testID, w.Code)
			}
			t.Logf("\t%s\tTest %d:\tShould receive a status code of 200 for the retrieve.", tests.Success, testID)

			var ru user.Info

			if err := json.NewDecoder(w.Body).Decode(&ru); err != nil {
				t.Fatalf("\t%s\tTest %d:\tShould be able to unmarshal the response : %v", tests.Failed, testID, err)
			}

			if ru.Name != "Doe John" {
				t.Fatalf("\t%s\tTest %d:\tShould see an updated Name : got %q want %q", tests.Failed, testID, ru.Name, "Doe John")
			}
			t.Logf("\t%s\tTest %d:\tShould see an updated Name.", tests.Failed, testID)

			if ru.Email != "johndoe@test.com" {
				t.Fatalf("\t%s\tTest %d:\tShould not affect other fields like Email : got %q want %q", tests.Failed, testID, ru.Email, "johndoe@test.com")
			}
			t.Logf("\t%s\tTest %d:\tShould not affect other fields like Email.", tests.Failed, testID)
		}
	}
}

// putUser403 validates a user can't modify users unless they are an admin.
func (ut *UserTests) putUser403(t *testing.T, id string) {
	body := `{"name": "Dow Jones"}`

	r := httptest.NewRequest(http.MethodPut, "/users/"+id, strings.NewReader(body))
	w := httptest.NewRecorder()

	r.Header.Set("Authorization", "Bearer "+ut.userToken)
	ut.app.ServeHTTP(w, r)

	t.Log("Given the need update a user with the users endpoint.")
	{
		testID := 0
		t.Logf("\tTest %d:\tWhen a non-admin user makes a request", testID)
		{
			if w.Code != http.StatusForbidden {
				t.Fatalf("\t%s\tTest %d:\tShould receive a status code of 403 for the response : %v", tests.Failed, testID, w.Code)
			}
			t.Logf("\t%s\tTest %d:\tShould receive a status code of 403 for the response.", tests.Failed, testID)
		}
	}
}

// getToken401 ensures an unkonwn user can't generate a token.
func (ut *UserTests) getToken401(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "users/token", nil)
	w := httptest.NewRecorder()

	r.SetBasicAuth("unknown@example.com", "some-password")
	ut.app.ServeHTTP(w, r)

	t.Log("Given the need to deny tokens to unknown users.")
	{
		testID := 0
		t.Logf("\tTest %d:\tWhen fetching a token with unrecognized email.", testID)
		{
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("\t%s\tTest %d:\tShould receive a status code of 401 for the response : %v", tests.Failed, testID, w.Code)
			}
			t.Logf("\t%s\tTest %d:\tShould receive a status code of 401 for the response.", tests.Failed, testID)
		}
	}
}

// getToken200 validates a user can acces the token.
func (ut *UserTests) getToken200(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "users/token", nil)
	w := httptest.NewRecorder()

	r.SetBasicAuth("johndoe@test.com", "gophers")
	ut.app.ServeHTTP(w, r)

	t.Log("Given the need to recieve token to recognized user.")
	{
		testID := 0
		t.Logf("\tTest %d:\tWhen fetching a token with recognized email.", testID)
		{
			if w.Code != http.StatusOK {
				t.Fatalf("\t%s\tTest %d:\tShould receive a status code of 200 for the response : %v", tests.Failed, testID, w.Code)
			}
			t.Logf("\t%s\tTest %d:\tShould receive a status code of 200 for the response.", tests.Failed, testID)
			var got struct {
				Token string `json:"token"`
			}

			if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
				t.Fatalf("\t%s\tTest %d:\tShould be able to unmarshal the response : %v", tests.Failed, testID, err)
			}
			t.Logf("\t%s\tTest %d:\tShould be able to unmarshal the response.", tests.Success, testID)
		}
	}
}

// postUser400 ensures thet user can not be created with invalid params.
func (ut *UserTests) postUser400(t *testing.T) {
	body, err := json.Marshal(&user.NewUser{})
	if err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodPost, "/users", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	r.Header.Set("Authorization", "Bearer "+ut.adminToken)
	ut.app.ServeHTTP(w, r)

	t.Log("Given the need to deny user creation with invalid parameters.")
	{
		testID := 0
		t.Logf("\tTest %d:\tWhen using an incomplete user value.", testID)
		{
			if w.Code != http.StatusBadRequest {
				t.Fatalf("\t%s\tTest %d:\tShould receive a status code of 400 for the response : %v", tests.Failed, testID, w.Code)
			}
			t.Logf("\t%s\tTest %d:\tShould receive a status code of 400 for the response.", tests.Success, testID)
		}
	}
}

// postUser403 validates a user can't be created unless the calling user is
// authenticated.
func (ut *UserTests) postUser403(t *testing.T) {
	body, err := json.Marshal(&user.NewUser{})
	if err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodPost, "/users", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	ut.app.ServeHTTP(w, r)

	t.Log("Given the need to deny user creation with invalid parameters.")
	{
		testID := 0
		t.Logf("\tTest %d:\tWhen using an incomplete user value.", testID)
		{
			if w.Code != http.StatusForbidden {
				t.Fatalf("\t%s\tTest %d:\tShould receive a status code of 403 for the response : %v", tests.Failed, testID, w.Code)
			}
			t.Logf("\t%s\tTest %d:\tShould receive a status code of 403 for the response.", tests.Success, testID)
		}
	}
}

// postUser401 validates a user can't be created unless the calling user is
// an admin. Regular users can't do this.
func (ut *UserTests) postUser401(t *testing.T) {
	body, err := json.Marshal(&user.NewUser{})
	if err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodPost, "/users", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	r.Header.Set("Authorization", "Bearer "+ut.userToken)
	ut.app.ServeHTTP(w, r)

	t.Log("Given the need to deny user creation with invalid parameters.")
	{
		testID := 0
		t.Logf("\tTest %d:\tWhen using an incomplete user value.", testID)
		{
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("\t%s\tTest %d:\tShould receive a status code of 403 for the response : %v", tests.Failed, testID, w.Code)
			}
			t.Logf("\t%s\tTest %d:\tShould receive a status code of 403 for the response.", tests.Success, testID)
		}
	}
}

// getUser400 validates a user request for a malformed userid.
func (ut *UserTests) getUser400(t *testing.T) {
	id := "12345"

	r := httptest.NewRequest(http.MethodGet, "/users/"+id, nil)
	w := httptest.NewRecorder()

	r.Header.Set("Authorization", "Bearer "+ut.adminToken)
	ut.app.ServeHTTP(w, r)

	t.Log("Given the need to validate getting a user with malformed id.")
	{
		testID := 0
		t.Logf("\tTest %d:\tWhen using the new user %s.", testID, id)
		{
			if w.Code != http.StatusBadRequest {
				t.Fatalf("\t%s\tTest %d:\tShould receive a status code of 400 for the response : %v", tests.Failed, testID, w.Code)
			}
			t.Logf("\t%s\tTest %d:\tShould receive a status code of 400 for the response.", tests.Success, testID)
		}
	}
}

// getUser403 validates a regular user can't fetch anyone but themselves.
func (ut *UserTests) getUser403(t *testing.T) {
	t.Log("Given the need to validate reqular users can't fetch other users.")
	{
		testID := 0
		t.Logf("\tTest %d:\tWhen fetching the admin user as a regular user.", testID)
		{
			const adminID = "5cf37266-3473-4006-984f-9325122678b7"

			r := httptest.NewRequest(http.MethodGet, "/users/"+adminID, nil)
			w := httptest.NewRecorder()

			r.Header.Set("Authorization", "Bearer "+ut.userToken)
			ut.app.ServeHTTP(w, r)

			if w.Code != http.StatusForbidden {
				t.Fatalf("\t%s\tTest %d:\tShould receive a status code of 403 for the response : %v", tests.Failed, testID, w.Code)
			}
			t.Logf("\t%s\tTest %d:\tShould receive a status code of 403 for the response.", tests.Success, testID)
		}

		testID = 1
		t.Logf("\tTest %d:\tWhen fetching the user as themselves.", testID)
		{
			const userID = "45b5fbd3-755f-4379-8f07-a58d4a30fa2f"

			r := httptest.NewRequest(http.MethodGet, "/users/"+userID, nil)
			w := httptest.NewRecorder()

			r.Header.Set("Authorization", "Bearer "+ut.userToken)
			ut.app.ServeHTTP(w, r)

			if w.Code != http.StatusOK {
				t.Fatalf("\t%s\tTest %d:\tShould receive a status code of 200 for the response : %v", tests.Failed, testID, w.Code)
			}
			t.Logf("\t%s\tTest %d:\tShould receive a status code of 200 for the response.", tests.Success, testID)
		}
	}
}

// getUser404 validates a user request for unrecognized userid.
func (ut *UserTests) getUser404(t *testing.T) {
	id := "a2b0639f-2cc6-44b8-b97b-15d69dbb511e"

	r := httptest.NewRequest(http.MethodGet, "/users/"+id, nil)
	w := httptest.NewRecorder()

	r.Header.Set("Authorization", "Bearer "+ut.adminToken)
	ut.app.ServeHTTP(w, r)

	t.Log("Given the need to validate getting a user with unrecognized id.")
	{
		testID := 0
		t.Logf("\tTest %d:\tWhen using the new user %s.", testID, id)
		{
			if w.Code != http.StatusNotFound {
				t.Fatalf("\t%s\tTest %d:\tShould receive a status code of 404 for the response : %v", tests.Failed, testID, w.Code)
			}
			t.Logf("\t%s\tTest %d:\tShould receive a status code of 404 for the response.", tests.Success, testID)
		}
	}
}

// deleteUserNotFound validates a user request for unrecognized userid.
func (ut *UserTests) deleteUserNotFound(t *testing.T) {
	id := "a2b0639f-2cc6-44b8-b97b-15d69dbb511e"

	r := httptest.NewRequest(http.MethodDelete, "/users/"+id, nil)
	w := httptest.NewRecorder()

	r.Header.Set("Authorization", "Bearer "+ut.adminToken)
	ut.app.ServeHTTP(w, r)

	t.Log("Given the need to validate getting a user with unrecognized id.")
	{
		testID := 0
		t.Logf("\tTest %d:\tWhen using the new user %s.", testID, id)
		{
			if w.Code != http.StatusNotFound {
				t.Fatalf("\t%s\tTest %d:\tShould receive a status code of 404 for the response : %v", tests.Failed, testID, w.Code)
			}
			t.Logf("\t%s\tTest %d:\tShould receive a status code of 404 for the response.", tests.Success, testID)
		}
	}
}

// putUser404 validates a user request for unrecognized userid.
func (ut *UserTests) putUser404(t *testing.T) {
	id := "a2b0639f-2cc6-44b8-b97b-15d69dbb511e"

	r := httptest.NewRequest(http.MethodPut, "/users/"+id, nil)
	w := httptest.NewRecorder()

	r.Header.Set("Authorization", "Bearer "+ut.adminToken)
	ut.app.ServeHTTP(w, r)

	t.Log("Given the need to validate getting a user with unrecognized id.")
	{
		testID := 0
		t.Logf("\tTest %d:\tWhen using the new user %s.", testID, id)
		{
			if w.Code != http.StatusNotFound {
				t.Fatalf("\t%s\tTest %d:\tShould receive a status code of 404 for the response : %v", tests.Failed, testID, w.Code)
			}
			t.Logf("\t%s\tTest %d:\tShould receive a status code of 404 for the response.", tests.Success, testID)
		}
	}
}
