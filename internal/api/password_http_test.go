package api_test

import "testing"

func TestPasswordEndpointRequiresBearer(t *testing.T) {
	srv, tok := setup(t)
	do(t, srv, "", "POST", "/api/v1/auth/password", `{}`, 401)
	// Auth objects without a durable password directory refuse writes.
	do(t, srv, tok, "POST", "/api/v1/auth/password", `{"current_password":"s3cret-pass","new_password":"another-password"}`, 503)
}
