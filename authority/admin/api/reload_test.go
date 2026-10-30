package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/linkedca"
)

func TestReloadAdminResourcesRoute(t *testing.T) {
	for _, tc := range []struct {
		name      string
		method    string
		token     string
		authErr   error
		enabled   bool
		adminType linkedca.Admin_Type
		reloadErr error
		status    int
		calls     int
	}{
		{name: "super-admin", method: "POST", token: "signed-admin-token", enabled: true, adminType: linkedca.Admin_SUPER_ADMIN, status: http.StatusOK, calls: 1},
		{name: "missing-token", method: "POST", enabled: true, status: http.StatusUnauthorized},
		{name: "invalid-token", method: "POST", token: "invalid", enabled: true, authErr: admin.NewError(admin.ErrorUnauthorizedType, "invalid token"), status: http.StatusUnauthorized},
		{name: "disabled-api", method: "POST", token: "signed-admin-token", adminType: linkedca.Admin_SUPER_ADMIN, status: http.StatusNotImplemented},
		{name: "ordinary-admin", method: "POST", token: "signed-admin-token", enabled: true, adminType: linkedca.Admin_ADMIN, status: http.StatusUnauthorized},
		{name: "reload-error", method: "POST", token: "signed-admin-token", enabled: true, adminType: linkedca.Admin_SUPER_ADMIN, reloadErr: errors.New("database unavailable"), status: http.StatusInternalServerError, calls: 1},
		{name: "get-does-not-mutate", method: "GET", token: "signed-admin-token", enabled: true, adminType: linkedca.Admin_SUPER_ADMIN, status: http.StatusMethodNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			auth := &mockAdminAuthority{
				MockIsAdminAPIEnabled: func() bool { return tc.enabled },
				MockAuthorizeAdminToken: func(r *http.Request, token string) (*linkedca.Admin, error) {
					require.Equal(t, tc.token, token)
					if tc.authErr != nil {
						return nil, tc.authErr
					}
					return &linkedca.Admin{Type: tc.adminType}, nil
				},
				MockReloadAdminResources: func(ctx context.Context) error {
					calls++
					require.Equal(t, linkedca.Admin_SUPER_ADMIN, linkedca.MustAdminFromContext(ctx).Type)
					return tc.reloadErr
				},
			}
			mockMustAuthority(t, auth)
			router := chi.NewRouter()
			router.Route("/admin", func(r chi.Router) { Route(r) })
			req := httptest.NewRequest(tc.method, "/admin/resources/reload", http.NoBody)
			if tc.token != "" {
				req.Header.Set("Authorization", tc.token)
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			require.Equal(t, tc.status, w.Code, w.Body.String())
			require.Equal(t, tc.calls, calls)
			if tc.status == http.StatusOK {
				var response ReloadAdminResourcesResponse
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
				require.Equal(t, "ok", response.Status)
			}
		})
	}
}
