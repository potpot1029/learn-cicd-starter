package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantResult string
		wantErr    bool
		errMessage string
	}{
		{
			name: "valid authorization header",
			headers: http.Header{
				"Authorization": []string{"ApiKey api-key"},
			},
			wantResult: "api-key",
			wantErr:    false,
			errMessage: "",
		},
		{
			name:       "missing authorization header",
			headers:    http.Header{},
			wantResult: "",
			wantErr:    true,
			errMessage: "no authorization header included",
		},
		{
			name: "malformed authorization header: not ApiKey",
			headers: http.Header{
				"Authorization": []string{"NotApiKey api-key"},
			},
			wantResult: "",
			wantErr:    true,
			errMessage: "malformed authorization header",
		},
		{
			name: "malformed authorization header: wrong format",
			headers: http.Header{
				"Authorization": []string{"api-key"},
			},
			wantResult: "",
			wantErr:    true,
			errMessage: "malformed authorization header",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tc.headers)

			if (err != nil) != tc.wantErr {
				t.Fatalf("GetAPIKey() error = %v, want %v", err, tc.wantErr)
			}

			if tc.wantErr {
				if err.Error() != tc.errMessage {
					t.Errorf("GetAPIKey() error message = %v, want %v", err.Error(), tc.errMessage)
				}
			}

			if apiKey != tc.wantResult {
				t.Errorf("GetAPIKey() apiKey = %v, want %v", apiKey, tc.wantResult)
			}

		})
	}
}
