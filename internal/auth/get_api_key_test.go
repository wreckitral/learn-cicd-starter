package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetApiKey(t *testing.T) {
	tests := map[string]struct {
		input   http.Header
		wantKey string
		wantErr error
	}{
		"valid api key": {
			input:   http.Header{"Authorization": []string{"ApiKey my-secret-key-123"}},
			wantKey: "my-secret-key-123",
			wantErr: nil,
		},
		"no authorization header included": {
			input:   http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		"malformed header, missing key": {
			input:   http.Header{"Authorization": []string{"ApiKey"}},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		"malformed header - wrong prefix": {
			input:   http.Header{"Authorization": []string{"Bearer my-secret-key-123"}},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tc.input)

			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error '%v', got nil", tc.wantErr)
				}
				if err.Error() != tc.wantErr.Error() {
					t.Fatalf("expected error '%v', got '%v'", tc.wantErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}

			if gotKey != tc.wantKey {
				t.Errorf("expected key '%v', got '%v'", tc.wantKey, gotKey)
			}
		})
	}
}
