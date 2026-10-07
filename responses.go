package goauth

// AuthResponse is returned by register, login, and refresh endpoints.
// In cookie mode the tokens travel in cookies, so the response holds only the user.
type AuthResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	User         User   `json:"user"`
}

// ErrorResponse is returned for all error responses.
type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail contains the machine-readable code and human-readable message.
type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
