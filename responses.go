package goauth

// AuthResponse is returned by register, login, and refresh endpoints.
type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
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
