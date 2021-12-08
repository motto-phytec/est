/*
Copyright (c) 2020 GMO GlobalSign, Inc.

Licensed under the MIT License (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at

https://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package hsmca

import "fmt"

// caError is an internal error structure implementing est.Error.
type caError struct {
	status     int
	desc       string
	retryAfter int
}

// StatusCode returns the HTTP status code.
func (e caError) StatusCode() int {
	return e.status
}

// Error returns a human-readable description of the error.
func (e caError) Error() string {
	return e.desc
}

// RetryAfter returns the value in seconds after which the client should
// retry the request.
func (e caError) RetryAfter() int {
	return e.retryAfter
}

// ErrAttemptsExceeded is returned when too many attempts have been made to decrypt a key
type ErrAttemptsExceeded struct{}

// ErrAttemptsExceeded is returned when too many attempts have been made to decrypt a key
func (err ErrAttemptsExceeded) Error() string {
	return "maximum number of passphrase attempts exceeded"
}

// ErrPasswordInvalid is returned when signing fails. It could also mean the signing
// key file was corrupted, but we have no way to distinguish.
type ErrPasswordInvalid struct{}

// ErrPasswordInvalid is returned when signing fails. It could also mean the signing
// key file was corrupted, but we have no way to distinguish.
func (err ErrPasswordInvalid) Error() string {
	return "password invalid, operation has failed."
}

// ErrKeyNotFound is returned when the keystore fails to retrieve a specific key.
type ErrKeyNotFound struct {
	KeyID string
}

// ErrKeyNotFound is returned when the keystore fails to retrieve a specific key.
func (err ErrKeyNotFound) Error() string {
	return fmt.Sprintf("signing key not found: %s", err.KeyID)
}
