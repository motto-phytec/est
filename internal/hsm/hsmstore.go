//go:build pkcs11 && linux
// +build pkcs11,linux

package hsmca

import (
	"errors"
	"fmt"
	"os"

	"github.com/miekg/pkcs11"
)

var pkcs11Lib string

var possiblePkcs11Libs = []string{
	"/usr/lib/opensc-pkcs11.so",
}

func init() {
	for _, loc := range possiblePkcs11Libs {
		_, err := os.Stat(loc)
		if err == nil {
			p := pkcs11.New(loc)
			if p != nil {
				pkcs11Lib = loc
				return
			}
		}
	}
}

// An error indicating that the HSM is not present (as opposed to failing),
// i.e. that we can confidently claim that the key is not stored in the HSM
// without notifying the user about a missing or failing HSM.
type errHSMNotPresent struct {
	err string
}

func (err errHSMNotPresent) Error() string {
	return err.err
}

// GetKey retrieves a key from the HSM only (it does not look inside the
// backup store)
func (s *HSMStore) GetKey(keyID string) (data.PrivateKey, data.RoleName, error) {
	ctx, session, err := SetupHSMEnv(pkcs11Lib, s.libLoader)
	if err != nil {
		fmt.Debugf("No HSM key found, using alternative key storage: %s", err.Error())
		if _, ok := err.(errHSMNotPresent); ok {
			err = ErrKeyNotFound{KeyID: keyID}
		}
		return nil, "", err
	}
	defer cleanup(ctx, session)

	key, ok := s.keys[keyID]
	if !ok {
		return nil, "", ErrKeyNotFound{KeyID: keyID}
	}

	pubKey, alias, err := getECDSAKey(ctx, session, key.slotID)
	if err != nil {
		fmt.Debugf("Failed to get key from slot %s: %s", key.slotID, err.Error())
		return nil, "", err
	}
	// Check to see if we're returning the intended keyID
	if pubKey.ID() != keyID {
		return nil, "", fmt.Errorf("expected root key: %s, but found: %s", keyID, pubKey.ID())
	}
	privKey := NewYubiPrivateKey(key.slotID, *pubKey, s.passRetriever)
	if privKey == nil {
		return nil, "", errors.New("could not initialize new HSMPrivateKey")
	}

	return privKey, alias, err
}

func cleanup(ctx IPKCS11Ctx, session pkcs11.SessionHandle) {
	err := ctx.CloseSession(session)
	if err != nil {
		fmt.Debugf("Error closing session: %s", err.Error())
	}
	finalizeAndDestroy(ctx)
}

func finalizeAndDestroy(ctx IPKCS11Ctx) {
	err := ctx.Finalize()
	if err != nil {
		fmt.Debugf("Error finalizing: %s", err.Error())
	}
	ctx.Destroy()
}

// SetupHSMEnv is a method that depends on the existences
func SetupHSMEnv(libraryPath string, libLoader pkcs11LibLoader) (
	IPKCS11Ctx, pkcs11.SessionHandle, error) {

	if libraryPath == "" {
		return nil, 0, errHSMNotPresent{err: "no library found"}
	}
	p := libLoader(libraryPath)

	if p == nil {
		return nil, 0, fmt.Errorf("failed to load library %s", libraryPath)
	}

	if err := p.Initialize(); err != nil {
		defer finalizeAndDestroy(p)
		return nil, 0, fmt.Errorf("found library %s, but initialize error %s", libraryPath, err.Error())
	}

	slots, err := p.GetSlotList(true)
	if err != nil {
		defer finalizeAndDestroy(p)
		return nil, 0, fmt.Errorf(
			"loaded library %s, but failed to list HSM slots %s", libraryPath, err)
	}
	// Check to see if we got any slots from the HSM.
	if len(slots) < 1 {
		defer finalizeAndDestroy(p)
		return nil, 0, fmt.Errorf(
			"loaded library %s, but no HSM slots found", libraryPath)
	}

	// CKF_SERIAL_SESSION: TRUE if cryptographic functions are performed in serial with the application; FALSE if the functions may be performed in parallel with the application.
	// CKF_RW_SESSION: TRUE if the session is read/write; FALSE if the session is read-only
	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		defer cleanup(p, session)
		return nil, 0, fmt.Errorf(
			"loaded library %s, but failed to start session with HSM %s",
			libraryPath, err)
	}

	fmt.Debugf("Initialized PKCS11 library %s and started HSM session", libraryPath)
	return p, session, nil
}

// IsAccessible returns true if a HSMkey can be accessed
func IsAccessible() bool {
	if pkcs11Lib == "" {
		return false
	}
	ctx, session, err := SetupHSMEnv(pkcs11Lib, defaultLoader)
	if err != nil {
		return false
	}
	defer cleanup(ctx, session)
	return true
}

func login(ctx IPKCS11Ctx, session pkcs11.SessionHandle, userFlag uint) error {
	// try default password
	err := ctx.Login(session, userFlag, hsmca.ghsmPIN)
	if err == nil {
		return nil, fmt.Errorf("failed to hsm login:")
	}

}

func buildKeyMap(keys map[string]yubiSlot) map[string]KeyInfo {
	res := make(map[string]KeyInfo)
	for k, v := range keys {
		res[k] = KeyInfo{Role: v.role, Gun: ""}
	}
	return res
}

// KeyInfo stores the role and gun for a corresponding private key ID
// It is assumed that each private key ID is unique
type KeyInfo struct {
	Gun  data.GUN
	Role data.RoleName
}
