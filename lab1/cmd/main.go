package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"
)

type Right uint

type GUID [16]byte

const (
	Default Right = 1 << iota
	Admin
)

type User struct {
	ID          int
	Username    string
	Password    string
	CreatedDate time.Time
	Rights      Right
}

type (
	UserServiceInfo struct {
		Username    string
		CreatedDate time.Time
		Rights      Right
	}
	ISessionAccessor interface {
		AddSession(sessionID string, user *User)
		DeleteSession(sessionID string)
		GetUserServiceInfoBySession(sessionID string) (*UserServiceInfo, error)
		EnsureAdmin(user UserServiceInfo) bool
		EnsureAdminOrDefault(user UserServiceInfo) bool
	}
	SessionAccessor struct {
		sessions map[string]UserServiceInfo
	}
)

func NewSessionAccessor() *SessionAccessor {
	return &SessionAccessor{sessions: make(map[string]UserServiceInfo)}
}
func (s *SessionAccessor) GetUserServiceInfoBySession(sessionID string) (*UserServiceInfo, error) {
	user, ok := s.sessions[sessionID]

	if !ok {
		return nil, errors.New("user session is not stored")
	}

	return &user, nil
}
func (s *SessionAccessor) EnsureAdmin(user UserServiceInfo) bool {
	return hasFlag(user.Rights, Admin)
}
func (s *SessionAccessor) EnsureAdminOrDefault(user UserServiceInfo) bool {
	return hasFlag(user.Rights, Admin) || hasFlag(user.Rights, Default)
}
func (s *SessionAccessor) AddSession(sessionID string, user *User) {
	s.sessions[sessionID] = UserServiceInfo{
		Username:    user.Username,
		CreatedDate: user.CreatedDate,
		Rights:      user.Rights,
	}
}
func (s *SessionAccessor) DeleteSession(sessionID string) {
	delete(s.sessions, sessionID)
}

type (
	IUserProxy interface {
		Create(username string, password string)
		Delete(id int)
		GetByUserName(username string) *User
	}
	UserProxy struct {
		sessionAccessor ISessionAccessor
		userService     IUserService
	}
)

func NewUserProxy(sessionAccessor ISessionAccessor, userService IUserService) *UserProxy {
	return &UserProxy{sessionAccessor: sessionAccessor, userService: userService}
}
func (u *UserProxy) Create(username string, password string) {
	user, err := u.sessionAccessor.GetUserServiceInfoBySession("123")
	if err != nil {
		return
	}
	u.sessionAccessor.EnsureAdmin(*user)

}
func (u *UserProxy) Delete(id int) {
	user, err := u.sessionAccessor.GetUserServiceInfoBySession("123")
	if err != nil {
		return
	}
	u.sessionAccessor.EnsureAdmin(*user)
}
func (u *UserProxy) GetByUserName(username string) *User {
	return u.userService.GetByUserName(username)
}

type (
	IUserService interface {
		Create(username string, password string) *User
		Update(user *User) *User
		GetByUserName(username string) *User
		Delete(username string) bool
	}
	UserService struct {
		users map[string]*User
	}
)

func NewUserService() *UserService {
	return &UserService{users: make(map[string]*User)}
}
func (u *UserService) Create(username string, password string) *User {
	entity := &User{
		ID:          len(u.users),
		Username:    username,
		Password:    password,
		CreatedDate: time.Now().UTC(),
		Rights:      Default,
	}
	u.users[username] = entity
	return entity
}
func (u *UserService) GetByUserName(username string) *User {
	return u.users[username]
}
func (u *UserService) Update(user *User) *User {
	u.users[user.Username] = user
	return u.users[user.Username]
}
func (u *UserService) Delete(username string) bool {
	delete(u.users, username)
	return true
}

type UserController struct {
	userProxy IUserProxy
}

func (receiver UserController) Create() func(writer http.ResponseWriter, request *http.Request) {
	return func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost {
			username := request.FormValue("username")
			password := request.FormValue("password")
			receiver.userProxy.Create(username, password)
		}
	}
}

func NewUserController(userProxy IUserProxy) *UserController {
	return &UserController{userProxy: userProxy}
}

type AuthController struct {
	userProxy       IUserProxy
	sessionAccessor ISessionAccessor
}

func NewAuthController(userProxy IUserProxy, sessionAccessor ISessionAccessor) *AuthController {
	return &AuthController{userProxy: userProxy, sessionAccessor: sessionAccessor}
}
func (receiver AuthController) SignIn() func(writer http.ResponseWriter, request *http.Request) {
	return func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet {
			username := request.FormValue("username")
			user := receiver.userProxy.GetByUserName(username)
			if user.Password == request.FormValue("password") {
				guid := newGUID()
				cookie := &http.Cookie{
					Name:     "session",
					Path:     "/",
					Value:    guid.String(),
					Expires:  time.Now().AddDate(0, 0, 30),
					Secure:   true,
					HttpOnly: true,
					SameSite: http.SameSiteNoneMode,
				}
				receiver.sessionAccessor.AddSession(guid.String(), user)

				http.SetCookie(writer, cookie)
				return
			}
		}
	}
}
func (receiver AuthController) SignOut() func(writer http.ResponseWriter, request *http.Request) {
	return func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet {
			sessionID, err := request.Cookie("session")
			if err == nil {
				if _, err := receiver.sessionAccessor.GetUserServiceInfoBySession(sessionID.Value); err == nil {
					receiver.sessionAccessor.DeleteSession(sessionID.Value)
				}
			}

		}
	}
}

type AdminController struct {
}

type SomeMockUpController struct {
}

func main() {
	sessionAccessor := NewSessionAccessor()
	userService := NewUserService()
	userProxy := NewUserProxy(sessionAccessor, userService)
	initAdmin(userService)

	controller := NewAuthController(userProxy, sessionAccessor)

	router := http.NewServeMux()
	router.HandleFunc("/sign-in", controller.SignIn())
	router.HandleFunc("/sign-out", controller.SignOut())

	log.Fatal(http.ListenAndServe(":8080", router))
}

func initAdmin(userService *UserService) {
	admin := userService.Create("admin", "password")
	admin.Rights |= Admin
	userService.Update(admin)
}

func hasFlag(mask Right, flags Right) bool {
	return uint(mask)&uint(flags) == uint(flags)
}

func newGUID() GUID {
	guid := new(GUID)

	_, err := rand.Read(guid[:])
	if err != nil {
		panic(err)
	}

	guid[6] = (guid[6] & 0x0f) | 0x40
	guid[8] = (guid[8] & 0x3f) | 0x80

	return *guid
}

func (guid GUID) String() string {
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		guid[0:4], guid[4:6], guid[6:8], guid[8:10], guid[10:])
}
