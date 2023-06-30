package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/stevenweathers/peregrine-lti/example/store"
	"github.com/stevenweathers/peregrine-lti/launch"
)

var launchSvc *launch.Service
var backendUrl string

func handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	params, err := launchSvc.GetLoginParamsFromRequestFormValues(r)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	response, err := launchSvc.HandleOidcLogin(ctx, params)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	callbackUrl := fmt.Sprintf("%s/lti/callback", backendUrl)

	redirURL, err := launchSvc.BuildLoginResponseRedirectURL(response.OIDCLoginResponseParams, response.RedirectURL, callbackUrl)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	http.Redirect(w, r, redirURL, http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	params, err := launchSvc.GetCallbackParamsFromRequestFormValues(r)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	
	_, err = launchSvc.HandleOidcCallback(ctx, params)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("These are the droids you are looking for!"))
}

func main() {
	ctx := context.Background()
	backendUrl = os.Getenv("BACKEND_URL")
	dataStore := store.New(ctx, os.Getenv("DATABASE_URL"))
	defer dataStore.DB.Close(ctx)
	dataSvc := store.LaunchDataService{
		DB: dataStore.DB,
	}
	launchSvc = launch.New(launch.Config{
		Issuer:       os.Getenv("ISSUER"),
		JWTKeySecret: os.Getenv("JWT_SECRET"),
	}, &dataSvc)
	http.HandleFunc("/lti/login", handleLogin)
	http.HandleFunc("/lti/callback", handleCallback)
	http.HandleFunc("/", handleIndex)

	err := http.ListenAndServe(":9000", nil)
	if err != nil {
		panic(err)
	}
}
