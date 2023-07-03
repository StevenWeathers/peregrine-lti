# peregrine-lti an LTI 1.3 library (CURRENTLY IN ACTIVE DEVELOPMENT)

Peregrine LTI is a [Go](https://go.dev) library providing
[Learning Tool Interoperability 1.3](https://www.imsglobal.org/spec/lti/v1p3) (aka LTI 1.3) launch features to aid in
building LTIs without having to master the spec.

## Why?

There are not many open source LTI spec launch libraries available, however most are either defunct or in other languages ([PHP](https://github.com/1EdTech/lti-1-3-php-library), [Python](https://github.com/dmitry-viskov/pylti1.3), [Node](https://github.com/Cvmcosta/ltijs), [Java](https://github.com/UOC/java-lti-1.3)) and I work with Go both professionally and personally.

## What this library is and is not

- This library is a very prescribed solution based on the LTI 1.3 spec, tested against Instructure's [Canvas](https://www.instructure.com/canvas).
- This library is not a clone of the existing libraries in other languages, this is a from scratch library based on the written 1.3 spec and my experience writing this protocol for tools in my career.
- This library is not all features of the *[LTI 1.3](https://www.imsglobal.org/spec/lti/v1p3)/[LTI Advantage](https://www.imsglobal.org/lti-advantage-overview)* spec, the first initial major release is just for the in platform launch experience. Features like Names and Role Provisioning Services, Deep Linking, and Assignment and Grade Services may be added in the future if desired.
- This library does not include any storage solution directly, feel free to use the solution of your choice.
  - If you need an example check the `example-server` branch of this repo for a PostgresSQL example.
- This library is not a server, it provides the functionality to parse the incoming request values, validate, and build a response to send to the learning platform where the your LTI tool is installed.

## Is it ready for production?

Technically the launch flow is feature complete, that is it handles all the required validations as per the LTI 1.3 spec.  However, I am still writing unit tests and testing the library against different LMS (Learning Management System) platforms.  This means that the public API of the library could still change before the `v1.0.0` release.

That being said, this library is in active use so it has been tested and is not just a proof of concept.

## Getting Started

[![Go Reference](https://pkg.go.dev/badge/github.com/StevenWeathers/peregrine-lti.svg)](https://pkg.go.dev/github.com/StevenWeathers/peregrine-lti)

### Installation

```bash
go get github.com/stevenweathers/peregrine-lti
```

### Usage
```go
package main

import (
	"fmt"
	"net/http"
	"github.com/stevenweathers/peregrine-lti/launch"
)

var backendUrl = "https://yourbackendurl.com"
var launchSvc *launch.Service

func handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	params, err := launch.GetLoginParamsFromRequestFormValues(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	response, err := launchSvc.HandleOidcLogin(ctx, params)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// provide your tools endpoint url for the callback
	callbackUrl := fmt.Sprintf("%s/lti/callback", backendUrl)

	redirURL, err := launch.BuildLoginResponseRedirectURL(response.OIDCLoginResponseParams, response.RedirectURL, callbackUrl)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	http.Redirect(w, r, redirURL, http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	params, err := launch.GetCallbackParamsFromRequestFormValues(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	_, err = launchSvc.HandleOidcCallback(ctx, params)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// redirect to your tools starting page
	http.Redirect(w, r, "/", http.StatusFound)
}

func main() {
	dataService := yourDataService{} // interface matching peregrine.ToolDataRepo
	launchSvc = launch.New(launch.Config{
		Issuer:       "yourIssuer", 
		JWTKeySecret: "yourJWTSecretKey",
    }, &dataService)

	// register handlers for the login and callback endpoints
	http.HandleFunc("/lti/login", handleLogin)
	http.HandleFunc("/lti/callback", handleCallback)

	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		panic(err)
	}
}
```

## Contributing

Please read [Contributing guide](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

## License

[![APACHE2 License](https://img.shields.io/github/license/StevenWeathers/peregrine-lti)](LICENSE)

> *Learning Tools Interoperability® (LTI®) is a trademark of the 1EdTech Consortium Inc. (https://www.1edtech.org)*
