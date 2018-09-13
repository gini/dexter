# Changes to the orginal project

Golang shines at cross-platform development, even though it does not seem that the original project was tested on Windows it almost worked as is. 
However there were a few things that I wanted to improve to make it useful to me. Below is the list of these changes.

## Building

The original project is build with Makefile, which does not work on Windows. Even on linux / mac `go get` does not run the Makefile it runs `go build`.
Since the project was injecting some variables values at compile time `dexter version` would give empty values after `go get` for version, git hash and date of build.
In order to make it more windows friendly and work out of the box I set out to do some destruction:

- Git hash and the date of build were removed completely. I did not find them valueable enough to keep.
- Version is now hardcoded

One of the "killer features" of the appliction is that you can embed your default google application credentials to the binary during the build. If we do away with 
"automatic" build-time embedding (which we have to if don't want to write separate build scripts for windows and linux/mac) we need to provide a "manual" alternative.
To that end I moved `defaultClientID` and `defaultClientSecret` in a separate file `cmd/data.go`. When you build the binary for your own use, 
please define the default values there, be careful not to commit them to git accidently.

Since the `go get` version of the binaray does not have default values I also added a error message when there is no default values and the user did not provide them
on the command line. Before that the application tried to open the URL with empty client ID which did not work very well.

You can install a generic version of application without embedded credentials by running:

```bash
go get github.com/andrewsav-datacom/dexter
```
use `go build` to rebuild the app once you modified `data.go` to embed your data.

Since I do not use travis, I removed travis build as well.

## Windows console output

In the original version what supposed to be colored output displayed as mangled control characters instead on Windows. I hope that I fixed that.
As mentioned above I also added a error message if Client ID / Client secret are not provide.

## Future-proofing

The user info endpoint was hardcode to use version 3. I changed that to use oauth2 discover to get the end point url from the server. 
This will make sure that the program will keep working when Google bumps the current version of the oauth2 api. 
In addition I put all uses of "https://accounts.google.com" into a variable. I theory the same workflow can be made work for a different OIDC provider too.
I did not implement that though, as I do not have other than Google to test with.

## Writing out user's email for use with tooling

I'm intending to run dexter as a part of a script, and after it finishes working I want the script to be aware of the email address that the user choose to login with.
Instead of asking the user again, I added `-f filename` switch to dexter, so that the username could be written to the `filename` specified. The script can read it aftewards then
and use it as it sees fit.
