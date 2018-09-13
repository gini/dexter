package utils

import (
	"errors"
	"fmt"
	"math/rand"
	"os/exec"
	"runtime"
)

// helper to generate a random string
func RandomString() string {
	var letter = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._+")

	b := make([]rune, 64)
	for i := range b {
		b[i] = letter[rand.Intn(len(letter))]
	}
	return string(b)
}

// point browser to the authCode URL
func OpenURL(url string) error {
	var cmd string
	var args []string

	// find the right command for MacOS & Linux
	switch os := runtime.GOOS; os {
	case "darwin":
		cmd = "open"
	case "linux":
		cmd = "xdg-open"
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler"}
	}

	// append url
	args = append(args, url)

	// run command
	err := exec.Command(cmd, args...).Start()

	if err != nil {
		return errors.New(fmt.Sprintf("command '%s' failed: %s", cmd, err))
	}

	return nil
}
