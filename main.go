package main

import (
	"github.com/gini/dexter/cmd"
	log "github.com/sirupsen/logrus"
)

func main() {
	// set log format & level
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})
	log.SetLevel(log.InfoLevel)

	cmd.Execute()
}
