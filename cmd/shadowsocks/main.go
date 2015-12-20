package main

import (
	"flag"
	log "github.com/Sirupsen/logrus"
	"github.com/kezhuw/shadowsocks"
	"github.com/kezhuw/shadowsocks/config"
	"io/ioutil"
)

var configFile string
var helpUsage bool

func init() {
	flag.StringVar(&configFile, "config", "", "Configuration file")
	flag.BoolVar(&helpUsage, "help", false, "Print usage")
}

func main() {
	flag.Parse()

	if helpUsage || configFile == "" {
		flag.PrintDefaults()
		return
	}

	content, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Errorf("fail to read configuration file: %s", err)
		return
	}

	config, err := config.Parse(content)
	if err != nil {
		log.Errorf("fail to parse configuration from file %s: %s", configFile, err)
		return
	}

	shadowsocks.Serve(config)
}
