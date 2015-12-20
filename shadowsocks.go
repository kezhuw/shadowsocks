package shadowsocks

import (
	log "github.com/Sirupsen/logrus"
	"github.com/kezhuw/shadowsocks/config"
	"github.com/kezhuw/shadowsocks/local"
	"github.com/kezhuw/shadowsocks/server"
	"sync"
)

func Serve(configs *config.Config) {
	if len(configs.Locals) == 0 && len(configs.Servers) == 0 {
		log.Fatal("no locals or servers")
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		local.Serve(configs.Locals)
	}()
	go func() {
		defer wg.Done()
		server.Serve(configs.Servers)
	}()
	wg.Wait()
}
