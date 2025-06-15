package main

import (
	"context"
	"fmt"
	"sync"

	"github.com/go-routeros/routeros/v3"
	"github.com/jellydator/ttlcache/v3"
	"github.com/rs/zerolog/log"

	"golang.org/x/sync/errgroup"

	csbouncer "github.com/crowdsecurity/go-cs-bouncer"

	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type mikrotikAddrList struct {
	c *routeros.Client
	// cache map[string]string
	cache *ttlcache.Cache[string, string]
	mutex sync.Mutex
}

func main() {

	initConfig()

	// prometheus metrics
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		if err := http.ListenAndServe(":2112", nil); err != nil && err != http.ErrServerClosed {
			log.Fatal().
				Err(err).
				Str("metrics_address", metricsAddr).
				Msg("Failed to start metrics server on desired address")
		}
	}()
	log.Info().
		Str("func", "main").
		Msgf("Metrics server started")

	bouncer := &csbouncer.StreamBouncer{
		APIKey:         crowdsecBouncerAPIKey,
		APIUrl:         crowdsecBouncerURL,
		TickerInterval: tickerInterval.String(),
		Origins:        crowdsecOrigins,
	}
	if err := bouncer.Init(); err != nil {
		log.Fatal().
			Err(err).
			Str("func", "main").
			Msg("Bouncer init failed")
	}

	var mal mikrotikAddrList

	mal.cache = ttlcache.New[string, string](
		ttlcache.WithDisableTouchOnHit[string, string](), // do not update TTL when reading items
	)
	go mal.cache.Start()             // starts automatic expired item deletion
	go recordMetrics(&mal)           // record metrics
	go runMikrotikCommandsLoop(&mal) // process cached addresses and insert them to MikroTik

	g, ctx := errgroup.WithContext(context.Background())

	g.Go(func() error {
		bouncer.Run(ctx)
		return fmt.Errorf("Bouncer stream halted")
	})

	g.Go(func() error {
		log.Info().
			Str("func", "main").
			Msgf("Processing new and deleted decisions...")

		for {
			select {
			case <-ctx.Done():
				log.Error().
					Str("func", "main").
					Msg("Terminating bouncer process")
				return nil
			case decisions := <-bouncer.Stream:
				mal.decisionProcess(decisions)
			}
		}
	})

	err := g.Wait()

	if err != nil {
		log.Error().
			Err(err).
			Str("func", "main").
			Send()
	}

}
