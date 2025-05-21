package main

import (
	"context"
	"fmt"
	"time"

	"github.com/go-routeros/routeros/v3"
	"github.com/jellydator/ttlcache/v3"
	"github.com/rs/zerolog/log"

	"golang.org/x/sync/errgroup"

	csbouncer "github.com/crowdsecurity/go-cs-bouncer"

	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type mikrotikAddrList struct {
	c *routeros.Client
	// cache map[string]string
	cache *ttlcache.Cache[string, string]
}

var (
	metricTTLCacheStats = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ttlcache_stats",
			Help: "generic ttlcache stats by operation, notice that by implementation those are counters and not gauge",
		},
		[]string{"operation"},
	)

	metricCache = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "cache_count",
		Help: "Cache hit/miss, func is add/remove address from address-list, operation is insert/hit/miss etc",
	},
		[]string{"func", "operation"},
	)

	metricDecision = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "decisions_total",
		Help: "Total number of decisions processed",
	},
		[]string{"proto", "func", "operation"},
	)
	metricTTLTruncated = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "truncated_ttl_total",
		Help: "Total number of decisions processed which had effective ttl set to default_ttl_max",
	},
		[]string{"proto", "truncated"},
	)
	metricMikrotikCmd = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mikrotik_cmd_total",
		Help: "Total number of commands executed in mikrotik",
	},
		[]string{"proto", "func", "operation", "result"},
	)
)

func main() {

	// zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

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
		Msgf("metrics server started")

	bouncer := &csbouncer.StreamBouncer{
		APIKey:         crowdsecBouncerAPIKey,
		APIUrl:         crowdsecBouncerURL,
		TickerInterval: "5s",
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
	go mal.cache.Start() // starts automatic expired item deletion
	go recordMetrics(&mal)

	// mal.initMikrotik() //initialize connection to mikrotik and fetch the current access-list entries

	// defer mal.c.Close()

	g, ctx := errgroup.WithContext(context.Background())

	g.Go(func() error {
		bouncer.Run(ctx)
		return fmt.Errorf("bouncer stream halted")
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
					Msg("terminating bouncer process")
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

func recordMetrics(mal *mikrotikAddrList) {
	go func() {
		for {
			time.Sleep(10 * time.Second)
			metricTTLCacheStats.WithLabelValues("insertions").Set(float64(mal.cache.Metrics().Insertions))
			metricTTLCacheStats.WithLabelValues("hits").Set(float64(mal.cache.Metrics().Hits))
			metricTTLCacheStats.WithLabelValues("misses").Set(float64(mal.cache.Metrics().Misses))
			metricTTLCacheStats.WithLabelValues("evictions").Set(float64(mal.cache.Metrics().Evictions))
		}
	}()
}
