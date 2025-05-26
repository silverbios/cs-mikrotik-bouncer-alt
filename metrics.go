package main

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

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
