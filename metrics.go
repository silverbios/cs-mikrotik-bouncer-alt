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
	metricPermBans = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "permban_total",
		Help: "Total number of decisions without ttl",
	},
		[]string{"proto"},
	)
	metricMikrotikClient = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mikrotik_client_total",
		Help: "Total number of connection actions executed to mikrotik, such as connect/disconnect",
	},
		[]string{"func", "result"},
	)

	metricMikrotikCmd = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mikrotik_cmd_total",
		Help: "Total number of commands executed in mikrotik",
	},
		[]string{"proto", "func", "operation", "result"},
	)
	metricMikrotikCmdDur = promauto.NewCounter(prometheus.CounterOpts{
		Name: "mikrotik_cmd_duration_total",
		Help: "Total time spend executing commands in mikrotik, in microseconds",
	},
	)
	metricLockWait = promauto.NewCounter(prometheus.CounterOpts{
		Name: "lock_wait_duration_total",
		Help: "Total time spend waiting to get lock to execute commands in mikrotik, in microseconds",
	},
	)
)

// intitMetrics initializes metrics with zero values so that they are available in the graphs
// thus grafana dashboard is not empty
func intitMetrics() {

	if useIPV4 {
		intitMetricsProto("ip")
	}

	if useIPV6 {
		intitMetricsProto("ipv6")
	}
	mikrotikClient := []string{"connect", "disconnect"}
	for _, m := range mikrotikClient {
		metricMikrotikClient.WithLabelValues(m, "error").Add(0)
		metricMikrotikClient.WithLabelValues(m, "success").Add(0)
	}
}

// intitMetricsProto for given protocol such as ip or ipv6
func intitMetricsProto(proto string) {
	add := []string{"insert", "skip", "update_equal", "update_shorten"}
	for _, v := range add {
		metricDecision.WithLabelValues(proto, "add", v).Add(0)
	}

	remove := []string{"no_op", "remove", "skip"}
	for _, v := range remove {
		metricDecision.WithLabelValues(proto, "remove", v).Add(0)
	}

	metricTTLTruncated.WithLabelValues(proto, "false").Add(0)
	metricTTLTruncated.WithLabelValues(proto, "true").Add(0)
	metricPermBans.WithLabelValues(proto).Add(0)

	metricMikrotikCmd.WithLabelValues(proto, "address_list", "add", "error").Add(0)
	metricMikrotikCmd.WithLabelValues(proto, "address_list", "add", "success").Add(0)

	modes := []string{"filter", "raw"}
	for _, mode := range modes {
		metricMikrotikCmd.WithLabelValues(proto, mode, "set", "error").Add(0)
		metricMikrotikCmd.WithLabelValues(proto, mode, "set", "success").Add(0)
	}
}

// recordMetrics generates metrics from metricTTLCacheStats in a loop
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
