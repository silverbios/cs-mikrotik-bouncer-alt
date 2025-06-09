package main

import (
	"fmt"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/jellydator/ttlcache/v3"
	"github.com/rs/zerolog/log"
)

func (mal *mikrotikAddrList) add(decision *models.Decision) bool {

	log.Info().
		Str("func", "add").
		Str("duration", *decision.Duration).
		Str("origin", *decision.Origin).
		Str("scenario", *decision.Scenario).
		Str("scope", *decision.Scope).
		// Bool("simulated", *decision.Simulated).
		// Int64("id", decision.ID).
		// Str("type", *decision.Type).
		// Str("until", decision.Until).
		// Str("uuid", decision.UUID).
		Str("value", *decision.Value).
		Msg("Processing new decision to add")

	address := *decision.Value
	newTTL := setTTL(*decision.Duration)
	proto := getProtoCmd(address)

	if proto == "ip" && !useIPV4 {
		log.Debug().
			Str("func", "add").
			Str("address", address).
			Str("new_ttl", newTTL.String()).
			Msg("skipping, IPv4 not enabled")
		metricDecision.WithLabelValues(proto, "add", "skip").Inc()
		return false
	}

	if proto == "ipv6" && !useIPV6 {
		log.Debug().
			Str("func", "add").
			Str("address", address).
			Str("new_ttl", newTTL.String()).
			Msg("skipping, IPv6 not enabled")
		metricDecision.WithLabelValues(proto, "add", "skip").Inc()
		return false
	}

	if proto == "ipv6" && useIPV6 {
		address += "/128"
	}

	// TODO: allow formatting comment for decision
	comment := fmt.Sprintf("%s %s %s", *decision.Origin, *decision.Scenario, *decision.Scope)

	var item = &ttlcache.Item[string, string]{}

	if mal.cache.Has(address) {
		metricCache.WithLabelValues("add", "hit").Inc()
		item = mal.cache.Get(address)
		currentTTL := time.Until(item.ExpiresAt())

		switch {
		case newTTL == currentTTL:
			metricDecision.WithLabelValues(proto, "add", "update_equal").Inc()
		case newTTL > currentTTL:
			metricDecision.WithLabelValues(proto, "add", "update_extend").Inc()
		case newTTL < currentTTL:
			metricDecision.WithLabelValues(proto, "add", "update_shorten").Inc()
		}
		log.Info().
			Str("func", "add").
			Str("address", address).
			Str("current_ttl", currentTTL.String()).
			Str("new_ttl", newTTL.String()).
			Msg("Address is in the cache, updating")

	} else {
		metricCache.WithLabelValues("add", "miss").Inc()
		log.Info().
			Str("func", "add").
			Str("address", address).
			Str("new_ttl", newTTL.String()).
			Msg("Address not in cache, adding")
		metricDecision.WithLabelValues(proto, "add", "insert").Inc()
	}

	mal.cache.Set(address, comment, newTTL)
	return true
}

func (mal *mikrotikAddrList) remove(decision *models.Decision) bool {

	log.Info().
		Str("func", "remove").
		Str("duration", *decision.Duration).
		Str("origin", *decision.Origin).
		Str("scenario", *decision.Scenario).
		Str("scope", *decision.Scope).
		// Bool("simulated", *decision.Simulated).
		// Int64("id", decision.ID).
		// Str("type", *decision.Type).
		// Str("until", decision.Until).
		// Str("uuid", decision.UUID).
		Str("value", *decision.Value).
		Msg("Processing new decision to remove")

	proto := getProtoCmd(*decision.Value)
	address := *decision.Value
	newTTL := setTTL(*decision.Duration)
	if proto == "ip" && !useIPV4 {
		log.Debug().
			Str("func", "remove").
			Str("address", address).
			Str("new_ttl", newTTL.String()).
			Msg("skipping, IPv4 not enabled")
		metricDecision.WithLabelValues(proto, "remove", "skip").Inc()
		return false
	}

	if proto == "ipv6" && !useIPV6 {
		log.Debug().
			Str("func", "remove").
			Str("address", address).
			Str("new_ttl", newTTL.String()).
			Msg("skipping, IPv6 not enabled")
		metricDecision.WithLabelValues(proto, "remove", "skip").Inc()
		return false
	}

	var item = &ttlcache.Item[string, string]{}

	if mal.cache.Has(address) {
		metricCache.WithLabelValues("del", "hit").Inc()
		item = mal.cache.Get(address)
		currentTTL := time.Until(item.ExpiresAt())
		log.Info().
			Str("func", "remove").
			Str("address", address).
			Str("ttl", currentTTL.String()).
			Msgf("Address is in the cache, removing")
		metricDecision.WithLabelValues(proto, "remove", "remove").Inc()
		mal.cache.Delete(address)
		return true

	} else {
		log.Info().
			Str("func", "remove").
			Str("address", address).
			Str("new_ttl", newTTL.String()).
			Msg("Address not in cache, nothing to do")

		metricCache.WithLabelValues("del", "miss").Inc()
		metricDecision.WithLabelValues(proto, "remove", "no_op").Inc()
		return false
	}

}

// decisionProcess runs in a loop every 5 seconds by default
//
// so if there are some changes we will process them, such as add/remove
//
// then if there were any decisions there will be a trigger of swapping address-lists in firewall rules
// thus we create a new list and use it as new
// old rule should auto-expire so there is no need fo cleanups
func (mal *mikrotikAddrList) decisionProcess(streamDecision *models.DecisionsStreamResponse) {

	decisionsAdded := 0
	decisionsDeleted := 0

	for _, decision := range streamDecision.Deleted {
		if mal.remove(decision) {
			decisionsDeleted++
		}
		if decisionsDeleted == debugDecisionsMax {
			break
		}
	}

	for _, decision := range streamDecision.New {

		if mal.add(decision) {
			decisionsAdded++
		}
		if decisionsAdded == debugDecisionsMax {
			break
		}
	}

	if triggerOnUpdate && ((decisionsAdded > 0) || (decisionsDeleted > 0)) {
		log.Info().
			Str("func", "decisionProcess").
			Msg("detected decision changes, triggering mikrotik update now")
		runMikrotikCommands(mal)
	}
}

// setTTL parses input time string
// if it cannot parse it then it returns default cache duration and spews warning to log
func setTTL(timeStr string) time.Duration {
	ttl, err := ParseMikrotikDuration(timeStr)
	if err != nil {
		ttl = defaultTTL
		log.Warn().Err(err).
			Str("func", "setTTL").
			Str("input", timeStr).
			Str("effective", ttl.String()).
			Msg("Failed to parse input mikrotik timeout value, setting default TTL")
	}
	return ttl
}
