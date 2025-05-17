package main

import (
	"fmt"
	"maps"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/spf13/viper"
)

var (
	addressList           string        // mikrotik filter address-list prefix
	crowdsecBouncerAPIKey string        // crowdsec bouncer API key
	crowdsecBouncerURL    string        // url to crowdsec lapi
	crowdsecOrigins       []string      // CORS
	debugDecisionsMax     int           // max decisions to use when processing, set to low as 3 to enable, default -1, means process everything
	defaultTTL            time.Duration // default time for items without TTL, this is required to allow automatic list expiry, if usure set it to 1d
	firewallRuleIdsIPv4   string        // comma separated firewall rule ids for IPv4
	firewallRuleIdsIPv6   string        // comma separated firewall rule ids for IPv6
	logLevel              string        // 0=debug, 1=info
	metricsAddr           string        // prometheus listen address
	mikrotikHost          string        // address of the mikrotik device
	password              string
	timeout               time.Duration
	useIPV4               bool
	useIPV6               bool
	username              string
	useTLS                bool // use TLS in communication with mikrotik
)

func initConfig() {

	// TODO: allow loading config from file, because using env vars is insecure

	viper.BindEnv("log_level")
	viper.SetDefault("log_level", "1")
	logLevel = viper.GetString("log_level")
	level, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		log.Fatal().
			Err(err).
			Str("func", "config").
			Msg("invalid log level")
	}
	zerolog.SetGlobalLevel(level)

	viper.BindEnv("debug_decisions_max")
	viper.SetDefault("debug_decisions_max", "-1")
	debugDecisionsMax = viper.GetInt("debug_decisions_max")

	viper.BindEnv("metrics_address")
	viper.SetDefault("metrics_address", ":2112")
	metricsAddr = viper.GetString("metrics_address")

	viper.BindEnv("mikrotik_host")
	mikrotikHost = viper.GetString("mikrotik_host")

	viper.BindEnv("mikrotik_user")
	username = viper.GetString("mikrotik_user")
	if username == "" {
		log.Fatal().
			Str("func", "config").
			Msg("Mikrotik username is not set")
	}

	viper.BindEnv("mikrotik_pass")
	password = viper.GetString("mikrotik_pass")
	if password == "" {
		log.Fatal().
			Str("func", "config").
			Msg("Mikrotik password is not set")
	}

	viper.BindEnv("mikrotik_tls")
	viper.SetDefault("mikrotik_tls", "true")
	useTLS = viper.GetBool("mikrotik_tls")

	viper.BindEnv("mikrotik_ipv4")
	viper.SetDefault("mikrotik_ipv4", "true")
	useIPV4 = viper.GetBool("mikrotik_ipv4")

	viper.BindEnv("mikrotik_ipv6")
	viper.SetDefault("mikrotik_ipv6", "true")
	useIPV6 = viper.GetBool("mikrotik_ipv6")

	viper.BindEnv("mikrotik_address_list")
	viper.SetDefault("mikrotik_address_list", "crowdsec")
	addressList = viper.GetString("mikrotik_address_list")
	if addressList == "" {
		log.Fatal().
			Str("func", "config").
			Msg("mikrotik_address_list cannot be empty")
	}

	viper.BindEnv("ip_firewall_rules") // TODO: add checker that those are numbers with commas only
	firewallRuleIdsIPv4 = viper.GetString("ip_firewall_rules")
	if useIPV4 && firewallRuleIdsIPv4 == "" {
		log.Fatal().
			Str("func", "config").
			Msg("ip_firewall_rules cannot be empty")
	}

	viper.BindEnv("ipv6_firewall_rules") // TODO: add checker that those are numbers with commas only
	firewallRuleIdsIPv6 = viper.GetString("ipv6_firewall_rules")
	if useIPV6 && firewallRuleIdsIPv6 == "" {
		log.Fatal().
			Str("func", "config").
			Msg("ipv6_firewall_rules cannot be empty")
	}

	viper.SetDefault("mikrotik_timeout", "10s")
	timeout = viper.GetDuration("mikrotik_timeout")
	timeoutStr, err := time.ParseDuration(timeout.String())
	if err != nil {
		log.Fatal().
			Err(err).
			Str("func", "config").
			Str("mikrotik_timeout", timeout.String()).
			Msg("Failed to parse mikrotik_timeout")
	}

	viper.BindEnv("crowdsec_origins")
	viper.SetDefault("crowdsec_origins", nil)

	viper.BindEnv("crowdsec_bouncer_api_key")
	viper.BindEnv("crowdsec_url")
	viper.SetDefault("crowdsec_url", "http://crowdsec:8080/")
	crowdsecBouncerAPIKey = viper.GetString("crowdsec_bouncer_api_key")
	if crowdsecBouncerAPIKey == "" {
		log.Fatal().
			Str("func", "config").
			Msg("Crowdsec API key is not set")
	}
	crowdsecBouncerURL = viper.GetString("crowdsec_url")
	if crowdsecBouncerURL == "" {
		log.Fatal().
			Str("func", "config").
			Msg("Crowdsec LAPI URL is not set")
	}

	crowdsecOrigins = viper.GetStringSlice("crowdsec_origins")

	viper.BindEnv("default_ttl")
	viper.SetDefault("default_ttl", "1h")
	defaultTTL = viper.GetDuration("default_ttl")
	defaultTTLD, err := time.ParseDuration(defaultTTL.String())
	if err != nil {
		log.Fatal().
			Err(err).
			Str("func", "config").
			Str("default_ttl", defaultTTL.String()).
			Msg("Failed to parse default_ttl")
	}

	all := viper.AllSettings()

	safeConfig := map[string]any{}
	maps.Copy(safeConfig, all)
	safeConfig["mikrotik_pass"] = fmt.Sprintf("%.*s...", 3, password)
	safeConfig["crowdsec_bouncer_api_key"] = fmt.Sprintf("%.*s...", 3, crowdsecBouncerAPIKey)

	log.Info().
		Str("func", "config").
		Msgf("Using config: %v", safeConfig)
	log.Info().
		Str("func", "config").
		Msgf("Setting default TTL to %v", defaultTTLD)
	log.Info().
		Str("func", "config").
		Msgf("Setting mikrotik_timeout to %v", timeoutStr)

}
