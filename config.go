package main

import (
	"fmt"
	"maps"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/spf13/viper"
)

var (
	addressList           string   // mikrotik filter address-list prefix
	crowdsecBouncerAPIKey string   // crowdsec bouncer API key
	crowdsecBouncerURL    string   // url to crowdsec lapi
	crowdsecOrigins       []string // CORS

	// use this for coding debug sessions only
	// max decisions to use when processing,
	// set to low as 3 to enable, thus limiting number of items processed
	// default -1, means process everything
	debugDecisionsMax int

	// default time for items without TTL,
	// this is required to allow automatic list expiry, if unsure set it to 1d
	defaultTTL time.Duration

	// default time for items with TTL, this is used to truncate incoming TTL
	// to specific value to prevent of address-list with addresses
	// which would expire after few days
	// default 24h
	// we assume that we get updates from crowdsec at least once per hour
	// so 1 day seems reasonable for now
	maxTTL time.Duration

	// set to true if you want to use maxTTL
	useMaxTTL bool

	srcFirewallRuleIdsIPv4 string // comma separated firewall rule ids for IPv4 for source rules
	srcFirewallRuleIdsIPv6 string // comma separated firewall rule ids for IPv6 for source rules
	dstFirewallRuleIdsIPv4 string // comma separated firewall rule ids for IPv4 for destination rules
	dstFirewallRuleIdsIPv6 string // comma separated firewall rule ids for IPv6 for destination rules
	logLevel               string // 0=debug, 1=info
	metricsAddr            string // prometheus listen address

	mikrotikHost string        // address of the mikrotik device
	password     string        // mikrotik api password
	timeout      time.Duration //mikrotik command timeout duration
	useIPV4      bool          // set to true to process IPv4 addresses
	useIPV6      bool          // set to true to process IPv6 addresses
	username     string        // mikrotik api username
	useTLS       bool          // use TLS in communication with mikrotik

	// run mikrotik address-list+fw update on received decision event
	// defaults to true if you want faster blocking/unblocking
	triggerOnUpdate bool
	//mikrotik update frequency to process create new address list and update firewall
	updateFreq time.Duration
)

func initConfig() {

	// TODO: allow loading config from file, because using env vars is insecure

	viper.BindEnv("log_format_json")
	viper.SetDefault("log_format_json", "true")
	logToJson := viper.GetBool("log_format_json")
	if !logToJson {
		// color console log
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}

	viper.BindEnv("log_level")
	viper.SetDefault("log_level", "1")
	logLevel = viper.GetString("log_level")
	level, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		log.Fatal().
			Err(err).
			Str("func", "config"). //TODO: use zerolog stacktrace which also uses func=
			Msg("invalid log_level")
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

	viper.BindEnv("ip_firewall_rules_src") // TODO: add checker that those are numbers with commas only
	srcFirewallRuleIdsIPv4 = viper.GetString("ip_firewall_rules_src")
	if useIPV4 && srcFirewallRuleIdsIPv4 == "" {
		log.Fatal().
			Str("func", "config").
			Msg("ip_firewall_rules_src cannot be empty")
	}

	viper.BindEnv("ipv6_firewall_rules_src") // TODO: add checker that those are numbers with commas only
	srcFirewallRuleIdsIPv6 = viper.GetString("ipv6_firewall_rules_src")
	if useIPV6 && srcFirewallRuleIdsIPv6 == "" {
		log.Fatal().
			Str("func", "config").
			Msg("ipv6_firewall_rules_src cannot be empty")
	}

	viper.BindEnv("ip_firewall_rules_dst") // TODO: add checker that those are numbers with commas only
	dstFirewallRuleIdsIPv4 = viper.GetString("ip_firewall_rules_dst")
	if useIPV4 && dstFirewallRuleIdsIPv4 == "" {
		log.Fatal().
			Str("func", "config").
			Msg("ip_firewall_rules_dst cannot be empty")
	}

	viper.BindEnv("ipv6_firewall_rules_dst") // TODO: add checker that those are numbers with commas only
	dstFirewallRuleIdsIPv6 = viper.GetString("ipv6_firewall_rules_dst")
	if useIPV6 && dstFirewallRuleIdsIPv6 == "" {
		log.Fatal().
			Str("func", "config").
			Msg("ipv6_firewall_rules_dst cannot be empty")
	}

	viper.BindEnv("mikrotik_timeout")
	viper.SetDefault("mikrotik_timeout", "10s")
	timeout = viper.GetDuration("mikrotik_timeout") // TODO: clean up viper.GetDuration
	timeoutD, err := time.ParseDuration(timeout.String())
	if err != nil {
		log.Fatal().
			Err(err).
			Str("func", "config").
			Str("mikrotik_timeout", viper.GetString("mikrotik_timeout")).
			Msg("Failed to parse mikrotik_timeout")
	}

	viper.BindEnv("mikrotik_update_frequency")
	viper.SetDefault("mikrotik_update_frequency", "1h")
	updateFreq = viper.GetDuration("mikrotik_update_frequency") // TODO: clean up viper.GetDuration
	updateFreqD, err := time.ParseDuration(updateFreq.String())
	if err != nil {
		log.Fatal().
			Err(err).
			Str("func", "config").
			Str("mikrotik_update_frequency", viper.GetString("mikrotik_update_frequency")).
			Msg("Failed to parse mikrotik_update_frequency")
	}

	viper.BindEnv("crowdsec_url")
	viper.SetDefault("crowdsec_url", "http://crowdsec:8080/")

	viper.BindEnv("crowdsec_bouncer_api_key")
	crowdsecBouncerAPIKey = viper.GetString("crowdsec_bouncer_api_key")
	if crowdsecBouncerAPIKey == "" {
		log.Fatal().
			Str("func", "config").
			Msg("Crowdsec API key is not set")
	}

	viper.BindEnv("crowdsec_url")
	crowdsecBouncerURL = viper.GetString("crowdsec_url")
	if crowdsecBouncerURL == "" {
		log.Fatal().
			Str("func", "config").
			Msg("Crowdsec LAPI URL is not set")
	}

	viper.BindEnv("crowdsec_origins")
	viper.SetDefault("crowdsec_origins", nil)
	crowdsecOrigins = viper.GetStringSlice("crowdsec_origins")

	viper.BindEnv("default_ttl")
	viper.SetDefault("default_ttl", "3h")
	defaultTTL = viper.GetDuration("default_ttl")
	defaultTTLD, err := time.ParseDuration(defaultTTL.String())
	if err != nil {
		log.Fatal().
			Err(err).
			Str("func", "config").
			Str("default_ttl", viper.GetString("default_ttl")).
			Msg("Failed to parse default_ttl")
	}

	viper.BindEnv("use_max_ttl")
	viper.SetDefault("use_max_ttl", "false")
	useMaxTTL = viper.GetBool("use_max_ttl")

	viper.BindEnv("default_ttl_max")
	viper.SetDefault("default_ttl_max", "24h")
	maxTTL = viper.GetDuration("default_ttl_max")
	maxTTLD, err := time.ParseDuration(maxTTL.String())
	if err != nil {
		log.Fatal().
			Err(err).
			Str("func", "config").
			Str("default_ttl_max", viper.GetString("default_ttl_max")).
			Msg("Failed to parse default_ttl_max")
	}
	if maxTTL < updateFreq {
		log.Fatal().
			Err(err).
			Str("func", "config").
			Str("default_ttl_max", viper.GetString("default_ttl_max")).
			Str("mikrotik_update_frequency", viper.GetString("mikrotik_update_frequency")).
			Msg("default_ttl_max can not be shorter than mikrotik_update_frequency")
	}

	viper.BindEnv("trigger_on_update")
	viper.SetDefault("trigger_on_update", "true")
	triggerOnUpdate = viper.GetBool("trigger_on_update")

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
		Msgf("Setting max TTL to %v", maxTTLD)
	log.Info().
		Str("func", "config").
		Msgf("Setting mikrotik_timeout to %v", timeoutD)
	log.Info().
		Str("func", "config").
		Msgf("Setting mikrotik_update_requency to %v", updateFreqD)

}
