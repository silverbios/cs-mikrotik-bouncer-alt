package main

import (
	"fmt"
	"maps"
	"os"
	"regexp"
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

	enableFirewallFilter bool   // enable updating firewall filter rules
	srcFilterRuleIdsIPv4 string // comma separated firewall filter rule ids for IPv4 for source rules
	srcFilterRuleIdsIPv6 string // comma separated firewall filter rule ids for IPv6 for source rules
	dstFilterRuleIdsIPv4 string // comma separated firewall filter rule ids for IPv4 for destination rules
	dstFilterRuleIdsIPv6 string // comma separated firewall filter rule ids for IPv6 for destination rules

	enableFirewallRaw bool   // enable updating firewall raw rules
	srcRawRuleIdsIPv4 string // comma separated firewall raw rule ids for IPv4 for source rules
	srcRawRuleIdsIPv6 string // comma separated firewall raw rule ids for IPv6 for source rules
	dstRawRuleIdsIPv4 string // comma separated firewall raw rule ids for IPv4 for destination rules
	dstRawRuleIdsIPv6 string // comma separated firewall raw rule ids for IPv6 for destination rules

	logLevel    string // 0=debug, 1=info
	metricsAddr string // prometheus listen address

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

	// how frequently process streamed decisions from CrowdSec LAPI
	// the best if this is as close to the total time used to update MikroTik
	// address lists and firewall as possible
	// if you get frequent delays in acquiring lock then try to increase this value
	tickerInterval time.Duration
)

func initConfig() {

	// TODO: allow loading config from file, because using env vars is insecure

	viper.BindEnv("log_format_json") //nolint:errcheck
	viper.SetDefault("log_format_json", "true")
	logToJson := viper.GetBool("log_format_json")
	if !logToJson {
		// color console log
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}

	viper.BindEnv("log_level") //nolint:errcheck
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

	viper.BindEnv("debug_decisions_max") //nolint:errcheck
	viper.SetDefault("debug_decisions_max", "-1")
	debugDecisionsMax = viper.GetInt("debug_decisions_max")

	viper.BindEnv("metrics_address") //nolint:errcheck
	viper.SetDefault("metrics_address", ":2112")
	metricsAddr = viper.GetString("metrics_address")

	viper.BindEnv("mikrotik_host") //nolint:errcheck
	mikrotikHost = viper.GetString("mikrotik_host")

	viper.BindEnv("mikrotik_user") //nolint:errcheck
	username = viper.GetString("mikrotik_user")
	if username == "" {
		log.Fatal().
			Str("func", "config").
			Msg("Mikrotik username is not set")
	}

	viper.BindEnv("mikrotik_pass") //nolint:errcheck
	password = viper.GetString("mikrotik_pass")
	if password == "" {
		log.Fatal().
			Str("func", "config").
			Msg("Mikrotik password is not set")
	}

	viper.BindEnv("mikrotik_tls") //nolint:errcheck
	viper.SetDefault("mikrotik_tls", "true")
	useTLS = viper.GetBool("mikrotik_tls")

	viper.BindEnv("mikrotik_ipv4") //nolint:errcheck
	viper.SetDefault("mikrotik_ipv4", "true")
	useIPV4 = viper.GetBool("mikrotik_ipv4")

	viper.BindEnv("mikrotik_ipv6") //nolint:errcheck
	viper.SetDefault("mikrotik_ipv6", "true")
	useIPV6 = viper.GetBool("mikrotik_ipv6")

	viper.BindEnv("mikrotik_firewall_filter_enable") //nolint:errcheck
	viper.SetDefault("mikrotik_firewall_filter_enable", "true")
	enableFirewallFilter = viper.GetBool("mikrotik_firewall_filter_enable")

	viper.BindEnv("mikrotik_firewall_raw_enable") //nolint:errcheck
	viper.SetDefault("mikrotik_firewall_raw_enable", "true")
	enableFirewallRaw = viper.GetBool("mikrotik_firewall_raw_enable")

	viper.BindEnv("mikrotik_address_list") //nolint:errcheck
	viper.SetDefault("mikrotik_address_list", "crowdsec")
	addressList = viper.GetString("mikrotik_address_list")
	if addressList == "" {
		log.Fatal().
			Str("func", "config").
			Msg("mikrotik_address_list cannot be empty")
	}

	if useIPV4 {
		if enableFirewallFilter {
			srcFilterRuleIdsIPv4 = cfgValidateFirewall("ip_firewall_filter_rules_src")
			dstFilterRuleIdsIPv4 = cfgValidateFirewall("ip_firewall_filter_rules_dst")
		}
		if enableFirewallRaw {
			srcRawRuleIdsIPv4 = cfgValidateFirewall("ip_firewall_raw_rules_src")
			dstRawRuleIdsIPv4 = cfgValidateFirewall("ip_firewall_raw_rules_dst")
		}
	}

	if useIPV6 {
		if enableFirewallFilter {
			srcFilterRuleIdsIPv6 = cfgValidateFirewall("ipv6_firewall_filter_rules_src")
			dstFilterRuleIdsIPv6 = cfgValidateFirewall("ipv6_firewall_filter_rules_dst")
		}
		if enableFirewallRaw {
			srcRawRuleIdsIPv6 = cfgValidateFirewall("ipv6_firewall_raw_rules_src")
			dstRawRuleIdsIPv6 = cfgValidateFirewall("ipv6_firewall_raw_rules_dst")
		}
	}

	viper.BindEnv("mikrotik_timeout") //nolint:errcheck
	viper.SetDefault("mikrotik_timeout", "10s")
	timeout = viper.GetDuration("mikrotik_timeout")
	timeoutD, err := time.ParseDuration(timeout.String())
	if err != nil {
		log.Fatal().
			Err(err).
			Str("func", "config").
			Str("mikrotik_timeout", viper.GetString("mikrotik_timeout")).
			Msg("Failed to parse mikrotik_timeout")
	}

	viper.BindEnv("mikrotik_update_frequency") //nolint:errcheck
	viper.SetDefault("mikrotik_update_frequency", "1h")
	updateFreq = viper.GetDuration("mikrotik_update_frequency")
	updateFreqD, err := time.ParseDuration(updateFreq.String())
	if err != nil {
		log.Fatal().
			Err(err).
			Str("func", "config").
			Str("mikrotik_update_frequency", viper.GetString("mikrotik_update_frequency")).
			Msg("Failed to parse mikrotik_update_frequency")
	}

	viper.BindEnv("crowdsec_url") //nolint:errcheck
	viper.SetDefault("crowdsec_url", "http://crowdsec:8080/")

	viper.BindEnv("crowdsec_bouncer_api_key") //nolint:errcheck
	crowdsecBouncerAPIKey = viper.GetString("crowdsec_bouncer_api_key")
	if crowdsecBouncerAPIKey == "" {
		log.Fatal().
			Str("func", "config").
			Msg("Crowdsec API key is not set")
	}

	viper.BindEnv("crowdsec_url") //nolint:errcheck
	crowdsecBouncerURL = viper.GetString("crowdsec_url")
	if crowdsecBouncerURL == "" {
		log.Fatal().
			Str("func", "config").
			Msg("Crowdsec LAPI URL is not set")
	}

	viper.BindEnv("crowdsec_origins") //nolint:errcheck
	viper.SetDefault("crowdsec_origins", nil)
	crowdsecOrigins = viper.GetStringSlice("crowdsec_origins")

	viper.BindEnv("default_ttl") //nolint:errcheck
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

	viper.BindEnv("use_max_ttl") //nolint:errcheck
	viper.SetDefault("use_max_ttl", "false")
	useMaxTTL = viper.GetBool("use_max_ttl")

	viper.BindEnv("default_ttl_max") //nolint:errcheck
	viper.SetDefault("default_ttl_max", "4h")
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
			Str("default_ttl_max", maxTTL.String()).
			Str("mikrotik_update_frequency", viper.GetString("mikrotik_update_frequency")).
			Msg("default_ttl_max can not be shorter than mikrotik_update_frequency")
	}

	viper.BindEnv("trigger_on_update") //nolint:errcheck
	viper.SetDefault("trigger_on_update", "true")
	triggerOnUpdate = viper.GetBool("trigger_on_update")

	viper.BindEnv("ticker_interval") //nolint:errcheck
	viper.SetDefault("ticker_interval", "10s")
	tickerInterval = viper.GetDuration("ticker_interval")
	tickerIntervalD, err := time.ParseDuration(tickerInterval.String())
	if err != nil {
		log.Fatal().
			Err(err).
			Str("func", "config").
			Str("ticker_interval", viper.GetString("ticker_interval")).
			Msg("ticker_interval value is invalid ")
	}
	if tickerInterval <= 0*time.Second {
		log.Fatal().
			Err(err).
			Str("func", "config").
			Str("ticker_interval", viper.GetString("ticker_interval")).
			Msg("ticker_interval value can not be equal zero or negative")
	}

	all := viper.AllSettings()

	safeConfig := map[string]any{}
	maps.Copy(safeConfig, all)
	safeConfig["mikrotik_pass"] = fmt.Sprintf("%.*s...", 3, password)
	safeConfig["crowdsec_bouncer_api_key"] = fmt.Sprintf("%.*s...", 3, crowdsecBouncerAPIKey)

	for key, val := range safeConfig {
		log.Info().
			Str("func", "config").
			Msgf("Using config: %v=%v", key, val)
	}
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
	log.Info().
		Str("func", "config").
		Msgf("Setting ticker_interval to %v", tickerIntervalD)

}

// cfgValidateFirewall checks if the input string is a valid mikrotik firewall format
// so just numbers and commas
func cfgValidateFirewall(name string) string {

	viper.BindEnv(name) //nolint:errcheck
	value := viper.GetString(name)

	if value == "" {
		log.Fatal().
			Str("func", "config").
			Str(name, value).
			Msgf("%s cannot be empty", name)

	}

	match, _ := regexp.MatchString("^([0-9]+,?)+$", value)
	if !match {
		log.Fatal().
			Str("func", "config").
			Str(name, value).
			Msgf("%s can contain only numbers and commas, aborting", name)
	}

	return value
}
