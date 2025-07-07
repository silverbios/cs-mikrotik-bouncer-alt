package main

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/go-routeros/routeros/v3"
)

func dial() (*routeros.Client, error) {
	if useTLS {
		return routeros.DialTLSTimeout(mikrotikHost, username, password, nil, timeout)
	}
	return routeros.DialTimeout(mikrotikHost, username, password, timeout)
}

// runMikrotikCommandsLoop does just basic loop with sleep + run commands to update MikroTik
func runMikrotikCommandsLoop(mal *mikrotikAddrList) {
	go func() {
		for {

			// on app start cache is empty but streamin decisions happens within 10s
			// and in that case it will trigger runMikrotikCommands() anyway

			time.Sleep(updateFreq)
			runMikrotikCommands(mal)

		}
	}()
}

func runMikrotikCommandsMetric(startTime int64) {
	metricMikrotikCmdDur.Add(float64(time.Now().UnixMicro() - startTime))
}

// runMikrotikCommands walks over the cached address list
// and adds addresses to new address-list in MikroTik
// and updates firewall rules to use that new address list
//
// we need it to be executed periodically to ensure that if we use default_ttl_max
// then we readd address prior expiry
func runMikrotikCommands(mal *mikrotikAddrList) {
	lockWaitStart := time.Now().UnixMicro()
	mal.mutex.Lock()
	lockWaitEnd := time.Now().UnixMicro()
	metricLockWait.Add(float64(lockWaitEnd - lockWaitStart))

	defer mal.mutex.Unlock()
	defer runMikrotikCommandsMetric(lockWaitStart)

	// TODO: allow defining custom format of target address-list name
	listName := fmt.Sprintf("%s_%s", addressList, time.Now().Format("2006-01-02_15-04-05"))
	var err error
	var conn *routeros.Client
	conn, err = mikrotikConnect()
	if err != nil {
		return
	}
	mal.c = conn

	defer func() {
		if errClose := mikrotikClose(mal.c); errClose != nil {
			log.Error().
				Str("func", "mikrotikClose").
				Str("list_name", listName).
				Msgf("Error closing connection to mikrotik: %v", errClose)
		}
	}()

	for _, item := range mal.cache.Items() {
		address := item.Key()
		ttl := item.TTL()
		comment := item.Value()
		err := mal.addToAddressList(listName, address, ttl, comment)
		if err != nil {
			return
		}
	}

	if useIPV4 {
		if enableFirewallFilter {
			_ = mal.setAddressListInFirewall("ip", "filter", listName, srcFilterRuleIdsIPv4, "src")
			_ = mal.setAddressListInFirewall("ip", "filter", listName, dstFilterRuleIdsIPv4, "dst")
		}
		if enableFirewallRaw {
			_ = mal.setAddressListInFirewall("ip", "raw", listName, srcRawRuleIdsIPv4, "src")
			_ = mal.setAddressListInFirewall("ip", "raw", listName, dstRawRuleIdsIPv4, "dst")
		}
	} else {
		log.Debug().
			Str("func", "runMikrotikCommands").
			Str("list_name", listName).
			Msgf("Skipping setAddressListInFirewall, because IPv4 support is disabled")
	}

	if useIPV6 {
		if enableFirewallFilter {
			_ = mal.setAddressListInFirewall("ipv6", "filter", listName, srcFilterRuleIdsIPv6, "src")
			_ = mal.setAddressListInFirewall("ipv6", "filter", listName, dstFilterRuleIdsIPv6, "dst")
		}
		if enableFirewallRaw {
			_ = mal.setAddressListInFirewall("ipv6", "raw", listName, srcRawRuleIdsIPv6, "src")
			_ = mal.setAddressListInFirewall("ipv6", "raw", listName, dstRawRuleIdsIPv6, "dst")
		}
	} else {
		log.Debug().
			Str("func", "runMikrotikCommands").
			Str("list_name", listName).
			Msgf("Skipping setAddressListInFirewall, because IPv6 support is disabled")
	}

}

func mikrotikConnect() (*routeros.Client, error) {

	log.Info().
		Str("func", "mikrotikConnect").
		Str("host", mikrotikHost).
		Str("username", username).
		Bool("useTLS", useTLS).
		Str("timeout", timeout.String()).
		Msg("Connecting to mikrotik")

	c, err := dial()
	if err != nil {
		log.Error().
			Err(err).
			Str("func", "connect").
			Str("host", mikrotikHost).
			Str("username", username).
			Bool("useTLS", useTLS).
			Str("timeout", timeout.String()).
			Msg("Connecting to mikrotik failed")
		// error codes are non-existent in github.com/go-routeros/routeros/v3
		metricMikrotikClient.WithLabelValues("connect", "error").Inc()
		return nil, err
	}
	// error codes are non-existent in github.com/go-routeros/routeros/v3
	metricMikrotikClient.WithLabelValues("connect", "success").Inc()
	return c, nil

}

func mikrotikClose(c *routeros.Client) error {

	log.Info().
		Str("func", "mikrotikClose").
		Str("host", mikrotikHost).
		Str("username", username).
		Bool("useTLS", useTLS).
		Str("timeout", timeout.String()).
		Msg("Closing connection to mikrotik")

	err := c.Close()
	if err != nil {
		log.Error().
			Err(err).
			Str("func", "mikrotikClose").
			Str("host", mikrotikHost).
			Str("username", username).
			Bool("useTLS", useTLS).
			Str("timeout", timeout.String()).
			Msg("Closing connection to mikrotik failed.")
		// error codes are non-existent in github.com/go-routeros/routeros/v3
		metricMikrotikClient.WithLabelValues("disconnect", "error").Inc()
		return err
	}
	// error codes are non-existent in github.com/go-routeros/routeros/v3
	metricMikrotikClient.WithLabelValues("disconnect", "success").Inc()
	return nil
}

// ParseMikrotikDuration parses a duration string,
// with addition of parsing days, weeks, and years.
//
// examples:
//
// "10d", "2w" or "3y4m5d".
func ParseMikrotikDuration(s string) (time.Duration, error) {
	neg := false
	if len(s) > 0 && s[0] == '-' {
		neg = true
		s = s[1:]
	}

	re := regexp.MustCompile(`(\d*\.\d+|\d+)[^\d]*`)
	unitMap := map[string]time.Duration{
		"d": 24,
		"w": 7 * 24,
		"y": 365 * 24,
	}

	strs := re.FindAllString(s, -1)
	var sumDur time.Duration
	for _, str := range strs {
		var _hours time.Duration = 1
		for unit, hours := range unitMap {
			if strings.Contains(str, unit) {
				str = strings.ReplaceAll(str, unit, "h")
				_hours = hours
				break
			}
		}

		dur, err := time.ParseDuration(str)
		if err != nil {
			return 0, err
		}

		sumDur += dur * _hours
	}

	if neg {
		sumDur = -sumDur
	}
	return sumDur, nil
}

// getProtoCmd returns protocol from address (but detection is pretty dumb)
//
// "ip" for IPv4
// "ipv6" for IPv6
//
// to be used by mirkotik api calls
func getProtoCmd(address string) string {
	if strings.Contains(address, ":") {
		return "ipv6"
	}
	return "ip"

}

// addToAddressList adds address to address-list in MikroTik
//
// listName - address-list-name
//
// address - address to add
// ttl - timeout for the address in the address-list
// comment
func (mal *mikrotikAddrList) addToAddressList(listName string, address string, ttl time.Duration, comment string) error {

	proto := getProtoCmd(address)
	if proto != "ip" && proto != "ipv6" {
		log.Error().
			Str("func", "addToAddressList").
			Str("proto", proto).
			Str("listName", listName).
			Str("address", address).
			Str("ttl", ttl.String()).
			// Str("comment", comment).
			Msgf("Invalid protocol, valid values are 'ip' or 'ipv6'")
		return nil
	}

	if ttl == 0*time.Second {
		newTTL := 2 * updateFreq
		log.Info().
			Str("func", "addToAddressList").
			Str("ttl", ttl.String()).
			Str("ttl_updated", newTTL.String()).
			Msgf("Ban without TTL converted to expiring ban")
		metricPermBans.WithLabelValues(proto).Inc()
		ttl = newTTL
	}

	ttlTruncated := "false"
	if useMaxTTL && ttl > maxTTL {
		ttl = maxTTL
		ttlTruncated = "true"
	}
	metricTTLTruncated.WithLabelValues(proto, ttlTruncated).Inc()

	log.Debug().
		Str("func", "addToAddressList").
		Msgf("mikrotik: /%s firewall address-list add list=%s address=%s comment='%s' timeout=%s", proto, listName, address, comment, ttl)

	cmd := fmt.Sprintf("/%s/firewall/address-list/add#=list=%s#=address=%s#=comment=%s#=timeout=%s", proto, listName, address, comment, ttl)

	r, err := mal.c.RunArgs(strings.Split(cmd, "#"))
	log.Debug().
		Str("func", "addToAddressList").
		Msgf("response: '%v'", r)
	if err != nil {
		log.Error().Err(err).
			Str("func", "addToAddressList").
			Str("proto", proto).
			Str("list_name", listName).
			Str("address", address).
			Str("ttl", ttl.String()).
			Str("ttl_truncated", ttlTruncated).
			// Str("comment", comment).
			Msgf("Failed to add address to adress-list")
		metricMikrotikCmd.WithLabelValues(proto, "address_list", "add", "error").Inc()
		return err

	}
	metricMikrotikCmd.WithLabelValues(proto, "address_list", "add", "success").Inc()

	log.Info().
		Str("func", "addToAddressList").
		Str("proto", proto).
		Str("list_name", listName).
		Str("address", address).
		Str("ttl", ttl.String()).
		Str("ttl_truncated", ttlTruncated).
		// Str("comment", comment).
		Msgf("Address added to mikrotik successfully")
	return nil
}

// setAddressListInFirewall sets given listName as src-address-list in firewall filter/raw rule in MikroTik
//
// proto - protocol such as 'ip' for IPV4 or 'ip6' for IPv6
//
// mode - /ip firewall <mode> set ... where mode is 'filter' for generic firewall (input/output/forward etc), or 'raw' for (prerouting/output)
// firewallRuleId - filter id in mikrotik firewall rules
//
// listName - name of the list in the address-list, we assume it exists
//
// where - where to put the address, only valid values are 'src' and 'dst'
func (mal *mikrotikAddrList) setAddressListInFirewall(proto string, mode string, listName string, firewallRuleIds string, where string) error {

	if proto != "ip" && proto != "ipv6" {
		log.Error().
			Str("func", "setAddressListInFirewall").
			Str("proto", proto).
			Str("mode", mode).
			Str("where", where).
			Str("listName", listName).
			Str("firewallRuleIds", firewallRuleIds).
			Msgf("Invalid protocol, valid values are 'ip' or 'ipv6', got '%s'", proto)
		return nil
	}

	if where != "src" && where != "dst" {
		log.Error().
			Str("func", "setAddressListInFirewall").
			Str("proto", proto).
			Str("mode", mode).
			Str("where", where).
			Str("listName", listName).
			Str("firewallRuleIds", firewallRuleIds).
			Msgf("Invalid 'where' value, valid values are 'src' or 'dst', got '%s'", where)
		return nil
	}

	whereStr := fmt.Sprintf("%s-address-list", where)
	log.Debug().
		Str("func", "setAddressListInFirewall").
		Str("proto", proto).
		Str("mode", mode).
		Str(whereStr, listName).
		Str("number", firewallRuleIds).
		Msgf("mikrotik: /%s firewall %s set %s=%s number=%s", proto, mode, whereStr, listName, firewallRuleIds)

	cmd := fmt.Sprintf("/%s/firewall/%s/set#=%s=%s#=.id=%s", proto, mode, whereStr, listName, firewallRuleIds)

	r, err := mal.c.RunArgs(strings.Split(cmd, "#"))
	log.Debug().
		Str("func", "setAddressListInFirewall").
		Msgf("response: '%v'", r)
	if err != nil {
		log.Error().Err(err).
			Str("func", "setAddressListInFirewall").
			Str("proto", proto).
			Str("mode", mode).
			Str(whereStr, listName).
			Str("number", firewallRuleIds).
			Msgf("Failed to set %s in firewall", whereStr)
		metricMikrotikCmd.WithLabelValues(proto, mode, "set", "error").Inc()
		return err

	}
	metricMikrotikCmd.WithLabelValues(proto, mode, "set", "success").Inc()
	log.Info().
		Str("func", "setAddressListInFirewall").
		Str("proto", proto).
		Str("mode", mode).
		Str(whereStr, listName).
		Str("number", firewallRuleIds).
		Msgf("New %s set to firewall %s in mikrotik successfully", whereStr, mode)
	return nil
}
