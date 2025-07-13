# Troubleshooting

## Application start

When app starts it should check for the required env vars and will check if
they have a valid values.

After that it will print in the log the passed down values
with sensitive data masked.

Connection to the CrowdSec API should happen within few seconds.
If it crashes then usually you provided invalid Crowdsec API key.

You can limit amount of messages by setting [DEBUG_DECISIONS_MAX=1](config.bouncer.md#debug_decisions_max)

The most important things are reported as `error` messages in the logs.

## No traffic blocked

Ensure that the firewall rules are high enough before other rules so that firewall
is not skipping them.
