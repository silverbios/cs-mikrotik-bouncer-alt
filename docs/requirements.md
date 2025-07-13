
# Overview

For now, this service is mainly thought to be used in as an app in a container.

If you need to build from source and run as standalone binary,
please see [deployment](deploy.md) section.

The app alone takes about up to 60MB or memory (depends on how large blocklists are).
CPU usage is minimal, 10 milicores should be enough.

Please see also [Known Limitations](known.limitations.md).

## Prerequisites

* You should have a MikroTik appliance and a CrowdSec instance running.
* The bouncer container is available as docker image under [quay.io/kaszpir/cs-mikrotik-bouncer-alt](https://quay.io/kaszpir/cs-mikrotik-bouncer-alt).
* The running container must have access to [CrowdSec LAPI](https://docs.crowdsec.net/u/user_guides/lapi_mgmt/)
  and to [MikroTik RouterOS API](https://help.mikrotik.com/docs/spaces/ROS/pages/47579160/API).

## Configuration and deployment overview

Read the following instructions below doing anything.

* Configure MikroTik device by adding user and firewall rules.
* Create a bouncer in CrowdSec.
* Prepare config for the bouncer
* Start the bouncer app via standalone binary or a container.
* Verify if all works as expected.
