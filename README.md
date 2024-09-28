# IPv6 DDNS for Cloudflare DNS

A Python script to ✨ generate new IPv6 address for the device upon IPv6 prefix change and 📝 update the corresponding Cloudflare DNS record to point to the new address 🙈 without using any online services to check the external IP address. Especially useful when behind a 🛰️ proxy server.

## Requirements

- Configurable global unicast IPv6 addresses (the delegated IPv6 prefix has a length shorter than 128) (the prefix your ISP delegated to your router begins with `2` or `3` and has a length shorter than 128)
- Linux OS (tested on Ubuntu 20.04)
- Domain name with Cloudflare as the DNS provider
- sudo privilege
- Python (tested on Python 3.8)

## Dependencies

- `iproute2` package (for the `ip` command)
- `requests` and `psutil` Python modules

## Usage

### `ddns.py`

The DDNS script.

`-z`, `--zone_id`: The zone ID of the domain name.

`-r`, `--record_id`: The record ID of the DNS record.

`-t`, `--api_token`: The API token.

`--ttl`: Optional. The desired TTL of the DNS record in seconds. If not specified, the TTL will not be checked or updated.

`--preferred_lft`: Optional. The preferred lifetime of the IPv6 address in seconds. If the preferred lifetime is expired, a new IPv6 address will be generated and the DNS record will be updated when this script is run. Setting this to a smaller value can circumvent IP bans. Defaults to `86400` (24 hours).

`--valid_lft`: Optional. The valid lifetime of the IPv6 address in seconds. It is recommended to set this value to larger than or equal to the IP change interval. Defaults to `108000` (30 hours).

`-i`, `--interface`: The network interface of the device to use.

`-v`, `--verbose`: Print the debug messages

Set both `--preferred_lft` and `--valid_lft` to `-1` to make the generated new IPv6 addresses permanent on the interface (not recommended). Note that this does not stop your ISP from changing the prefix delegated to your router. New addresses will still be generated and added to the interface when the prefix changes, swamping the interface with addresses.

Example:

```bash
sudo python ddns.py --zone_id 00000000000000000000000000000000 --record_id 00000000000000000000000000000000 --api_token 0000000000000000000000000000000000000000 --ttl 60 --preferred_lef 86400 --valid_lft 108000 --interface eth0
```

### `check_dns_record.py`

Utility script to check the DNS records of the domain name.

`-z`, `--zone_id`: The zone ID of the domain name.

`-t`, `--api_token`: The API token.

Example:

```bash
python check_dns_record.py --zone_id 00000000000000000000000000000000 --api_token 00000000000000000000000000000000
```

## Quick Start

### Add a new  DNS record

Add an AAAA record to your domain name with any IPv6 address (as it will be automatically updated by the script later) e.g. `2606:4700:4700::1111`.

### Get the required token and ID

Go to the [API Tokens](https://dash.cloudflare.com/profile/api-tokens) tab of your Cloudflare profile dashboard and create an API token for your zone (domain name) using the *Edit zone DNS* template. Take note of the token. It will be passed to the `--api_token` argument.

Go to the [Cloudflare dashboard](https://dash.cloudflare.com) and click your domain name in the *Websites* tab. Take note of the zone ID in the *API* section of the *Overview* tab. It will be passed to the `--zone_id` argument.

Use `check_dns_record.py` to check the DNS records of the domain name. Look for the newly created AAAA record and take note of its `id`. It will be passed to the `--record_id` argument.

### Check the name of the network interface

In the terminal, check the network interfaces and their IPv6 addresses by running:

```bash
ip -6 addr
```

Take note of the name of the desired interface with configurable global unicast IPv6 addresses. It will be passed to the `--interface` argument.

### Configure `crontab` to run the DDNS script periodically

Create a new shell script `ddns.sh`. Set the arguments to the desired values. Use the absolute path to `ddns.py` and omit `sudo` at the beginning as the `crontab` job will be configured for the `root` user directly. Example:

```shell
python /abs/path/to/ddns.py --zone_id 00000000000000000000000000000000 --record_id 00000000000000000000000000000000 --api_token 0000000000000000000000000000000000000000 --ttl 60 --preferred_lef 86400 --valid_lft 108000 --interface eth0
```

To keep a log of the output of the script, use the following line instead:

```shell
python /abs/path/to/ddns.py --zone_id 00000000000000000000000000000000 --record_id 00000000000000000000000000000000 --api_token 0000000000000000000000000000000000000000 --ttl 60 --preferred_lef 86400 --valid_lft 108000 --interface eth0 >> /abs/path/to/ddns.log 2>&1
```

In the terminal, edit `crontab` by running:

```bash
sudo crontab -e
```

Add the following line to the bottom of the file and save to run the DDNS script every 5 minutes:

```
*/5 * * * * bash /abs/path/to/ddns.sh
```
