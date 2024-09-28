# IPv6 DDNS for Cloudflare DNS

A Python script to 🧐 detect changes to the public IPv6 address and 📝 update the corresponding Cloudflare DNS record to point to the new address.

## Requirements

- Python (tested on Python 3.8)

## Dependencies

- `requests` Python module

## Usage

### `ddns.py`

The DDNS script.

`-z`, `--zone_id`: The zone ID of the domain name.

`-r`, `--record_id`: The record ID of the DNS record.

`-t`, `--api_token`: The API token.

`-s`, `--service`: The service to get the IPv6 addresses from. One of `icanhazip`, `ipify`, or `ipinfo`

`--ttl`: Optional. The desired TTL of the DNS record in seconds. If not specified, the TTL will not be checked or updated.

`-v`, `--verbose`: Print the debug messages

Example:

```bash
python ddns.py --zone_id 00000000000000000000000000000000 --record_id 00000000000000000000000000000000 --api_token 0000000000000000000000000000000000000000 --service icanhazip --ttl 60
```

### `check_dns_record.py`

An utility script to check the DNS records of the domain name.

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

### Configure `crontab` to run the DDNS script periodically

Create a new shell script `ddns.sh`. Set the arguments to the desired values. Use the absolute path to `ddns.py`. Example:

```shell
python /abs/path/to/ddns.py --zone_id 00000000000000000000000000000000 --record_id 00000000000000000000000000000000 --api_token 0000000000000000000000000000000000000000 --service icanhazip --ttl 60
```

To keep a log of the output of the script, use the following line instead:

```shell
python /abs/path/to/ddns.py --zone_id 00000000000000000000000000000000 --record_id 00000000000000000000000000000000 --api_token 0000000000000000000000000000000000000000 --service icanhazip --ttl 60 >> /abs/path/to/ddns.log 2>&1
```

In the terminal, edit `crontab` by running:

```bash
crontab -e
```

Add the following line to the bottom of the file and save to run the DDNS script every 5 minutes:

```
*/5 * * * * bash /abs/path/to/ddns.sh
```
