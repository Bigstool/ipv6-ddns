import argparse

import requests


def get_dns_records(zone_id: str, api_token: str) -> dict:
    """
    Get the DNS record of a domain name.
    :param zone_id: The zone ID of the domain name
    :param api_token: The API token
    :return: dns_record
    """
    url = f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records'

    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {api_token}'
    }

    response = requests.request('GET', url, headers=headers)
    response_json = response.json()

    return response_json['result']


def main():
    parser = argparse.ArgumentParser(description='Get the DNS record of a domain name')
    parser.add_argument('-z', '--zone_id', type=str, help='The zone ID of the domain name')
    parser.add_argument('-t', '--api_token', type=str, help='The API token')
    args = parser.parse_args()

    # Get the DNS record
    record = get_dns_records(zone_id=args.zone_id, api_token=args.api_token)

    # Print the DNS record
    print(record)


if __name__ == '__main__':
    main()
