import ipaddress
import argparse

import requests

from typing import Union
from time import time


def get_dns_record(zone_id: str, record_id: str, api_token: str) -> Union[dict, None]:
    """
    Get the current IP address the domain name points to.
    :param zone_id: The zone ID of the domain name
    :param record_id: The record ID of the DNS record
    :param api_token: The API token
    :return: dns_record: tuple[server_ip, server_name]
             server_ip: The IP address the domain name points to e.g., '2001:475:35:3f4::6'
             server_name: The domain name e.g., 'example.com'
             ttl: The TTL of the DNS record in seconds
             if the check fails, return None
    """
    try:
        url = f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}'

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_token}'
        }

        response = requests.request('GET', url, headers=headers, timeout=10)
        response_json = response.json()
    except (requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            Exception) as e:
        print(e)
        return None
    if response.status_code != 200:
        error = response_json['errors'] if 'errors' in response_json else 'Unknown error'
        print(f'Status code: {response.status_code}\tError: {error}')
        return None
    assert response_json['success'] is True
    assert 'result' in response_json
    assert 'content' in response_json['result']
    assert 'name' in response_json['result']
    assert 'ttl' in response_json['result']

    return response_json['result']


def update_dns_record(zone_id: str,
                      record_id: str,
                      server_ip: str,
                      server_name: str,
                      api_token: str,
                      ttl: Union[None, int] = None) -> bool:
    """
    Update the DNS record to point to the new IP address.
    :param zone_id: The zone ID of the domain name
    :param record_id: The record ID of the DNS record
    :param server_ip: The new IP address e.g., '2001:475:35:3f4:e824:8993:be1d:cc31'
    :param server_name: The name of the DNS record e.g., 'example.com'
    :param api_token: The API token
    :param ttl: The TTL of the DNS record in seconds
    :return: True if the update is successful, False otherwise
    """
    try:
        url = f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}'

        payload = {
            'content': f'{server_ip}',
            'name': server_name,
            'type': 'AAAA'
        }
        if ttl is not None:
            payload['ttl'] = ttl
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_token}'
        }

        response = requests.request('PUT', url, json=payload, headers=headers, timeout=10)
        response_json = response.json()
    except (requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            Exception) as e:
        print(e)
        return False
    if response.status_code != 200:
        error = response_json['errors'] if 'errors' in response_json else 'Unknown error'
        print(f'Status code: {response.status_code}\tError: {error}')
        return False
    try:
        assert response_json['success'] is True, 'response_json["success"] is False'
        assert 'result' in response_json, 'result not in response_json'
        assert 'content' in response_json['result'], 'content not in response_json[\'result\']'
        assert response_json['result']['content'] == server_ip, 'response_json[\'result\'][\'content\'] != server_ip'
    except (AssertionError, Exception) as e:
        print(e)
        return False
    return True


def get_ipv6_address(service: str) -> [str, None]:
    """
    Get the IPv6 addresses for a given interface.
    :param service: The service to get the IPv6 addresses from. One of 'icanhazip', 'ipify', or 'ipinfo'
    :return:
    """
    assert service in ['icanhazip', 'ipify', 'ipinfo']
    url = ''
    if service == 'icanhazip':
        url = 'https://ipv6.icanhazip.com/'
    elif service == 'ipify':
        url = 'https://api6.ipify.org/'
    elif service == 'ipinfo':
        url = 'https://v6.ipinfo.io/ip'
    # Get the IPv6 addresses
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except (requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.HTTPError,
            Exception) as e:
        print(e)
        return None
    ipv6_address = response.text.strip()
    # Assert that the IP address is a valid IPv6 address
    try:
        ipaddress.IPv6Address(ipv6_address)
    except (ipaddress.AddressValueError, Exception):
        print(f'Invalid IPv6 address: {ipv6_address}')
        return None
    return ipv6_address


def print_with_timestamp(message: str) -> None:
    """
    Print the message with the current timestamp.
    :param message: The message to print
    :return: None
    """
    print(f'[{int(time())}] {message}')


def ddns(zone_id: str,
         record_id: str,
         api_token: str,
         service: str,
         ttl: int,
         verbose: bool):
    """
    Check if the IPv6 address has changed and update the DNS record if it has.
    :param zone_id: The zone ID of the domain name.
    :param record_id: The record ID of the DNS record.
    :param api_token: The API token.
    :param service: The service to get the IPv6 addresses from. One of 'icanhazip', 'ipify', or 'ipinfo'.
    :param ttl: The TTL of the DNS record in seconds. -1 to keep the current TTL.
    :param verbose: Whether to print the debug messages.
    :return: None
    """
    # Flag for the update
    update = False

    # Get the current DNS record
    record = get_dns_record(zone_id, record_id, api_token)
    if record is None:  # Terminate if the check fails
        print_with_timestamp('Failed to check the DNS record.')
        return
    dns_ip = record['content']
    dns_name = record['name']
    dns_ttl = record['ttl']
    if verbose:
        print(f'DNS IP: {dns_ip}')
        print(f'DNS name: {dns_name}')
        print(f'DNS TTL: {dns_ttl}')

    # If TTL is specified, enforce the TTL
    new_ttl = dns_ttl
    if 0 < ttl != dns_ttl:
        new_ttl = ttl
        update = True

    # Check for DDNS update
    new_ip = dns_ip
    current_ip = get_ipv6_address(service=service)
    if current_ip is None:
        print_with_timestamp('Failed to get the current IP address.')
    if verbose:
        print(f'Current IP: {current_ip}')
    if current_ip is not None and current_ip != dns_ip:
        new_ip = current_ip
        update = True

    # If update is False, we don't need to update the DNS record
    if not update:
        print_with_timestamp('No update is needed.')
        return

    # Update the DNS record
    result = update_dns_record(zone_id=zone_id,
                               record_id=record_id,
                               server_ip=new_ip,
                               server_name=dns_name,
                               api_token=api_token,
                               ttl=new_ttl)
    if not result:
        print_with_timestamp('Failed to update the DNS record.')
    else:
        print_with_timestamp(f'Updated [{dns_ip}] -> [{new_ip}], TTL: {dns_ttl} -> {new_ttl}')


def main():
    parser = argparse.ArgumentParser(description='Update the DNS record to point to the new IPv6 address.')
    parser.add_argument('-z', '--zone_id', type=str, required=True, help='The zone ID of the domain name')
    parser.add_argument('-r', '--record_id', type=str, required=True, help='The record ID of the DNS record')
    parser.add_argument('-t', '--api_token', type=str, required=True, help='The API token')
    parser.add_argument('-s', '--service', type=str, default='icanhazip',
                        help='The service to get the IPv6 addresses from. One of "icanhazip", "ipify", or "ipinfo"')
    parser.add_argument('--ttl', type=int, default=-1,
                        help='The TTL of the DNS record in seconds. If not specified, the TTL will not be changed.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Print the debug messages')
    args = parser.parse_args()

    assert args.service in ['icanhazip', 'ipify', 'ipinfo'], f'Invalid service: {args.service}. ' \
                                                             f'Valid services are "icanhazip", "ipify", and "ipinfo"'

    ddns(zone_id=args.zone_id,
         record_id=args.record_id,
         api_token=args.api_token,
         service=args.service,
         ttl=args.ttl,
         verbose=args.verbose)


if __name__ == '__main__':
    main()
