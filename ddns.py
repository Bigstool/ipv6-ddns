import os
import re
import json
import ipaddress
import random
import subprocess
import socket
import argparse

import requests
import psutil

from typing import Union, Tuple, List
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
                      ttl: Union[None, int] = None) -> None:
    """
    Update the DNS record to point to the new IP address.
    :param zone_id: The zone ID of the domain name
    :param record_id: The record ID of the DNS record
    :param server_ip: The new IP address e.g., '2001:475:35:3f4:e824:8993:be1d:cc31'
    :param server_name: The name of the DNS record e.g., 'example.com'
    :param api_token: The API token
    :param ttl: The TTL of the DNS record in seconds
    :return: None
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
        return
    if response.status_code != 200:
        error = response_json['errors'] if 'errors' in response_json else 'Unknown error'
        print(f'Status code: {response.status_code}\tError: {error}')
        return
    assert response_json['success'] is True
    assert 'result' in response_json
    assert 'content' in response_json['result']
    assert response_json['result']['content'] == server_ip


def get_ipv6_addresses(interface: str) -> List[Tuple[str, int]]:
    """
    Get the IPv6 addresses for a given interface.
    :param interface: The interface to get the IPv6 addresses for e.g., 'eth0'
    :return: A list of tuple of IPv6 addresses and their prefix lengths e.g., [('2001:475:35:3f4::6', 64)]
    """
    # Get the IPv6 addresses
    ipv6_addresses = []
    for if_addr in psutil.net_if_addrs()[interface]:
        if if_addr.family == socket.AF_INET6:
            address = if_addr.address
            # Only keep the global unicast addresses
            if not (address.startswith('2') or address.startswith('3')):
                continue
            # Assert that the netmask is not empty or None
            assert if_addr.netmask != ''
            assert if_addr.netmask is not None
            # Convert the netmask to its binary representation and count the consecutive 1s to obtain the prefix length
            netmask = ipaddress.IPv6Address(if_addr.netmask)
            binary_netmask = bin(int(netmask))[2:]
            prefix_length = len(binary_netmask) - len(binary_netmask.lstrip('1'))

            ipv6_addresses.append((address, prefix_length))

    # Return the IPv6 addresses
    return ipv6_addresses


def get_prefixes(interface: str) -> List[Tuple[str, int]]:
    """
    Get the prefixes from the routing table for a given interface.
    :param interface: The interface to get the prefixes from the routing table for e.g., 'eth0'
    :return: A list of tuple of prefixes and their prefix lengths e.g., [('2001:475:35:3f4::', 64)]
    """
    try:
        # Run the "ip -6 route" command with the specified interface
        result = subprocess.run(['ip', '-6', 'route', 'show', 'dev', interface],
                                capture_output=True, text=True, check=True)
        # Process the output to extract IPv6 addresses
        addresses = re.findall(r'\b[0-9a-fA-F:]+/[0-9]+\b', result.stdout)
        # Deduplicate
        addresses = list(set(addresses))
    except subprocess.CalledProcessError as e:
        # Handle errors if the command fails
        print(f"Error: {e}")
        exit(1)

    prefixes = []
    for address in addresses:
        # Only keep the global unicast addresses
        if not (address.startswith('2') or address.startswith('3')):
            continue
        # Extract the prefix from each address
        prefix, prefix_length = address.split('/')
        # Add the prefix to the list of prefixes
        prefixes.append((prefix, int(prefix_length)))

    return prefixes


def generate_ipv6_address(old_ip: str, prefix_length: int) -> str:
    """
    Generate a valid IPv6 address that falls within the same subnet as the old IP address.
    :param old_ip: The old IP address e.g., '2001:475:35:3f4::6'
    :param prefix_length: The prefix length of the old IP address e.g., 64
    :return: new_ip: The new IP address e.g., '2001:475:35:3f4:e824:8993:be1d:cc31'
    """
    # Get the network
    network = ipaddress.IPv6Network(f'{old_ip}/{prefix_length}', strict=False)

    # Generate a random IPv6 address
    new_ip = ipaddress.IPv6Address(random.randint(int(network.network_address), int(network.broadcast_address)))

    # Return the new IPv6 address
    return new_ip.compressed


def ddns(zone_id: str,
         record_id: str,
         api_token: str,
         ttl: int,
         preferred_lft: int,
         valid_lft: int,
         interface: str,
         verbose: bool):
    """
    Check if the IPv6 address has changed and update the DNS record if it has.
    :param zone_id: The zone ID of the domain name.
    :param record_id: The record ID of the DNS record.
    :param api_token: The API token.
    :param ttl: The TTL of the DNS record in seconds.
    :param preferred_lft: The preferred lifetime of the IPv6 address in seconds.
    :param valid_lft: The valid lifetime of the IPv6 address in seconds.
    :param interface: The network interface of the device to use e.g., 'eth0'.
    :param verbose: Whether to print the debug messages.
    :return: None
    """
    # Print the timestamp if verbose
    if verbose:
        print(f'Timestamp: {int(time())}')

    # Get the current DNS record
    record = get_dns_record(zone_id, record_id, api_token)
    if record is None:  # Terminate if the check fails
        print('Failed to check the DNS record.')
        return
    server_ip = record['content']
    server_name = record['name']
    server_ttl = record['ttl']
    if verbose:
        print(f'Current server IP: {server_ip}')
        print(f'Current server name: {server_name}')
        print(f'Current TTL: {server_ttl}')

    # Read the cache file
    cache_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'cache.json')
    try:
        with open(cache_path, 'r') as f:
            cache = json.load(f)
    except (FileNotFoundError, json.decoder.JSONDecodeError, Exception):
        cache = None

    # If TTL is specified, enforce the TTL
    if 0 < ttl != server_ttl:
        update_dns_record(zone_id, record_id, server_ip, server_name, api_token, ttl)
        print(f'Updated the TTL of the DNS record to {ttl} seconds')

    # Check for DDNS update
    new_ip: Union[str, None] = None
    new_prefix_length: Union[int, None] = None
    # If server_ip not in addresses, update the DNS record
    addresses = get_ipv6_addresses(interface)
    prefixes = get_prefixes(interface)
    if verbose:
        print(f'IPv6 address(es) for {interface}: {addresses}\n'
              f'Prefix(es) for {interface}: {prefixes}')
    if len(prefixes) == 0:
        print('There is no prefix for the given interface.')
        return
    if server_ip not in [address[0] for address in addresses]:
        # Generate IP address using the prefix of the first entry in the routing table
        new_ip = generate_ipv6_address(prefixes[0][0], prefixes[0][1])
        new_prefix_length = prefixes[0][1]
        if verbose:
            print('The server IP is not in the list of IPv6 addresses. Flagged for update.')
    elif verbose:
        print('The server IP is already in the list of IPv6 addresses.')
    # If cache does not exist or either lifetime changed, update the DNS record
    if new_ip is None:
        if cache is None or preferred_lft != cache['preferred_lft'] or valid_lft != cache['valid_lft']:
            # Generate IP address using the prefix of the first entry in the routing table
            new_ip = generate_ipv6_address(prefixes[0][0], prefixes[0][1])
            new_prefix_length = prefixes[0][1]
            if verbose:
                print('The cache does not exist or the lifetime has changed. Flagged for update.')
        elif verbose:
            print('The cache exists.')
    # If routing table contains new prefix, update the DNS record
    if new_ip is None:
        assert 'prefixes' in cache
        # Check if the routing table contains new prefixes
        new_prefixes = [prefix for prefix in prefixes if f'{prefix[0]}/{prefix[1]}' not in cache['prefixes']]
        if len(new_prefixes) > 0:
            # Generate IP address using the prefix of the first new entry in new_prefixes
            new_ip = generate_ipv6_address(new_prefixes[0][0], new_prefixes[0][1])
            new_prefix_length = new_prefixes[0][1]
            if verbose:
                print(f'The routing table contains new prefixes: {new_prefixes}. Flagged for update.')
        elif verbose:
            print('The routing table does not contain new prefixes.')
    # If preferred_lft expired, update the DNS record
    if new_ip is None:
        assert 'timestamp' in cache
        lft_remaining = cache['timestamp'] + preferred_lft - int(time())
        if lft_remaining <= 0:
            # Generate IP address in the same subnet as the current server IP
            prefix_length = [address[1] for address in addresses if address[0] == server_ip][0]
            new_ip = generate_ipv6_address(server_ip, prefix_length)
            new_prefix_length = prefix_length
            if verbose:
                print(f'The preferred lifetime has expired. Flagged for update.')
        elif verbose:
            print(f'The preferred lifetime has not expired. Remaining lifetime: {lft_remaining} seconds.')

    # If new_ip is still None, we don't need to update the DNS record
    if new_ip is None:
        print('No update is needed.')
        return
    assert new_prefix_length is not None

    # Add the new IP address to the list of IPv6 addresses
    command = ['ip', 'addr', 'add', f'{new_ip}/{new_prefix_length}', 'dev', interface]
    if preferred_lft > 0:
        command.extend(['valid_lft', str(valid_lft), 'preferred_lft', str(preferred_lft)])
    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print(f'Failed to add the new IP address to the list of IPv6 addresses: {e}')
        return
    if verbose:
        print('Added the new IP address to the list of IPv6 addresses.')

    # Update the cache
    cache = {
        'timestamp': int(time()),
        'prefixes': [f'{prefix[0]}/{prefix[1]}' for prefix in prefixes],
        'preferred_lft': preferred_lft,
        'valid_lft': valid_lft
    }
    with open(cache_path, 'w') as f:
        json.dump(cache, f, indent=4)
    if verbose:
        print(f'Updated the cache as {cache}')

    # Update the DNS record
    update_dns_record(zone_id=zone_id,
                      record_id=record_id,
                      server_ip=new_ip,
                      server_name=server_name,
                      api_token=api_token,
                      ttl=ttl if ttl > 0 else server_ttl)
    print(f'Updated the DNS record to point to {new_ip}')


def main():
    parser = argparse.ArgumentParser(description='Update the DNS record to point to the new IPv6 address.')
    parser.add_argument('-z', '--zone_id', type=str, required=True, help='The zone ID of the domain name')
    parser.add_argument('-r', '--record_id', type=str, required=True, help='The record ID of the DNS record')
    parser.add_argument('-t', '--api_token', type=str, required=True, help='The API token')
    parser.add_argument('--ttl', type=int, default=-1,
                        help='The TTL of the DNS record in seconds. If not specified, the TTL will not be changed.')
    parser.add_argument('--preferred_lft', type=int, default=86400,
                        help='The preferred lifetime of the IPv6 address in seconds. '
                             'If the preferred lifetime is expired, a new IPv6 address will be generated and '
                             'the DNS record will be updated when this script is run. '
                             'Setting this to a smaller value can circumvent IP bans. '
                             'Set both --preferred_lft and --valid_lft to -1 to make the IPv6 address permanent '
                             '(not recommended). Defaults to 86400 (24 hours).')
    parser.add_argument('--valid_lft', type=int, default=108000,
                        help='The valid lifetime of the IPv6 address in seconds. '
                             'It is recommended to set this value to larger than or equal to the IP change interval. '
                             'Set both --preferred_lft and --valid_lft to -1 to make the IPv6 address permanent '
                             '(not recommended). Defaults to 108000 (30 hours).')
    parser.add_argument('-i', '--interface', type=str, required=True,
                        help='The network interface of the device to use')
    parser.add_argument('-v', '--verbose', action='store_true', help='Print the debug messages')
    args = parser.parse_args()

    assert (args.preferred_lft == args.valid_lft == -1) or (0 < args.preferred_lft <= args.valid_lft), \
           'preferred_lft must be greater than 0 and less than or equal to valid_lft or both must be -1'

    ddns(zone_id=args.zone_id,
         record_id=args.record_id,
         api_token=args.api_token,
         ttl=args.ttl,
         preferred_lft=args.preferred_lft,
         valid_lft=args.valid_lft,
         interface=args.interface,
         verbose=args.verbose)


if __name__ == '__main__':
    main()
