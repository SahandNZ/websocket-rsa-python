import argparse
import logging

from src.client import Client
from src.encryption import RSA
from src.server import Server


def run_server(base_url: str, port: int, keys_root: str):
    server = Server(base_url=base_url, port=port, keys_root=keys_root)
    server.run()


def run_client(base_url: str, port: int):
    client = Client(base_url=base_url, port=port)
    client.run()


if __name__ == '__main__':
    logging.basicConfig(format='[%(asctime)s] %(name)s | %(levelname)s | %(message)s', level=logging.INFO,
                        datefmt='%Y-%m-%d %H:%M:%S')

    parser = argparse.ArgumentParser()
    parser.add_argument('-g', '--generate-keys', action='store_true')
    parser.add_argument('-s', '--server', action='store_true')
    parser.add_argument('-c', '--client', action='store_true')

    parser.add_argument('-k', '--keys-root', action='store', type=str, required=False, default="keys")
    parser.add_argument('-u', '--base-url', action='store', type=str, required=False, default="localhost")
    parser.add_argument('-p', '--port', action='store', type=int, required=False, default=8000)
    args = parser.parse_args()

    if args.generate_keys:
        RSA.generate_and_save_keys(root=args.keys_root)

    if args.server:
        run_server(base_url=args.base_url, port=args.port, keys_root=args.keys_root)

    if args.client:
        run_client(base_url=args.base_url, port=args.port)
