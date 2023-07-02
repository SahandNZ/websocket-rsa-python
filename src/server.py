import asyncio
import logging

import websockets

from src.encryption import RSA


class Server:
    def __init__(self, base_url: str, port: int, keys_root: str):
        self.base_url: str = base_url
        self.port: int = port

        public_key, private_key = RSA.load_keys(keys_root)
        self.rsa = RSA(public_key, private_key)

        self.__logger = logging.getLogger('websockets.server')

    async def handler(self, ws):
        public_key_pem = self.rsa.public_key.save_pkcs1('PEM')
        await ws.send(public_key_pem)

        encrypted_message = 'not empty'
        while 0 != len(encrypted_message):
            encrypted_message = await ws.recv()
            message = self.rsa.decrypt(encrypted_message)
            self.__logger.info("{:<30} {}".format("Encrypted message", str(encrypted_message)[:64] + '...'))
            self.__logger.info("{:<30} {}".format("Message", message))

            response_message = f"Receive message: {message}"
            response_signature = self.rsa.sign(response_message)
            response = response_message + "<DELIMITER>" + response_signature
            await ws.send(response)
            self.__logger.info("{:<30} {}".format("Response message", response_message))
            self.__logger.info("{:<30} {}".format("Response signature", response_signature[:64] + '...'))
            self.__logger.info("{:<30} {}".format("Response", response_message))
            print()

    def run(self):
        server = websockets.serve(self.handler, self.base_url, self.port)
        asyncio.get_event_loop().run_until_complete(server)
        asyncio.get_event_loop().run_forever()
