import asyncio
import logging

import rsa
import websockets

from src.encryption import RSA


class Client:
    def __init__(self, base_url: str, port: int):
        self.base_url: str = base_url
        self.port: int = port
        self.rsa: RSA = None

        self.__logger = logging.getLogger('websockets.client')

    async def handler(self):
        async with websockets.connect(f"ws://{self.base_url}:{self.port}") as ws:
            public_key_pem = await ws.recv()
            public_key = rsa.PublicKey.load_pkcs1(public_key_pem)
            self.rsa = RSA(public_key=public_key)
            self.__logger.info("{:<30} {}".format("RSA public key (pem)",
                                                  str(public_key_pem).split('\\n')[1][:64] + '...'))

            message = 'not empty'
            while 0 != len(message):
                # send message
                message = input("Enter new message(Enter empty message to close the connection)")
                encrypted_message = self.rsa.encrypt(message)
                await ws.send(encrypted_message)
                self.__logger.info("{:<30} {}".format("Message", message))
                self.__logger.info("{:<30} {}".format("Encrypted message", str(encrypted_message)[:64] + '...'))

                # receive response
                response = await ws.recv()
                response_message, response_signature = response.split('<DELIMITER>')
                verification = self.rsa.verify(response_message, response_signature)
                self.__logger.info("{:<30} {}".format("Response", response[:64] + '...'))
                self.__logger.info("{:<30} {}".format("Response message", response_message))
                self.__logger.info("{:<30} {}".format("Response signature", response_signature[:64] + '...'))
                self.__logger.info("{:<30} {}".format("RSA verification", verification))
                print()

    def run(self):
        asyncio.run(self.handler())
