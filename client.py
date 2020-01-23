import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import os
import crypto_funcs
import sys

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(name)-12s %(levelname)-8s %(message)s",
    datefmt="%m-%d %H:%M:%S",
)
logger = logging.getLogger("root")

STATE_CONNECT = 0
STATE_OPEN = 1
STATE_DATA = 2
STATE_CLOSE = 3
STATE_NEGOTIATE = 4
STATE_DH = 5


class ClientProtocol(asyncio.Protocol):
    """
	Client that handles a single client
	"""

    def __init__(self, file_name, loop, iterations_per_key):
        """
		Default constructor
		:param file_name: Name of the file to send
		:param loop: Asyncio Loop to use
		"""
        self.file_name = file_name
        self.loop = loop
        self.state = STATE_CONNECT  # Initial State
        self.buffer = ""  # Buffer to receive data chunks

        self.symetric_ciphers = ["AES", "ChaCha20", "3DES"]
        self.cipher_modes = ["GCM", "None", "ECB", "CBC"]
        self.digest_algorithms = ["SHA256", "SHA512", "BLAKE2"]

        self.used_symetric_cipher = None
        self.used_cipher_mode = None
        self.used_digest_algorithm = None

        self.file_padding = 0
        self.iterations_per_key = iterations_per_key

        self.p = None
        self.g = None
        self.private_key = None
        self.shared_key = None
        self.public_key_pem = None

    def connection_made(self, transport) -> None:
        """
		Called when the client connects.

		:param transport: The transport stream to use for this client
		:return: No return
		"""
        self.transport = transport

        logger.debug("Connected to Server")

        message = {
            "type": "NEGOTIATION_REQ",
            "algorithms": {
                "symetric_ciphers": self.symetric_ciphers,
                "chiper_modes": self.cipher_modes,
                "digest_algorithms": self.digest_algorithms,
            },
        }

        self._send(message)

        self.state = STATE_NEGOTIATE

    def data_received(self, data: str) -> None:
        """
		Called when data is received from the server.
		Stores the data in the buffer

		:param data: The data that was received. This may not be a complete JSON message
		:return:
		"""
        logger.debug("Received: {}".format(data))
        try:
            self.buffer += data.decode()
        except:
            logger.exception("Could not decode data from client")

        idx = self.buffer.find("\r\n")

        while idx >= 0:  # While there are separators
            frame = self.buffer[: idx + 2].strip()  # Extract the JSON object
            self.buffer = self.buffer[
                idx + 2 :
            ]  # Removes the JSON object from the buffer

            self.on_frame(frame)  # Process the frame
            idx = self.buffer.find("\r\n")

        if len(self.buffer) > 4096 * 1024 * 1024:  # If buffer is larger than 4M
            logger.warning("Buffer to large")
            self.buffer = ""
            self.transport.close()

    def on_frame(self, frame: str) -> None:
        """
		Processes a frame (JSON Object)

		:param frame: The JSON Object to process
		:return:
		"""

        logger.debug("Frame: {}".format(frame))
        logger.debug("State: {}".format(self.state))

        try:
            message = json.loads(frame)
        except Exception as e:
            logger.exception("Could not decode the JSON message - {}".format(e))
            self.transport.close()
            return

        mtype = message.get("type", None)

        if mtype == "OK":  # Server replied OK. We can advance the state
            if self.state == STATE_OPEN:
                logger.info("Channel open")
                self.send_file(self.file_name)
            elif self.state == STATE_DATA:  # Got an OK during a message transfer.
                # Reserved for future use
                pass
            else:
                logger.warning("Ignoring message from server")
            return

        elif mtype == "NEGOTIATION_REP":
            algs = message["algorithms"]
            self.used_symetric_cipher = algs["symetric_cipher"]
            self.used_cipher_mode = algs["cipher_mode"]
            self.used_digest_algorithm = algs["digest_algorithm"]

            (
                self.p,
                self.g,
                self.private_key,
                self.public_key_pem,
            ) = crypto_funcs.diffie_hellman_client()

            message = {
                "type": "DH_INIT",
                "parameters": {
                    "p": self.p,
                    "g": self.g,
                    "public_key": str(self.public_key_pem, "ISO-8859-1"),
                },
            }
            self._send(message)
            self.state = STATE_DH
            return

        elif mtype == "DH_SERVER_KEY":
            public_key_pem_client = bytes(message["key"], "ISO-8859-1")

            self.shared_key = crypto_funcs.generate_shared_key(
                self.private_key, public_key_pem_client, self.used_digest_algorithm
            )

            if self.file_padding == 0:
                open_message = {"type": "OPEN", "file_name": self.file_name}
                message = crypto_funcs.create_secure_message(
                    open_message,
                    self.shared_key,
                    self.used_symetric_cipher,
                    self.used_cipher_mode,
                    self.used_digest_algorithm,
                )

                self._send(message)
                self.state = STATE_OPEN

            else:
                self.state = STATE_DATA
                self.send_file(self.file_name)

            return

        elif mtype == "ERROR":
            logger.warning(
                "Got error from server: {}".format(message.get("data", None))
            )

        else:
            logger.warning("Invalid message type")

        self.transport.close()
        self.loop.stop()

    def connection_lost(self, exc):
        """
		Connection was lost for some reason.
		:param exc:
		:return:
		"""
        logger.info("The server closed the connection")
        self.loop.stop()

    def send_file(self, file_name: str) -> None:
        """
		Sends a file to the server.
		The file is read in chunks, encoded to Base64 and sent as part of a DATA JSON message
		:param file_name: File to send
		:return:  None
		"""
        text = None
        with open(file_name, "rb") as reader:
            data_message = {"type": "DATA", "data": None}
            reader.seek(self.file_padding)

            if self.used_symetric_cipher == "AES":
                block_size = 16 * 60
            elif self.used_symetric_cipher == "3DES":
                block_size = 8 * 60
            elif self.used_symetric_cipher == "ChaCha20":
                block_size = 16 * 60

            # Send each chunk
            for i in range(self.iterations_per_key):
                chunk = reader.read(block_size)
                self.file_padding += block_size

                data_message["data"] = base64.b64encode(chunk).decode()

                message = crypto_funcs.create_secure_message(
                    data_message,
                    self.shared_key,
                    self.used_symetric_cipher,
                    self.used_cipher_mode,
                    self.used_digest_algorithm,
                )

                logger.info("Transfering Chunk")
                self._send(message)

                if len(chunk) != block_size:
                    close_message = {"type": "CLOSE"}
                    message = crypto_funcs.create_secure_message(
                        close_message,
                        self.shared_key,
                        self.used_symetric_cipher,
                        self.used_cipher_mode,
                        self.used_digest_algorithm,
                    )
                    self._send(message)

                    logger.info("File transferred. Closing transport")
                    self.transport.close()
                    return

        (
            self.p,
            self.g,
            self.private_key,
            self.public_key_pem,
        ) = crypto_funcs.diffie_hellman_client()

        message = {
            "type": "DH_INIT",
            "parameters": {
                "p": self.p,
                "g": self.g,
                "public_key": str(self.public_key_pem, "ISO-8859-1"),
            },
        }
        self._send(message)
        self.state = STATE_DH

    def _send(self, message: str) -> None:
        """
		Effectively encodes and sends a message
		:param message:
		:return:
		"""
        logger.debug("Send: {}".format(message))

        message_b = (json.dumps(message) + "\r\n").encode()
        self.transport.write(message_b)


def main():
    parser = argparse.ArgumentParser(description="Sends files to servers.")
    parser.add_argument(
        "-v", action="count", dest="verbose", help="Shows debug messages", default=0
    )
    parser.add_argument(
        "-s",
        type=str,
        nargs=1,
        dest="server",
        default="127.0.0.1",
        help="Server address (default=127.0.0.1)",
    )
    parser.add_argument(
        "-p",
        type=int,
        nargs=1,
        dest="port",
        default=5000,
        help="Server port (default=5000)",
    )
    parser.add_argument(
        "-i",
        type=int,
        dest="iters_per_key",
        default=1000,
        help="Number of iterations per key (default 1000)",
    )

    parser.add_argument(type=str, dest="file_name", help="File to send")

    args = parser.parse_args()
    file_name = os.path.abspath(args.file_name)
    level = logging.DEBUG if args.verbose > 0 else logging.INFO
    port = args.port
    server = args.server
    iters_per_key = args.iters_per_key

    coloredlogs.install(level)
    logger.setLevel(level)

    logger.info(
        "Sending file: {} to {}:{} LogLevel: {}".format(file_name, server, port, level)
    )

    loop = asyncio.get_event_loop()
    coro = loop.create_connection(
        lambda: ClientProtocol(file_name, loop, iters_per_key), server, port
    )
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()


if __name__ == "__main__":
    main()
