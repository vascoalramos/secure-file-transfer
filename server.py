import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import re
import os
from aio_tcpserver import tcp_server
import crypto_funcs

logger = logging.getLogger("root")

STATE_CONNECT = 0
STATE_OPEN = 1
STATE_DATA = 2
STATE_CLOSE = 3
STATE_NEGOTIATE = 4
STATE_DH = 5

# GLOBAL
storage_dir = "files"


class ClientHandler(asyncio.Protocol):
    def __init__(self, signal):
        """
		Default constructor
		"""
        self.signal = signal
        self.state = STATE_CONNECT
        self.file = None
        self.file_name = None
        self.file_path = None
        self.storage_dir = storage_dir
        self.buffer = ""
        self.peername = ""

        self.symetric_ciphers = ["AES", "3DES", "ChaCha20"]
        self.cipher_modes = ["ECB", "CBC", "GCM", "None"]
        self.digest_algorithms = ["SHA256", "SHA512", "BLAKE2"]

        self.used_symetric_cipher = None
        self.used_chiper_mode = None
        self.used_digest_algorithm = None

        self.p = None
        self.g = None
        self.private_key = None
        self.shared_key = None
        self.public_key_pem = None

    def connection_made(self, transport) -> None:
        """
		Called when a client connects.

		:param transport: The transport stream to use with this client
		:return:
		"""
        self.peername = transport.get_extra_info("peername")
        logger.info("\n\nConnection from {}".format(self.peername))
        self.transport = transport
        self.state = STATE_CONNECT

    def data_received(self, data: bytes) -> None:
        """
		Called when data is received from the client.
		Stores the data in the buffer.

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
            self.buffer = self.buffer[idx + 2 :]  # Removes the JSON object from the buffer

            self.on_frame(frame)  # Process the frame
            idx = self.buffer.find("\r\n")

        if len(self.buffer) > 4096 * 1024 * 1024:  # If buffer is larger than 4M
            logger.warning("Buffer to large")
            self.buffer = ""
            self.transport.close()

    def on_frame(self, frame: str) -> None:
        """
		Called when a frame (JSON Object) is extracted.

		:param frame: The JSON object to process
		:return:
		"""
        # logger.debug("Frame: {}".format(frame))

        try:
            message = json.loads(frame)
        except:
            logger.exception("Could not decode JSON message: {}".format(frame))
            self.transport.close()
            return

        mtype = message.get("type", "").upper()

        if mtype == "SECURE_X":
            actual_message = base64.b64decode(message["payload"])
            mac = base64.b64decode(message["mac"])
            if message["iv"] != None:
                iv = base64.b64decode(message["iv"])
            else:
                iv = None
            if message["nonce"] != None:
                nonce = base64.b64decode(message["nonce"])
            else:
                nonce = None
            if message["tag"] != None:
                tag = base64.b64decode(message["tag"])
            else:
                tag = None

            # Verify integrity of the message
            digest = crypto_funcs.generate_mac(
                actual_message, self.shared_key, self.used_digest_algorithm
            )
            if mac != digest:
                if self.file_path != None:  # If we created a file delete it!
                    os.remove(self.file_path)
                logger.warning("The integrity of the message has been compromised")
                ret = False
            else:
                actual_message = crypto_funcs.symmetric_key_decrypt(
                    actual_message,
                    self.shared_key,
                    self.used_symetric_cipher,
                    self.used_chiper_mode,
                    iv,
                    nonce,
                    tag,
                )

                actual_message = actual_message.decode()
                actual_message = actual_message.split("}")[0] + "}"

                message = json.loads(actual_message)
                mtype = message["type"]

                if mtype == "DATA":
                    ret = self.process_data(message)
                    self.state = STATE_DATA
                elif mtype == "OPEN":
                    ret = self.process_open(message)
                    self.state = STATE_OPEN
                elif mtype == "CLOSE":
                    ret = self.process_close(message)

        elif mtype == "NEGOTIATION_REQ":
            ret = self.process_negotiation(message)
            self.state = STATE_NEGOTIATE
        elif mtype == "DH_INIT":
            ret = self.process_dh_init(message)
            self.state = STATE_DH
        else:
            logger.warning("Invalid message type: {}".format(message["type"]))
            ret = False

        if not ret:
            try:
                self._send({"type": "ERROR", "message": "See server"})
            except:
                pass  # Silently ignore

            logger.info("Closing transport")
            if self.file is not None:
                self.file.close()
                self.file = None

            self.state = STATE_CLOSE
            self.transport.close()

    def process_negotiation(self, message: str):
        """
		Processes a NEGOTIATION_REQ message from the client.
        This message will trigger the negotiation process where the server will chose the algorithms to be used.
        If there is not match in the algorithms supported by the client and the ones supported by the client the
        communication will be closed.

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
        logger.debug(f"Process Negotation: {message}")

        symetric_ciphers = message["algorithms"]["symetric_ciphers"]
        chiper_modes = message["algorithms"]["chiper_modes"]
        digest_algorithms = message["algorithms"]["digest_algorithms"]

        for sm_cipher in symetric_ciphers:
            if sm_cipher in self.symetric_ciphers:
                self.used_symetric_cipher = sm_cipher
                break

        for cipher_md in chiper_modes:
            if cipher_md in self.cipher_modes:
                self.used_chiper_mode = cipher_md
                break

        for digest_alg in digest_algorithms:
            if digest_alg in self.digest_algorithms:
                self.used_digest_algorithm = digest_alg
                break

        message = {
            "type": "NEGOTIATION_REP",
            "algorithms": {
                "symetric_cipher": self.used_symetric_cipher,
                "cipher_mode": self.used_chiper_mode,
                "digest_algorithm": self.used_digest_algorithm,
            },
        }

        if (
            self.used_symetric_cipher is not None
            and self.used_chiper_mode is not None
            and self.used_digest_algorithm is not None
        ):
            self._send(message)
            return True

        return False

    def process_dh_init(self, message: str):
        """
		Processes a DH_INIT message from the client.
        This message will trigger the exchange of public key and generation of the shared key.

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
        self.p = message["parameters"]["p"]
        self.g = message["parameters"]["g"]
        public_key_pem_client = bytes(message["parameters"]["public_key"], "ISO-8859-1")

        try:
            self.private_key, self.public_key_pem = crypto_funcs.diffie_hellman_server(
                self.p, self.g, public_key_pem_client
            )

            message = {
                "type": "DH_SERVER_KEY",
                "key": str(self.public_key_pem, "ISO-8859-1"),
            }

            self._send(message)

            self.shared_key = crypto_funcs.generate_shared_key(
                self.private_key, public_key_pem_client, self.used_digest_algorithm
            )

            return True
        except Exception as e:
            print(e)
            return False

    def process_open(self, message: str) -> bool:
        """
		Processes an OPEN message from the client.
		This message should contain the filename.

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
        logger.debug("Process Open: {}".format(message))
        if self.state != STATE_DH:
            logger.warning("Invalid state. Discarding")
            return False

        if not "file_name" in message:
            logger.warning("No filename in Open")
            return False

        # Only chars and letters in the filename
        file_name = re.sub(r"[^\w\.]", "", message["file_name"])
        file_path = os.path.join(self.storage_dir, file_name)
        if not os.path.exists("files"):
            try:
                os.mkdir("files")
            except:
                logger.exception("Unable to create storage directory")
                return False

        try:
            self.file = open(file_path, "wb")
            logger.info("File open")
        except Exception:
            logger.exception("Unable to open file")
            return False

        self._send({"type": "OK"})

        self.file_name = file_name
        self.file_path = file_path
        self.state = STATE_OPEN
        return True

    def process_data(self, message: str) -> bool:
        """
		Processes a DATA message from the client.
		This message should contain a chunk of the file.

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
        logger.debug("Process Data: {}".format(message))
        if self.state == STATE_OPEN or self.state == STATE_DH:
            self.state = STATE_DATA

        elif self.state == STATE_DATA:
            # Next packets
            pass

        else:
            logger.warning("Invalid state. Discarding")
            return False

        try:
            data = message.get("data", None)
            if data is None:
                logger.debug("Invalid message. No data found")
                return False

            bdata = base64.b64decode(message["data"])

        except:
            logger.exception("Could not decode base64 content from message.data")
            return False

        try:
            self.file.write(bdata)
            self.file.flush()
        except:
            logger.exception("Could not write to file")
            return False

        return True

    def process_close(self, message: str) -> bool:
        """
		Processes a CLOSE message from the client.
		This message will trigger the termination of this session.

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
        logger.debug("Process Close: {}".format(message))

        self.transport.close()
        if self.file is not None:
            self.file.close()
            self.file = None

        self.state = STATE_CLOSE

        return True

    def _send(self, message: str) -> None:
        """
		Effectively encodes and sends a message.

		:param message: The message to send
		:return:
		"""
        logger.debug("Send: {}".format(message))

        message_b = (json.dumps(message) + "\r\n").encode()
        self.transport.write(message_b)


def main():
    global storage_dir

    parser = argparse.ArgumentParser(description="Receives files from clients.")
    parser.add_argument(
        "-v",
        action="count",
        dest="verbose",
        help="Shows debug messages (default=False)",
        default=0,
    )
    parser.add_argument(
        "-p", type=int, nargs=1, dest="port", default=5000, help="TCP Port to use (default=5000)",
    )

    parser.add_argument(
        "-d",
        type=str,
        required=False,
        dest="storage_dir",
        default="files",
        help="Where to store files (default=./files)",
    )

    args = parser.parse_args()
    storage_dir = os.path.abspath(args.storage_dir)
    level = logging.DEBUG if args.verbose > 0 else logging.INFO
    port = args.port
    if port <= 0 or port > 65535:
        logger.error("Invalid port")
        return

    if port < 1024 and not os.geteuid() == 0:
        logger.error("Ports below 1024 require eUID=0 (root)")
        return

    coloredlogs.install(level)
    logger.setLevel(level)

    logger.info("Port: {} LogLevel: {} Storage: {}".format(port, level, storage_dir))
    tcp_server(ClientHandler, worker=2, port=port, reuse_port=True)


if __name__ == "__main__":
    main()
