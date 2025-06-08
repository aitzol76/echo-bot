import asyncio
import json
import logging
import sys
from getpass import getpass
from argparse import ArgumentParser
from typing import Optional, FrozenSet

from slixmpp import ClientXMPP
from slixmpp.jid import JID
from slixmpp.stanza import Message
from slixmpp.plugins import register_plugin
from slixmpp.xmlstream.handler import CoroutineCallback
from slixmpp.xmlstream.matcher import MatchXPath

from slixmpp_omemo import XEP_0384
from omemo.storage import Storage, JSONType, Just, Nothing
from omemo.types import DeviceInformation

# Configure logging
log = logging.getLogger("omemo-bot")
logging.basicConfig(level=logging.DEBUG)


class JSONStorage(Storage):
    FILE = "omemo_storage.json"

    def __init__(self):
        super().__init__()
        try:
            with open(self.FILE, encoding="utf8") as f:
                self._data = json.load(f)
        except Exception:
            self._data = {}

    async def _load(self, key: str):
        return Just(self._data[key]) if key in self._data else Nothing()

    async def _store(self, key: str, value: JSONType):
        self._data[key] = value
        with open(self.FILE, "w", encoding="utf8") as f:
            json.dump(self._data, f)

    async def _delete(self, key: str):
        self._data.pop(key, None)
        with open(self.FILE, "w", encoding="utf8") as f:
            json.dump(self._data, f)


class CustomOMEMOPlugin(XEP_0384):
    def plugin_init(self):
        self._storage = JSONStorage()
        super().plugin_init()

    @property
    def storage(self):
        return self._storage

    @property
    def _btbv_enabled(self) -> bool:
        return True

    async def _devices_blindly_trusted(self, blindly_trusted: FrozenSet[DeviceInformation], identifier: Optional[str]):
        log.info(f"🔐 Trusted devices: {blindly_trusted}")

    async def _prompt_manual_trust(self, manually_trusted: FrozenSet[DeviceInformation], identifier: Optional[str]):
        log.warning("Manual trust prompt unexpectedly triggered")

register_plugin(CustomOMEMOPlugin)


class OmemoEchoBot(ClientXMPP):
    def __init__(self, jid, password):
        super().__init__(jid, password)
        self.add_event_handler("session_start", self.start)
        self.register_handler(CoroutineCallback(
            "MessageHandler",
            MatchXPath("{%s}message" % self.default_ns),
            self.message_handler
        ))

    async def start(self, _):
        self.send_presence()
        await self.get_roster()
        log.info("✅ Connected")

        # Publish OMEMO bundle
        log.info("🔐 Publishing OMEMO bundle...")
        await self['xep_0384'].publish_bundle()
        log.info("✅ OMEMO bundle published")

        # Optional greeting
        await self.send_encrypted(self.boundjid.bare, "chat", "🤖 OMEMO EchoBot is online!")

    async def message_handler(self, msg: Message):
        mfrom = msg["from"]
        mtype = msg["type"]
        omemo = self["xep_0384"]

        if mtype not in {"chat", "normal"}:
            return

        if omemo.is_encrypted(msg):
            try:
                decrypted, _ = await omemo.decrypt_message(msg)
                body = decrypted.get("body", "")
                log.info(f"🔓 Decrypted from {mfrom}: {body}")
                await self.send_encrypted(mfrom, mtype, f"🔁 Echo: {body}")
            except Exception as e:
                log.warning(f"❌ Decryption failed: {e}")
                # Only respond with plaintext error, do NOT fallback to plaintext echo
                self.send_plain(mfrom, mtype, f"❌ Couldn't decrypt: {e}")
        else:
            body = msg.get("body", "")
            if body:
                log.info(f"✉️ Plaintext from {mfrom}: {body}")
                self.send_plain(mfrom, mtype, f"🔁 Echo (plaintext): {body}")

    def send_plain(self, to: JID, mtype: str, body: str):
        msg = self.make_message(mto=to, mtype=mtype)
        msg["body"] = body
        msg.send()

    async def send_encrypted(self, to: JID, mtype: str, body: str):
        omemo = self["xep_0384"]
        msg = self.make_message(mto=to, mtype=mtype)
        msg["body"] = body
        msg.set_from(self.boundjid)

        try:
            messages, _ = await omemo.encrypt_message(msg, to)
            for ns, m in messages.items():
                m["eme"]["namespace"] = ns
                m["eme"]["name"] = self["xep_0380"].mechanisms.get(ns, "OMEMO")
                m.send()
        except Exception as e:
            log.error(f"❌ Encryption failed: {e}")
            self.send_plain(to, mtype, f"❌ Failed to encrypt: {e}")


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-u", "--username", help="Your full JID")
    parser.add_argument("-p", "--password", help="Your XMPP password")
    args = parser.parse_args()

    if not args.username:
        args.username = input("Username (JID): ")
    if not args.password:
        args.password = getpass("Password: ")

    xmpp = OmemoEchoBot(args.username, args.password)
    xmpp.register_plugin("xep_0199")  # Ping
    xmpp.register_plugin("xep_0380")  # EME
    xmpp.register_plugin("xep_0384", module=sys.modules[__name__])  # OMEMO

    xmpp.connect()
    asyncio.get_event_loop().run_forever()

