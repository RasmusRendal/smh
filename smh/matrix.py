from typing import Any, Callable, Dict, Tuple
import json
import hashlib
from signedjson.types import SigningKey
from signedjson.key import decode_signing_key_base64, NACL_ED25519, get_verify_key
from signedjson.sign import sign_json
import requests
import time
import sys
import os
import re
from synapse.events.utils import prune_event_dict
from synapse.api.room_versions import RoomVersions
from synapse.api.constants import EventTypes, HistoryVisibility
from synapse.crypto.event_signing import add_hashes_and_signatures

from .unpaddedbase64 import decode_base64, encode_base64

slug = "v4"
key = decode_signing_key_base64(
    NACL_ED25519, os.environ["SMH_KEY_VERSION"], os.environ["SMH_KEY"])

SERVER_NAME = os.environ["SMH_SERVER_NAME"]
ROOM_NAME = "Rank test room"
VERIFY_TLS = False


class CanonicalEncoder(json.JSONEncoder):
    def __init__(self, skipkeys=False, ensure_ascii=False, check_circular=True, allow_nan=True, sort_keys=True, indent=None, separators=(',', ':'), default=None):
        json.JSONEncoder.__init__(self, skipkeys=skipkeys, ensure_ascii=False, check_circular=check_circular,
                                  allow_nan=allow_nan, sort_keys=True, indent=indent, separators=(',', ':'))


def encode_canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        # Encode code-points outside of ASCII as UTF-8 rather than \u escapes
        ensure_ascii=False,
        # Remove unnecessary white space.
        separators=(",", ":"),
        # Sort the keys of dictionaries.
        sort_keys=True,
        # Encode the resulting unicode as UTF-8 bytes.
    ).encode("UTF-8")


def strip_userid(userid: str) -> str:
    return encode_base64(userid.encode()) + "ROM" + slug


def timestamp() -> int:
    return 1739277117153


def roomid(userid: str) -> str:
    return "!" + strip_userid(userid) + ":" + SERVER_NAME


def userid_from_roomid(roomid: str) -> str:
    return decode_base64(roomid.split("ROM")[0][1:]).decode()


def get_server_keys():
    response = {"old_verify_keys": {},
                "server_name": SERVER_NAME,
                "valid_until_ts": round(time.time() * 1000) + 1000 * 60 * 60 * 72,
                "verify_keys": {
                    ("%s:%s" % (key.alg, key.version)): {
                        "key": encode_base64(get_verify_key(key).encode())
                    },
    }
    }
    return sign_json(response, SERVER_NAME, key)


def resolve_servername(name: str) -> str:
    port = None
    if name.count(":") == 1:
        name, port = name.split(":")
    elif name.count(":") > 1:
        # IPv6 :/
        raise NotImplementedError

    ip_literal_regex = re.compile(
        r"^((localhost)|(([0-9]{1,3}\.){3}[0-9]{1,3}))$")
    if ip_literal_regex.match(name):
        return f"https://{name}:{port}"
    else:
        assert port == None
        r = requests.get(f"https://{name}/.well-known/matrix/server")
        return r.json()["m.server"]


def make_matrix_request(
    method,
    origin_name: str,
    origin_key,
    destination: str,
    destination_url: str,
    path: str,
    content,
) -> requests.Response:
    if method is None:
        if content is None:
            method = "GET"
        else:
            method = "POST"

    json_to_sign = {
        "method": method,
        "uri": path,
        "origin": origin_name,
        "destination": destination,
    }

    if content is not None:
        json_to_sign["content"] = content

    signed_json = sign_json(json_to_sign, origin_name, origin_key)

    authorization_headers = []

    for key, sig in signed_json["signatures"][origin_name].items():
        header = 'X-Matrix origin=%s,key="%s",sig="%s",destination="%s"' % (
            origin_name,
            key,
            sig,
            destination,
        )
        authorization_headers.append(header)

    dest = "%s%s" % (destination_url, path)
    print("Requesting %s" % dest, file=sys.stderr)

    headers = {
        "Authorization": authorization_headers[0],
    }

    if method == "POST":
        headers["Content-Type"] = "application/json"

    return requests.request(
        method=method,
        url=dest,
        headers=headers,
        verify=VERIFY_TLS,
        data=encode_canonical_json(content),
        # stream=True,
    )


def prev_event(event):
    return (event["event_id"], event["hashes"])


def room_creation_events(userid: str):
    create_room = {
        "content": {
            "creator": f"@noreply:{SERVER_NAME}",
            "m.federate": True,
            "room_version": "1"
        },
        "event_id": f"$createroom{strip_userid(userid)}:{SERVER_NAME}",
        "origin_server_ts": timestamp(),
        "room_id": roomid(userid),
        "sender": f"@noreply:{SERVER_NAME}",
        "state_key": "",
        "depth": 0,
        "type": EventTypes.Create,
        "auth_events": [],
        "prev_events": [],
        "unsigned": {
            "age": 0,
            "membership": "join"
        }
    }
    add_hashes_and_signatures(RoomVersions.V1, create_room, SERVER_NAME, key)
    noreply_join = {
        "type": EventTypes.Member,
        "sender": f"@noreply:{SERVER_NAME}",
        "content": {
            "displayname": "Noreply",
            "membership": "join"
        },
        "state_key": f"@noreply:{SERVER_NAME}",
        "origin_server_ts": timestamp(),
        "unsigned": {
            "membership": "join",
            "age": 0
        },
        "event_id": f"$noreplyjoin{strip_userid(userid)}:{SERVER_NAME}",
        "depth": 1,
        "prev_events": [prev_event(create_room)],
        "auth_events": [prev_event(create_room)],
        "room_id": roomid(userid)
    }
    add_hashes_and_signatures(RoomVersions.V1, noreply_join, SERVER_NAME, key)

    history_visibility = {
        "type": EventTypes.RoomHistoryVisibility,
        "sender": f"@noreply:{SERVER_NAME}",
        "content": {
            "history_visibility": HistoryVisibility.WORLD_READABLE,
        },
        "state_key": "",
        "origin_server_ts": timestamp(),
        "prev_events": [prev_event(noreply_join)],
        "auth_events": [prev_event(create_room), prev_event(noreply_join)],
        "unsigned": {
            "membership": "join",
            "age": 0
        },
        "event_id": f"$hisvis{strip_userid(userid)}:{SERVER_NAME}",
        "depth": 2,
        "room_id": roomid(userid)
    }
    add_hashes_and_signatures(
        RoomVersions.V1, history_visibility, SERVER_NAME, key)

    power_levels = {
        "content": {
            "ban": 100,
            "events": {
                "m.room.name": 100,
                "m.room.power_levels": 100
            },
            "events_default": 100,
            "invite": 100,
            "kick": 100,
            "notifications": {
                "room": 100
            },
            "redact": 100,
            "state_default": 100,
            "users": {
                f"@noreply:{SERVER_NAME}": 100
            },
            "users_default": 0
        },
        "event_id": f"$powerlevels{strip_userid(userid)}:{SERVER_NAME}",
        "prev_events": [prev_event(history_visibility)],
        "auth_events": [prev_event(create_room), prev_event(noreply_join)],
        "origin_server_ts": timestamp(),
        "room_id": roomid(userid),
        "sender": f"@noreply:{SERVER_NAME}",
        "state_key": "",
        "type": EventTypes.PowerLevels,
        "depth": 3,
        "unsigned": {
            "age": 0,
            "membership": "join"
        }
    }
    add_hashes_and_signatures(RoomVersions.V1, power_levels, SERVER_NAME, key)

    invite = {
        "content": {
            "membership": "invite"
        },
        "event_id": f"$invite{strip_userid(userid)}:{SERVER_NAME}",
        "room_id": roomid(userid),
        "origin": SERVER_NAME,
        "depth": 4,
        "origin_server_ts": timestamp(),
        "sender": f"@noreply:{SERVER_NAME}",
        "state_key": userid,
        "type": EventTypes.Member,
        "auth_events": [prev_event(create_room), prev_event(noreply_join), prev_event(power_levels)],
        "prev_events": [prev_event(power_levels)],
    }
    add_hashes_and_signatures(RoomVersions.V1, invite, SERVER_NAME, key)

    events = [create_room, noreply_join,
              history_visibility, power_levels, invite]
    return events


def invite_event(userid):
    return room_creation_events(userid)[-1]


def send_invite(user):
    user_server = ":".join(user.split(":")[1:])
    server_url = resolve_servername(user_server)
    event_json = invite_event(user)
    add_hashes_and_signatures(RoomVersions.V1, event_json, SERVER_NAME, key)
    invite_payload = {
        "event": event_json,
        "invite_room_state": [
            {
                "content": {
                    "name": ROOM_NAME
                },
                "sender": f"@noreply:{SERVER_NAME}",
                "state_key": "",
                "type": EventTypes.Name
            },
            {
                "content": {
                    "join_rule": "invite"
                },
                "sender": f"@noreply:{SERVER_NAME}",
                "state_key": "",
                "type": EventTypes.JoinRules
            }
        ],
        "room_version": "1"
    }

    r = make_matrix_request("PUT", SERVER_NAME, key, user_server, server_url,
                            f"/_matrix/federation/v2/invite/{roomid(user)}/{event_json["event_id"]}", invite_payload)
    return r


def send_message(user, msg):
    user_server = ":".join(user.split(":")[1:])
    server_url = resolve_servername(user_server)
    rce = room_creation_events(user)
    message_event = {
        "type": EventTypes.Message,
        "sender": f"@noreply:{SERVER_NAME}",
        "content": {
            "msgtype": "m.text",
            "body": msg,
            "m.mentions": {}
        },
        "origin_server_ts": round(time.time() * 1000),
        "event_id": f"$msg{strip_userid(user)}{round(time.time() * 1000)}:{SERVER_NAME}",
        "room_id": roomid(user),
        "auth_events": [prev_event(rce[0]), prev_event(rce[1]), prev_event(rce[3])],
        "prev_events": [prev_event(rce[-1])],
        "depth": 2,
    }
    add_hashes_and_signatures(RoomVersions.V1, message_event, SERVER_NAME, key)
    request_body = {
        "edus": [],
        "origin": SERVER_NAME,
        "origin_server_ts": round(time.time() * 1000),
        "pdus": [message_event],
    }

    txnId = str(round(time.time() * 1000))
    r = make_matrix_request("PUT", SERVER_NAME, key, user_server,
                            server_url, f"/_matrix/federation/v1/send/{txnId}", request_body)
    return r


def room_created(user):
    user_server = ":".join(user.split(":")[1:])
    server_url = resolve_servername(user_server)
    eventId = room_creation_events(user)[0]["event_id"]
    r = make_matrix_request("GET", SERVER_NAME, key, user_server,
                            server_url, f"/_matrix/federation/v1/event/{eventId}", None)
    return len(r.text) > 5
