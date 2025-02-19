from .matrix import SERVER_NAME, key, get_server_keys, CanonicalEncoder, room_creation_events, prev_event, send_invite, send_message, invite_event, room_created, userid_from_roomid
import time
from flask import Flask, Response, request
from synapse.api.room_versions import RoomVersions
from synapse.crypto.event_signing import add_hashes_and_signatures
from synapse.api.constants import EventTypes
from synapse.api.errors import Codes
import json


app = Flask(__name__)


def json_response(obj, status=200):
    return Response(CanonicalEncoder().encode(obj), mimetype="application/json", status=status)


@app.route("/.well-known/matrix/server")
def well_known():
    return json_response({"m.server": SERVER_NAME + ":443"})


@app.route("/_matrix/federation/v1/version")
def federation_version():
    return json_response({"server": {"name": "Rank matrix server", "version": "💯"}})


@app.route("/_matrix/key/v2/server")
def server_keys():
    return json_response(get_server_keys())


@app.route("/_matrix/federation/v1/query/profile")
def query_profile():
    data = request.args
    if data["user_id"] != f"@noreply:{SERVER_NAME}":
        return json_response({"errcode": "M_NOT_FOUND", "error": "User does not exist."}, status=404)
    return json_response({})


@app.route("/_matrix/federation/v1/make_join/<roomid>/<userid>")
def make_join(roomid: str, userid: str):
    rce = room_creation_events(userid)

    to_return = {
        "event": {
            "content": {
                "membership": "join"
            },
            "origin": SERVER_NAME,
            "origin_server_ts": round(time.time() * 1000),
            "room_id": roomid,
            "sender": userid,
            "state_key": userid,
            "prev_events": [prev_event(rce[-1])],
            "auth_events": [prev_event(rce[0]), prev_event(rce[3]), prev_event(rce[-1])],
            "depth": 5,
            "type": "m.room.member"
        },
        "room_version": "1"
    }
    return json_response(to_return)


@app.route("/_matrix/federation/v2/send_join/<roomid>/<eventid>", methods=['PUT'])
def send_join(roomid: str, eventid: str):
    rb = request.get_json()
    add_hashes_and_signatures(RoomVersions.V1, rb, SERVER_NAME, key)
    rce = room_creation_events(rb["sender"])
    # rb["prev_events"] = prev_event(rce[-1])
    response = {
        "auth_chain": rce,
        "event": rb,
        "members_omitted": True,
        "origin": SERVER_NAME,
        "servers_in_room": [
            SERVER_NAME,
            rb["origin"],
        ],
        "state": rce
    }

    return json_response(response)


@app.route("/_matrix/federation/v1/state/<roomid>")
def state(roomid):
    print(request)
    # TODO: Parse userid
    userid = userid_from_roomid(roomid)
    rce = room_creation_events(userid)
    return json_response({
        "auth_chain": rce,
        "pdus": rce
    })


@app.route("/_matrix/federation/v1/state_ids/<roomid>")
def state_ids(roomid):
    print(request)
    # TODO: Parse userid
    userid = userid_from_roomid(roomid)
    rce = room_creation_events(userid)
    return json_response({
        "auth_chain_ids": [e["event_id"] for e in rce],
        "pdu_ids": [e["event_id"] for e in rce]
    })


@app.route("/_matrix/federation/v1/get_missing_events/<roomid>", methods=['POST'])
def get_missing_events(roomid):
    b = request.get_json()
    print(request)
    print(b)
    return json_response({"events": [invite_event(userid_from_roomid(roomid))]})


@app.route("/_matrix/federation/v1/send/<txnid>", methods=['PUT'])
def send_transaction(txnid):
    """Currently just ignores EDUs"""
    for pdu in request.get_json()["pdus"]:
        # I think it keeps resending the join event, because we keep forking the room state
        assert pdu["type"] == EventTypes.Member
    if len(request.get_json()["pdus"]) > 0:
        return json_response({"error": "I don't care about your events"})
    return json_response({})


@app.route("/_matrix/federation/v1/backfill/<roomid>")
def backfill(roomid):
    print(request)
    return json_response({
        "origin": SERVER_NAME,
        "origin_server_ts": round(time.time() * 1000),
        "pdus": [],
    })


@app.route("/_matrix/federation/<version>/invite/<roomid>/<eventid>", methods=['PUT'])
def receive_invitation(version, roomid, eventid):
    return json_response({
        "errcode": Codes.FORBIDDEN,
        "error": "This homeserver is not taking invitations",
    }, status=403)


@app.route("/send_message", methods=['POST'])
def send_messagefr():
    data = request.get_json()
    user = data["user"]
    if not room_created(user):
        send_invite(user)
    r = send_message(user, data["msg"])
    return json_response({"response": r.text})


def handle_bad_request(e):
    print(request)
    print(e)
    return "Bad request!", 404


app.register_error_handler(404, handle_bad_request)
