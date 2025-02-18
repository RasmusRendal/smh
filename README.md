# The incredible Stateless Matrix Homeserver (SMH)

I have friends that live far away I would still like to make cry.
Unable to use physical violence, I have to resort to writing a stateless matrix homeserver, which allows a noreply user to send messages to unsuspecting victims, making a mess of their homeserver states.
This is achieved by having all the room creation, setup, and invite be constants derived from the receiving user id, and then shifting as much of the burden of maintaining the room state unto the receiving homeserver as possible.

The sole endpoint is `/send_message`.
Call it like so:

```
 $ curl -k https://127.0.0.1:8083/send_message --json '{"user": "@rasmus:localhost:8480", "msg": "Du skulle skamme dig"}'
```

This homeserver implements the absolutely necessary endpoints for matrix synapse to be able to receive messages via the federation API, only some of them give 500 errors.
Due to the victim homeserver deciding the event id of the join event, the DAG will be somewhat messed up.
Each message ends up being a child of the invite event instead, and the victim can't see any messages from before they join.
And did I mention that the whole project is incredibly shoddily made?

## Development
```bash
 $ # Generate certificates
 $ openssl req -x509 -nodes -days 3650 -newkey ec:<(openssl ecparam -name prime256v1) -keyout private_key.pem -out certificate.pem
 $ # Run the server
 $ gunicorn -b 127.0.0.1:8083 smh:app --reload --keyfile private_key.pem --certfile certificate.pem --workers 2
```

I've been testing with a matrix synapse dev environment, it works okay.
