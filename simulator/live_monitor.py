import socketio

sio = socketio.Client()

@sio.event
def connect():
    print("Connected to Fractal Vault live stream")

@sio.on("trust_event")
def on_trust_event(data):
    print("LIVE TRUST EVENT:")
    print(data)
    print("-" * 40)

sio.connect("http://127.0.0.1:3000")
sio.wait()