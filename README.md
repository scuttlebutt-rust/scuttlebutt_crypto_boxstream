# Scuttlebutt BoxStream
An implementation of the box stream protocol used by Scuttlebutt for secure
communication between peers.

## Usage
To create a pair of boxer/unboxer:
```cs
var client = new Client(network_key, server_publicKey, client_keypair);

var a = client.ClientEphemeralPubKey;
var b = client.ServerEphemeralPubKey;

var (client_boxer, client_unboxer) = BoxStreamBuilder.Build(
  client.ClientDerivedSecret,
  server_publicKey,
  client_keypair.PublicKey,
  network_key,
  a, b
);
```

After the creation of the `Boxer` and `Unboxer` they can be used for
sending:
```cs
var plain = System.Text.Encoding.Unicode.GetBytes("hello world");

var msg = client_boxer.Box(plain);
```

And receiving:
```cs
var netstream = NetworkStream(inbound_conn, true);

var reply = await receiver.Unbox(netstream);
Console.WriteLine(reply);
```

# License
Unless explicitly stated, all the files in this repository are under the AGPL
[license](./LICENSE).
