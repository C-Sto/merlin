# DNS comms
**WARNING** All DNS comms are performed essentially in *plaintext*. Any third party that is able to intercept data between the agent and the server will be able to see everything. This is extremely likely, given the way DNS works. No lookups are performed with the expectation that they are sent directly to the nameserver, it is always assumed that they are handed through third parties.

All base32 encoding is performed with the extended hex charset (known as HexEncoding) with no padding.

The space for command ID's in this transport is 3 bytes.


## Getting messages from the client
The model the server uses to send data to the client is as follows:
- After a client sends a message to the server, a 3 byte command ID is returned in the 3 leftmost octets in the A record response. 
- The client should convert those 3 bytes into a base32 string, and send a TXT lookup in the form `cmdid.ns`
- The txt response will include a single record indicating how many responses must be looked up to get the full response.
- The response can be retreived by lookup up `x.cmdid.ns` where x is the record number.


## Sending messages from the client
The model for a client sending a DNS message is as follows:

DNS A lookup of the form:
- `payload.this.max.cmdid.ns`

where:
- **ns**: This value is the host domain nameserver. It should be the value that the 'ns' record is set to.
- **cmdid**: This is the command ID, a unique 3 byte value used to ensure that received commands are not interleaved. This enables concurrent sending of multiple messages, likely to happen with multiple agents.
- **max**: This is the maximum count of chunked messages associated with cmdid, represented in a base32 value. It decodes to a uint32 (however, the top 4 bits are unused. The maximum value for this is therefore 16777215).
- **this**: This is is the relative chunk number, represented in base32. This is used to re-organise the payload values into the correct order on the server in the (likely) event that they arrive out-of-order. It also facilitates 'lost' messages, as DNS is also performed over UDP, requests might be lost. Having to send _all_ of the values back to re-assemble the original message is... not ideal.
- **payload**: This is a base32 value containing a chunk of the full message. When reassembled in the order specified by the `this` section, it should decode to a byte value that can be interpreted by the server. The value will never exceed a length of 60 characters, and is not intended to be decoded in isolation of all other chunks associated with the command ID.

DNS responses to the message send will indicate if and how the client should receive data from the server.

## A lookup responses

The A record lookups will result in a response from the server, assuming no errors are encountered. SRVERR or NX indicate a transport error.

- **0.0.0.0**: this indicates a chunk has successfully been received. No further action required.
- **x.x.x.1**: This indicates the final chunk has successfully been received and decoded correctly. The cmdID can be cleared from the agent memory. If a response is required to be returned to the client the octets correspond to the raw byte values in base10 that are to be requested (see the 'Getting messages from the client' section). To generate the msgID, the 3 byte value should be marshalled into a big endian slice of bytes. Eg: `00.12.34.56` would marshal into a byte slice represented in go as `[]byte{12,34,56}`, resulting in a base32 value of `1GH3G` (or represented in hex as `0c2238`).