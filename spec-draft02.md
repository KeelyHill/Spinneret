
# Spinneret Description and  Specification

## Sections
- Philosophies
- The Object Encoding
- Spinneret Protocol and Specification
    - Overview (gives a short high-level look at the protocol)

## Philosophies

- Small, lightweight, portable.
- Unlocking/breaking a single device should only comprise that device.
- User control (and revocability of nodes).
- As an interface to functions  and properties.
- All communication within a network is encrypted.
- Nodes should not impose on the user or their experience; but may make suggestions.
- Camel case names
- UTF-8 encoded
- Names (of properties and functions) describe themselves and their purpose specifically and briefly, nothing more, but staying generic. (e.g. not "`GE_TurnOn()`", but "`turnOn()`", not "`flipOn()`")
- Assume no access to anything for node, it must be granted by network-setup-user -- this is aside from a node's own property permissions #later

## The Object Encoding (a possible lighter and specific alternative to json)

Try to put in https://en.wikipedia.org/wiki/Extended_Backus–Naur_form #todo

### Encoding Design:

Generic types -- `name (repr) = syntax --> example`

- string (`s`) = `s[len]:[string value]` --> `s11:Hello World == "Hello World"`  (`1:a` is a char)
  - Strings are utf-8 encoded; the length of a string is its utf-8 encoded length. Emoji length 4 example in python: `b'\xf0\x9f\x8c\xa1'.decode('utf-8') == '
  - JSON (`application/json`) can also be placed as data for longer trees where there is user client which can do the parsing and/or nice layout, but the data is not necessary for the functioning of the node.
  - Even CSV(`text/csv`) could possibly work for things like sensor logs.
- int (`i`) = `i[value];` --> `i42;` == `42` -- (corresponds to a signed 32 bit int in C if the `I` and `h` get implemented, otherwise `int64_t`)
  - More specific and memory conscious integers (proposal) #maybe
    - `I[val];` - corresponds to a signed (64 bit) C type --> `I438955893;`
    - `h[val];` - corresponds to a signed C `short` (16 bit) -- even `H`=16 bit `h`=8bit
    - also considering a `u` suffix to the `i` to signify unsigned (e.g. `iu42;`)
    - would an 8 bit int be useful enough? #maybe
    - Alternative: `byte (y), int16 (i), int32 (I), int64 (L), float (d), double (D), huge (H)`
- float (`f`) = `f[value];` --> `f4.2; == 4.2`
  - double precision assumed
  - scientific shorthand, can be used to represent larger values - `2e3` as 2 km, for example #maybe
  - somehow support NaN? is this just null? #maybe
- bool (`b`) = `T` or `F` --> `T == true`
- list (`l`) = `l[items];` --> `li42;; == [42]`
  - thinking about forgetting the `l` and `;` and just using `[]`. I can't think of an advantage to the former right now (perhaps consistency) #maybe
  - only allow one type per list? #maybe
- dict (`d`) = `d[key][value][key][value]...;` --> `ds3:foos3bar; == {'foo':'bar'}`
- null (`n`) = `\x00`
- byte data (`z`) = `z[data len]:[bytes]` --> `z15:\xc3\x95\x81\xb3\x8e\xac\xa0\x97\x15\x97\x1c\xcd\xca\x1e\xc9`
  - Unlike string(`s`), there is there is no utf-8 encoding or decoding -- only bytes
  - There is no set interpretation for this data -- the protocol uses this type for the various cryptographic keys.
  - SVG (`image/svg+xml`), for example, can be handy for icons and the like.

Special "encapsulating" types

- Action: `^[action_name]([$parameter]; ...)[return_type repr];`
  - (action) Parameter = `$[name]|[type repr]|[meta];` --> `$temperature|i|d...;`
  -  `^set_color($hex_string|s|n;)n;`
  - \#later To make optional append a `?` to the end of the name. When calling pass null if argument not being sent. May allow for same name actions with different params (kind of like c++ overloading) #later
  - later may add meta to actions not just on the params #later #maybe
- Property: `p[name]|[type repr]|[value]|[meta];` --> `pcolor|s|s6:1100FF|ds4:descs16:hex color;>`
  - Properties are _never more than readonly_, they must be set via a 'setter' action - they can also be completely private
  - Names must be unique to the node
- Node: `n<p...;p...;...|^action(...);^action(...);|[node info dict]>`
  - Nodes hold their properties, actions, and information. See the protocol for details on the node info dictionary.
- Forbidden characters for names (including `[space]`): ``{}()[]|:;+,.=><%$#@!?^`*'\"~``.
- `/` is a namespace delimiter for nodes with many actions or properties with categories (e.g. Each app has a namespace) #maybe
- Possible enum syntax for properties and action parameters #later #maybe
  - `type repr` would be `'e'`, the meta dict would contain the key `"enum"` with a list value containing the strings of the enum. When being call (through an action, for example), the index of the enum value would be sent as an int (or even `e[index];`)
  - Example:  
definition: `$waterTemp|e|ds4:enum ls3:hots4:warms4:cold;;`  
usage: `^startWash(i1;);`
  - It could also support 'standard enums' defined by this spec (or a spec) when the meta would be the name of the enum rather than as list. It could also use this technique to self reference an enum in the node's meta using some prefix.
- Names are not encoded as strings or bytes (no `s#:...`), just characters. Parsers are to use name bounding characters ('`^`' and '`(`' on actions, for example)
- Meta -  `meta` is a dictionary allowing specific keys all being optional (pass null when empty). See protocol below for keys.

Maybe support an 'AnyObject' or 'AnyType' or 'T'? #later #maybe

## Spinneret Protocol and Specification

### Overview  

Of the entire protocol defined, there are really several 'micro-protocols'. Each level is essentially a structure frame whose implementations may be represent as objects and/or structs.  

Most basic and core of the protocol conception is the "Node structure definition". It defines:   
- what a node is; its attributes, info, cryptographic keys, and address.  
- its properties (values related to the node's operation and use)  
- the property structure  
- its actions (procedures that can be requested to run with optional arguments) the "action/parameter structures"  
- the various metadata these structures can have  
- some network settings that are shared by all nodes in a network.  

In close companionship with the Node is the concept of addressing each based on an asymmetric signing algorithm followed by cryptographic hashing. There are two key-pairs generated in the same means: a signing pair (used to generate the address) and an peer-to-peer encryption (via key agreement) pair. Such signing and encryption is crucial to the protocol. The addressing also works with routing. Address generation (defined below) = `base64(sha256^2(public_verify_key))`  

The next layer is the broadcast framing structure. It defines how a broadcast (as raw bytes) is structured and the 'kinds' of broadcasts that are transmitted. It further specifies the distinct use and handling of each kind. Broadcasts are always have _some_ destination. A broadcast may be _to_: and single node (the destination's address), a general group (prefixed with `*`), a secure group (prefixed with a `#`) or to all nodes - `*`. The payload is also encrypted when the destination is a node or a secure group.  

Networks (and further more routing) are (while can be independent of the broadcast structure) built on top of broadcasts. All communication (i.e. broadcasts) between nodes in a network is encrypted with the symmetric key of the network 'proving' a nodes existence in a network. Nodes are to implement certain methods/procedures via the Node-level protocol ("actions" e.g. `^timeSet(...);`) for setup, maintenance, and configuration of the node and network. Networks can only be setup by a "user". A "user" is simply another asymmetric key pair acting as an administrator to the network independent of the node used _by_ the user. "Users" can perform network wide actions (such as setting the time, or validate nodes). They are verified via their signature on any broadcast. Every node stores the user's signing key, given to it only by a user after initialization into the network.   

[Routing algorithm a work in progress.]  

Fully encrypted broadcasts are the closest "to the metal". They follow a basic structure containing the symmetrically encrypted data, along with a signature from the sender node.  

Final introductory note: While this was conceived to work via a mesh network radio (such as ZigBee), it could also be layered on top of TLS and/or IP too (even an HTTP api). It _could_ act as a virtual node (represented in as a DB model) on a server ("cloud" to raspberry pi) doing some special capability, logging, or external login. I write this to show possibility; if done later, proceeds with caution of security.

---

### Broadcasts

Also thinking about a fail silently, particularly for announcement (they could/should be incoming only, expecting no response)

Announcing/Requesting the node info itself as dict and entire node structure. (as pseudo property) #todo #wip

Broadcasts are a structure of bytes that is encrypted with the network key and physically transmitted.

Difference between a packet: A broadcast is the structure of sender address, receiver address, and broadcast payload. Once the encoded broadcast is encrypted for transmission, a strict few more bytes are pre-pended (as a short header) to make a the **packet: a version byte, handle byte, and length of the broadcast**.  
```  
+----+-------+-------+-------+-------+-------+-------------+  
|byte|   0   |   1   |   2   |   3   |   4   | n...65535+4 |  
+----+-------+-------+---------------+---------------------+  
|    |version|handle |  length of    |   full broadcast    |  
|    |       |       |  full         |                     |  
|    |       |       |  broadcast    |                     |  
+----+-------+-------+---------------+---------------------+  
```

- version: `x01` at this time
- handle byte: tells the receiver how decrypt, decode, or otherwise process the broadcast data. Currently, there are two:  
`x01`: normal in-network broadcast, the most common.  
`x05`: discovery broadcast, used in the adding of nodes to a network  
`x00`: nothing encrypted or signed, but normal broadcast otherwise, used in early testing
  - `x0A, x0E,`: nothing (expansion possibility, follows pattern)  
`x20-x24`: nothing (expansion possibility, ascii device control codes)  
`x2A,xAA`: nothing (expansion possibility, follows pattern)   #later  
`x30-3f`: 16 in sequence
    - network-network communication would be nice, and could use on of these #later
  - possible expansion:  
- beacon advertisement  
- node adhoc (signed, but no network-level encryption)  
- node adhoc-open; only transmit plain broadcast, no encryption or signing.  
- network-network communication  
- infrastructure (e.g. stoplights,signs)
- length: the length of the full broadcast (network byte-order)
- broadcast: broadcast bytes are signed then networked encrypted, then encrypted based on handle

All (but discovery) broadcasts are encrypted using the network symmetric key. There may be further encryption depending on the secrecy required on the broadcast.

The broadcast destination, marked in the specification below as `to`. The destination may be a single node, all nodes, or a group. Broadcasts are always encrypted with the network key, but further encryption on the payload may be added depending on the destination. A single `*` (star) is used to send a broadcast to all nodes in the network with the single layer of encryption.  

There are two kinds of "groups" (other than `*`): standard (referred to as a 'group', or 'general group') and secure group. A group is simply a name (utf-8 encoded) with a character prefix specifying the kind of group. (e.g. `#doorlocks`, `*lights`)  
- `#` (octothorp) prefixes a secure group there is an extra layer of encryption on payload. These require more setup by the user as a group specific symmetric key must be transferred to all nodes the user wishes to be in the group. If a secure group is the destination, the payload of the broadcast is also encrypted with this symmetric key. There can only ever be one secure group for a broadcasts destination. To revoke a node for a secure group, the a new key must be redistributed.  
- `*` (star) prefixes a standard group, not to confused with just '`*`' for all nodes. The payload is _not_ encrypted additionally. Therefore, standard groups can simply be assigned and used more like wild cards -- they are certainly easier on the processor as well -- their use is recommend when internal security of the broadcasted data is not a large concern. (Note: broadcasts are still signed by the sender.)

Broadcasts follow a basic structure as follows, parts of the broadcast are separated by `|` (pipe):  
`[version][nonce_id]|[KIND]|[to]|[from]|[payload as base64]` <small>(generic illustration, not valid)</small>

Every broadcast has a 4 byte (32 bit) nonce id, it SHOULD be random to be unique.

The version is as bytes, so `0.1` is `'\x00\x01'` (2-bytes)

The payload and encryption

- The `payload` may be in a variety of formats (dictated by the kind of broadcast), but the data is always base 64 encoded when placed into the broadcast structure.
  - Idea for multi-part payloads: The payload frame itself begins with a byte telling about the payload. `\x00` for single broadcast, `\x0`1 for the start of a multi-part broadcast, `\x02` for the continuing of the multipart broadcast, `\x81` for the last part of a multipart broadcast. The receiver assembles the full data if possible or streams it (like music playing) #later #maybe
  - Idea: a 'payload dict context', like a standardized namespace context for a broadcast ANNC
- The "extra layer of encryption" is placed on the based 64'd payload when the destination is a single node or a secure group, otherwise it is left unencrypted base 64 data.

"Kinds" of broadcasts specification:  
`v/id` represents the version and nonce bytes below for example cleanness. (e.g. `\x00\x00\x01\x41\xF1\x91\xC4\x2D`)

- `REQ` (request) - request for the value of a property or to run an action - properties and actions separated by a comma.
  - `v/id|REQ|[to]|[from]|[props or ^actions()... payload]|[announce result group else null]`
  - ex: `'v/id|REQ|abc|xyz|^turnOn()|\x00'` → base 64 payload→ `'v/id|REQ|abc|xyz|dHVybk9uKCk|\x00'`
  - Comma separation of payload: `on,^turnOn()` is requesting to get the value of `on` and run `^turnOn()`.

  - Action arguments have no extraneous delimiters as they are treated like lists. `^setGPIO(i7;T)` - set gpio #7 to true.
  - An action argument MAY be null if the action implementation allows it. (This can be used to simulate optional parameters if there is not an explicit way in future versions.) Implementations SHOULD ignore this value if when validating the requested arguments against the parameters types.
  - A response will only become an announcement if there was not an error and the "announce group" is not null.
  - The `announce result group` tells the receiver node to broadcast an announcement to a group rather than a response. A response will only become an announcement if there was not an error and the 'announce group' is not null.
  - Every request MUST have some kind of response (or announcement) back. If running void action, just `ACK` (no payload, see `RESP`).
- `ANNC` (announcement) - sends the value of a property _or_ the definition of the entire node across all nodes (or some, never one) in the network.
  - `v/id|ANNC|[to]|[from(self)]|[payload]`
  - Use cases included: sudden change like motion detection, a push notification, a data dump, etc. Any time when a request is not needed to provoke.
  - The payload can be a node structure, or a encoded dictionary whose keys are the name of a node property and value is the (encoded) value of the property.  
~~Announcements MUST be to some kind of group (including `*`)~~.
  - ex: `'v/id|ANNC|*|xzy|node<...>'`
  - ex: `'v/id|ANNC|#dinning_room|abc|ds6:colors7:#ff33aa;'` → base 64 payload → `'v/id|#dinning_room|abc|ZHM2OmNvbG9yczc6I2ZmMzNhYTs='`
  - ? Considering an 'SOS' type announcement payload, for a node to use if in bad situation (or just a action to be called to the user's node) #later #maybe
- `RESP` (response) - a structure for a response to a request.
  - `v/id|RESP|[to]|[from]|[CODE]|[payload]`
  - ex: `'v/id|RESP|xyz|abc|ACK|hbotr\x00'`
  - If the response code is `OK` then the payload is an encoded dictionary (which may only have one key-value pair) containing the keys of either the property name or the action name (prefixed with a '`^`') requested. The value for each key is the encoded value of the property or the returned value of the action.   

For multi-part requests where there was an issue with a specific part (such as no permission for a property), a node SHOULD set the first byte of key's value to '`\x15`' indicating a problem without disruption. The requester is to assume they cannot access the property or run the action (i.e. `ds8:fakeprops1:\x15;`), the rest of the value MAY be an error message string #wip  

For any other response codes, the payload is either a string description of the error or null.
  - Responses MUST NOT be _to_ a group, but rather the single node that made the request
  - When building a response, actions in a request MUST be dealt with first as their function may change the value of a property.
  - When processing and running an action (with or without a return value), an action MAY add properties to the response dictionary associated with running the action as a way to update the node.
  - Idea: was considering putting the request nonce (`...|[req nonce][payload]`) before the payload of the response to signify what request is being respond too, but i don't have a great reason for it now. Making note for later. #later #maybe
  - Response codes accompany a response broadcast, giving it a specific purpose and handleability. Codes & definitions:

    - `ACK` - acknowledgment, used when a broadcast is to be acknowledged with no need for payload.
    - `OK` - okay, no issues (also like `ACK` but with a payload)
    - `BDSIG` - bad signature; node could not validate the signature
    - `PRSER` - parse error; node could not successfully parse the broadcast -- payload is brief reason.
    - `DENID` - request (`REQ`) was denied -- payload is brief reason.
    - `NAK` - negative acknowledgement. More generic error, no other codes apply; node does not know what went wrong, but node okay. For example, an action may  fail to run/exist/have bad parameters, but other actions and properties can be returned.
    - `NUKER` - node unknown error (or just something wrong with the node itself) -- payload may contain brief reason. This code should only be sent as a last case lost cause scenario. _When the node is not okay_. (see: `NAK` for less extreme cases). Clients can alert user should this error be seen/logged. There _may_ be nothing wrong with the broadcast.
    - Possible Ideas:  
Need one between ok and denied ('`MEH`' mostly okay, issues ISUE )   
`WHOU`(if payload attempts to be encrypted back to a node, but can't due to lack of public key to it is not encrypted)  
`FORB`(forbidden) `NTFD, NOCH`(no change)  
An unencrypted-out-of-network `BEACON` broadcast could be useful(for later)   
other node update required?, `NUPDT`(node update suggested),  
something if a node requests help (if it thinks it can decrypt net-casts, NUKER?)`   #maybe #wip  

`BEACON` type name - like a ANNC but not between nodes in network (could just use ANNC)

Plain Broadcast to Transmittable Broadcast:  

After being structure into an plain unencrypted broadcast the entire frame is base 64'ed, signed(with nodes signing private key) and placed into the final broadcast structure as follows:  
```  
(1) (Raw broadcast): \x00\x01NONC|REQ|abc|xyz|^turnOn()|n  
(1.5) Encrypt payload appropriately for destination - also based64'd post-encryption:  
                     \x00\x01NONC|REQ|abc|xyz|en2r79t3d9al9ea|n  
(1.5 else) base64 payload if no encryption done to payload  
(2) Sign:    '[signature][message]' structure, encode as base 64:  
              sigexampleasdfghjk\x01\x02HFIAT|REQ|abc|xyz|en2r79t3d9al9ea|n  
              c2lnZXhhbXBsZWFzZGZnaGprXHgwMF...WJjfHh5enxlbjJyNzl0M2Q5YWw5ZWF8bg  
(3) Finally encrypt with network symmetric key, algorithm nonce appended to front:  
                 nonceblabarnonceqwertyqwobviouslyfakepoiuyasserioslynotrealdfgzxcvb  
                 \                                                                /  
(4) Actually broadcast these bytes with appending marking byte (pseudo-encryption for illustration)  
```

Fully encrypted broadcast from network to plain data  
```  
(1) With the raw data: nonceblabarnonce...realdfgzxcvb  
(2) Decrypt using network symmetric key  
(3) Verify signature and separate data  
(4) Check the destination (assure to receiver directly or by group)  
(4.5) Decrypt/base 64 decode the payload appropriately  
(5) Process the payload (and possible response code or announce result)  
```

### Node

A node is seen by itself and all other nodes as an structure encapsulating data and functions -- like an object in OOP. A node structure has properties, actions, and a 'node info' dict. Nodes are not privileged (they can be granted a key to a secure group), only a user key-value key pairs have the power to do network relation actions (such as setting the time or adding new nodes.)

A bare-bones operational node needs to store the address, two public keys, and version bytes of other nodes in the network. It must also store its own two key pairs, its address, the user key pair, the shared secret of the network(and any other secure groups, and the names of groups it belongs to), and its own actions and properties. Ideally, it would also contain the next hop to other nodes.

Properties - readonly (or no-read) information specific to the node.

- MUST have a name, type, value, and meta (null if no meta)
- E.g. temperature, color, open (meaning: 'is open'), locked, direction, etc.
- Property names starting with an underscore ( ` _ ` ) are private and never exposed in the public node structure. It serves as means to have private and persistent variables saved to local storage without implementing a custom means of storage. It can also be used to create a custom getter to add more logic.
- Required properties #wip
- ?later allow specific grants as readability by user #later #todo #wip

Actions - operations specific to a node, runs a function, or does something. Can also be used as setters for properties.

- MUST have a `name` (for calling it), a `return` type (null if void).
- MAY have "action parameters". Action parameters must have a descriptive `name`, `type`, and the standard `meta`
- Example names: `setTemperature, turnOn, setColor`
- Required Actions:  
A node MUST have the following actions to perform their respective function -- like a standard library for system/network. These actions are not publicly exposed in the node's structure to the network, it is assumed that the node as them. The names are prefixed with an `X`(? #wip) to denote the speciality and avoid name conflicts. #wip
  - `^ping($nonce:i:n)` - responds with ACK and nonce value (may want to also include node's time) #wip
  - `^setTime($sec:i:n)` - unix time seconds of 'setting' node, it is up to the receiver node to half the ping-pong time of itself to the 'setting' node.
    - 1. Node receives a valid(i.e. signed) setTime() action request from 'setter'(a user) and stores it temporarily.
    - 2. Node pings 'setter' to determine latency and divides this value by two. (This can be done several time to get an average if desired.)
    - 3. Node subtracts the calculated travel time from the temporary variable and sets its clock the that time.
  - `^groupAlter($name:s:n, $add:b:n)` - "group alter" request MUST be signed by a user. The name of the group is included. The second parameter `add` is true to add a node to the group, false if removing it. `add==false` also works for removing secure groups, but not adding. These groups are prefixed with a `*` _after_ creation, thus not included in the name parameter.
  - `^secureGroupAdd($name:s:n, $symmetricKey:z:n)` - "secure group add" request signed by a user whose parameters are the name of the group and the symmetric key associated with it. If being created, the user generates the symmetric key, and sets a name -- it makes no difference to the receiving node. If the group name is already known by the node, the key is replaced as it likely had to be regenerated to revoke access to another node. These groups are prefixed with a `#` _after_ creation for use in broadcasts.
  - `^setNetworkSetting($key:s:n, $value:z:n)` - sets/creates the key for a network setting (of acceptable keys) #maybe
    - Assuming the broadcast had a valid user signature, and the key is valid (see bellow), the nodes sets the value.
    - Network Setting Keys -- all optional #maybe #wip
      - `nick` - a user set alias for the network
      - `TZD` -- time zone designator (`Z` (UTC) or `+hh:mm` or `-hh:mm`) #maybe
  - `^setAnnonceOnChange($propName:s:n, $to:z:n, $yes:b:n)` - given the name of the property, this tells a node to announce a property when its value changes. Useful for things like temperature. (May remove this, and leave up to node implementation) #maybe
  - `^beingNetRevoked()` - called out of courtesy of revoker when network key is being changed and the node is not to be included; acts as a gesture to the node to 'reset' its network settings and be available for discovery.
  - `^factoryReset()` -- will only run if user signature is valid, resets the node to the manufacture's or developers discretion.
  - Possible additions: `addUser(key);` signed by a current user to add other users.
  - Considering an `SOS` type thing for announcements that nodes can use to request help in something to be used in extreme cases. #later #maybe

Node Info (Node attributes?, info?, XInfo?) - a dictionary of (mostly optional) values -- working on better name

- Required
    - `addr` - generated from the node's verifying (public signing) key - how the node is identified on the network
    - `kVerify` - bytes (base64?#maybe) of the node's verifying key
    - `kPublic` - public key (base64?#maybe) used for the KDF for decrypting node to node payloads.
    - `routing` - list/graph of nodes and/or connections for routing and spreading of routing. #wip
    - `netTime` - unix time according to the network consensus and/or user setting #wip
    - `v` - string of version of protocol being used (`"x.x"`)
    - `capabilities ` - list of strings of radios/capabilities (www,ip,wifi,bt,ir,rf,3g,zigbee,zwave,ethernet) - must at least have something #later #wip
- Optional
    - `groups` - list of group names the node is a part of. (This includes secure groups _names_ too), assumed empty if not presnet
    - `nick` - user set string as a nickname/alias for the node -- ('alias' more clear?)
    - `internetCapable`  - (bool) if a node has the ability to relay messages from other nodes to internet; assumes false
    - `defaultANNC` - the default group an announcement is broadcast too. Assumes '`*`' (all) is not specified.
    - `zone` - user set string as identifier of location. Forward slash convention (`/`) used to denote containment. (i.e. "home/bedroom")
    - `latlon` - list of 2 (or 3 for altitude) floats of location that can be set by user or device with gps. -- a node may restrict user setting of this property if it has its own means of determining location.
    - `creatorInfo` - a dict for a developer/manufacturer/company/person to place their own info such as build, name, product details, and etc. No restriction on keys.
    - `kind` - list of type of device. i.e. `["switch", "sensor"]` from lamp to stove -- like a mime type almost (thinking of creating a thing like a mime type but for devices) #maybe
    - `keepscache` - bool, for saying wether or not this node keeps a cache of all properties of all nodes in network #maybe
    - `barebones` - bool, true for low powered sensors and stuff that mainly provide data (via ANNC) that don't do much else #maybe
    - `defaultAction` - name of the action that best represents the node's functionality (for use in user interfaces) #maybe
    - `defaultProp` - name of the property that best represents the node (for use in user interfaces) #maybe
    - `implements` - list of strings, each pre-determined string being associated with actions and/or properties that it conforms to (think: light,lock,phone,etc.) #maybe
    - `UIOrder` - list of property and action names in preferred order of displaying in a client's UI, client implementation recommend. #later #maybe
    - `triggers` - dictionary of property names (and `Xtime` #wip) whose value is an array of "trigger dictionaries". #later

### Meta

'`meta`' is a dictionary with specific keys all being optional for use in properties and action-parameters.

Allowed keys (full list a work in progress)

- `desc` - description string of arbitrary length (ideally brief < 255 chars) providing a human understandable description.
- `min` - minimum inclusive (for number or length of string)
- `max` - max inclusive (for number or length of string)
- `placehold` - can act as filler text in user facing form
- `unit` - string from list of protocol understood units
- `lastChange` -- time of last change to property
- `setter` - name of the setter action (if exists) for interface building and UX, if requesting an actual setter action, a node MAY also request the property with the 'setter' meta to get the result of the action.
- `mimetype` - the mime type pf the data (string or bytes). Useful examples include `image/svg` and `text/csv`
- `falseName` - the display name if the boolean value is false (e.g. on==true then "on" if on==false then "off")
- `dontCache` - (assumed false) if true: recommendation to not change the value of the property (e.g for motion detection trigger; possibly) #maybe
- `range` - formatted "min..max" inclusive (i.e. `"range":"1..10"`) #maybe
- `signed` - if false, can't be negative, assumes true; may implement with types instead #maybe
- `emoji` - emoji char(s) representing thing as an icon (this is another way to deal with icons) #maybe
- `icon_kind`? - pre-know/set categories of things with icons (i.e. light_switch, dish_washer, etc.), could be used for different states for thing too. #later #maybe
- `icon`? - using binary base 64 data(may just say to use unicode and emojis in name/desc? - not image itself) #maybe

Example (as json)

- `{"min":15, "max":45, "unit":"c", "emoji":"\U0001F321"}`

### Routing #wip

Normal Routing #wip

- Routing is a work in progress. Main two ideas:  
    - waterfall routing where every node just rebroadcasts it is not to them (causes loops which must be ignored in implementation via the nonce id.) -- groups would probably use this anyhow.  
    - direct preempted route joined by `>` in the destination part of the broadcast structure.
- May periodically ANNC changes in single-hop advertisements containing basic cost information to neighbors.

- A general concept:  
Alice needs to send (only) to Bob. Cant connect directly, must go though Carlos. Alice looks in routing table and sees that Carlos is the next hop to Bob. Alice looks how to get to Carlos, sees his transceivers MAC address. Alice transmits to that MAC. Carlos received the packet, sees that it is addressed to bob, and does the same process to transmit it to bob.

- Note: the last step before transmission is appending the `\x05` byte to the raw data, marking it as a normal in-network broadcast.
- ["Dynamic Source Routing"](https://en.wikipedia.org/wiki/Dynamic_Source_Routing) and even better [Scalable Source Routing](https://en.wikipedia.org/wiki/Scalable_Source_Routing) looks interesting for inspiration for actual routing.

Node Discovery - "Marco Polo"

- Nodes should not "scream about themselves" when without a network. They should only ever respond to a 'Marco' for unfulfilled nodes. In the walk through below `alice` and `bob` represent a node's addresses. Note: the last step before transmission is appending the `\x05` byte to the raw data marking it as a discovery broadcast.
- 1. User (Alice) makes an unencrypted (but signed) `MARCO` broadcast containing their public address and keys in search for nodes.
  - `\x00\x01|MARCO|alice|[alice verify_key]|[alice public_key]`

- 2. Interested nodes (without a network key), respond with a signed `POLO` broadcast directly to Alice containing the public-key encrypted with the user's public key payload: the entire node's data structure.
  - `\x00\x01|POLO|alice|[bob public_key]|node<...addr:'bob'...>`
- 3. If the user decides to accept the node into the network, a final `ACPT` (#maybe `JOIN` instead) is signed, and sent containing the discoverer's public key and the bynar list encoded payload: the network's symmetric key, the new node's node structure signed by the user, and the user's (Alice's) node's data structure for network bootstrapping. The new node should also verify the address and keys against this node structure. In addition to sending, the user node MUST add the new node to its _known nodes_(i.e. cached nodes). <small>No other steps are taken for denying a node, simply don't accept it. A node must only respond once to a single `MARCO`</small>
  - `\x00\x01|ACPT|bob|[alice public key]|l[network key][node<alice...>][user signed new node struct bytes];`
- 4. Once the new node receives the `ACPT`, it can then introduce(acquaint) itself to the network's nodes by transmitting a network-level encrypted and signed `AQUA` broadcast (inherently to all nodes) containing its node structure signed by the user that it received in the `ACPT`. This allows the other nodes to verify is entry intro the network beyond ownership of the network key.
  - `\x00\x01|ANNC|*|bob|node<...>`
- Should anything go wrong during the Marco-Polo-Accept process (such as bad signature or some processing error), a new node that wishes to be added to the network SHOULD send an unencrypted error message for receiving by the user.  
Three categories of errors which follow "`DER-`" are `SIG`: bad signature; `PRSE`: issue parsing/decrypting; `MSG`: generic issue with the node.  
The payload is a bynar encoded string and always present (even if empty).  
`\x00\x01|DER-(SIG, PRSE, MSG)|[payload message]`

"On the fly" routing for physically moving nodes without a network #maybe #stretch

### Address, Key Generation and Encryption Specification #todo #wip

Symmetric key encryption used for network level and secure group level encryption use the ChaCha20 cipher stream algorithm. It uses a 32 byte private key and 8 byte nonce.

For my python prototype, I am using [PyNaCl](https://pynacl.readthedocs.io/en/latest/) (libsodium bindings) PublicBox and SigningKey for the shared key derivation for node to node payloads, and for signing every broadcast.

To generate a node's address: the verify key is generated from the signing key. The verify key is then sha256'ed twice, base64'd (url-safe; `'-_'` instead of `'+/'`). While this entire string may be used as the address, for most cases the first 7 bytes of this string is recommended for use. Collisions are still extremely unlikely. It only needs to be computed once for a node, thus can be stored.   
Pseudo code: `base64_urlsafe_encode(sha256raw(sha256raw(verify_key)))[:7]`

[Micro ECC](https://github.com/kmackay/micro-ecc) for micro controllers. Dedicated chip preferred for small systems. #later

### Network - the concept of a "network"

Networks are the primary setup for this system. A network is setup by a user. Things that are user set are signed by the user's key (separate from the key of the node used by the user -- e.g. computer/phone):

- A node joins a network when it gets the symmetric key for network-level communication via encryption.
- To revoke a node, a new key must be redistributed (may make this so each node has a separate "access key" to the network based on a key or hash or hash function depending on feasibility)
- Allows a user to connect a phone/computer to the network via a "relay node" for commination and data gathering with the networked nodes (i.e. in physical presence or over an internet connected node)

#### Users

A user is simply additional encryption and signing key pairs. These are used to add nodes to the network, and perform network-level actions (such as setting the time and adding groups)

There should be nothing stopping any two nodes from "talking" to each other whether in or out of a network (and even routing through each other), but a node will need the proper permissions depending on what is being communicated and what the node dev/user allows public/private.

#### Starting a network.

Starting a network is as simple as generating dual key pairs (encrypting and signing) for a User, generating a symmetric key for the network, and adding other node's via "Marco Polo" discovery.

Because network symmetric keys are generated by the user (likely on a more powerful machine than an 8 bit micro controller), they can be more complex in their generation as more competing power is available. The length however should still be acceptable for any node.

A node can only be a part of one network at a time


network-network communication #maybe #stretch

### Units (removable for an MVP)

Use SI units when applicable unless an imperial unit can not be converted

The following are to be included as part of protocol standard -- most representations are simply the SI shorthand #wip

- Celsius - `c`
- Meter - `m`
- Date - as [valid W3C NOTE-datetime](http://www.w3.org/TR/NOTE-datetime) - `datetime`
- UnixTime - `nixtime` [s.i.c]
- Color - represented as hex string "#rrggbb[aa]". Valid: "#00FFFF", "#222222AA" - `color`
  - may allow for 'rgb' short hand "#ccc", no real reason not to
  - A color enum like how CSS does it with a several main colors that can be used in replacement of the hex string (if not # then enum) #later #maybe
- Kilometer - `Km`
- Kilogram - `Kg`
- Meters/Second - `m/s`
- Degree - `deg`
- Radian - `rad`
- Percentage - `percent` - assumes 0 to 100 range using smallest int
- Newton - `N`
- Volt - `V`
- Amperage - `A`
- Watt - `W`
- Joule - `J`
- Hertz - `Hz`
- Decibel
- Pascal

maybe respect `K`, `m` as prefixes (kilo- and mili-)? -- may just use scientific notation with current units #later #maybe

### Thing Ideas
- Garage doors
- Thermostats/air conditioners
- Locks
- generic sensors
- fans
- window shades
- home security devices
- sprinklers
- door bells
- outlets
- humidifiers
- fausets
- cars
- AVs

### Think abouts/keep in mind

"passive" node info key meaning may only send data and may not always receive or forward (useful for things like the Amazon dash button)

#### Examples of good (and recommended) names for action/property common tasks #maybe #wip

`^setState(state:bool)` - sets the state to on (true) or off (false)

`on:bool` - if the device is on or not

`^dimToPercent(level:uint:percent, time:uint:seconds=0)`

`brightness:uint:percent`

`^setColor(hex:string:color)` - sets the color of the device output based on the color hex string

`color:string:color` - color of device output has hex color

`^setTemperature(temp:unit:c)`

`temperature` - the temperature in celsius

`^isPresent()->bool` - for a device that understands user proximity #maybe #wip

`locked:bool` device's output is locked/unlocked (usefully for electronic locks or doors)

`open:bool` - if device io is open/closed

`batteryLevel` - for devices with a battery

#### Mesh: From an HN comment:  
MQTT suffers from not having a real RPC system. Eventually with pub/sub you're going to end up with a "request 10" that is copied in replies, and at that point you've just invented a bad RFC system.  

Better to use one that was designed from the start for RFC (and that also supports streaming/push/pubsub as you'll want that too). I recommend gRPC (if your IoT think is beefy enough  
to support HTTPZ), or something lighter like CapnProto's RPC.

#### A "templating" thing that allows devs to more easily write the encoding with actions and properties to then be "compiled".

Something like this, almost yaml-like  
```  
node:  
  prop: 'on':string = true  
    meta: {}  
  prop: ...  
  action: 'setState':null  
    param: state:bool  
```
