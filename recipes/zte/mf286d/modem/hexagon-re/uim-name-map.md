# UIM Extended Message Name-Map (EXP-042)

| ID | REQ shape | RESP shape | Identity |
|---|---|---|---|
| 0x00 | csz1/ml0 | csz8/ml7 | ? |
| 0x1e | csz1/ml0 | csz8/ml8204 | ? |
| 0x1f | csz76/ml5 | csz6224/ml115 | ? |
| 0x20 | csz76/ml75 | csz6224/ml5785 | ? |
| 0x21 | csz76/ml72 | csz4384/ml4380 | ? |
| 0x22 | csz4172/ml4163 | csz16/ml19 | ? |
| 0x23 | csz332/ml322 | csz16/ml19 | ? |
| 0x24 | csz72/ml64 | csz1108/ml1079 | ? |
| 0x25 | csz76/ml62 | csz284/ml283 | ? |
| 0x26 | csz336/ml320 | csz284/ml283 | ? |
| 0x27 | csz84/ml70 | csz284/ml283 | ? |
| 0x28 | csz84/ml70 | csz284/ml283 | ? |
| 0x29 | csz36/ml26 | csz12/ml12 | ? |
| 0x2a | csz2048/ml1344 | csz8/ml7 | ? |
| 0x2b | csz44/ml41 | csz8/ml7 | Refresh-related (7B resp) |
| 0x2c | csz44/ml41 | csz8/ml7 | ? |
| 0x2d | csz40/ml37 | csz2080/ml1359 | Get File Attr ext (1359B) |
| 0x2e | csz4/ml7 | csz16/ml14 | ? |
| 0x2f | csz2/ml4 | csz9112/ml5477 | ? |
| 0x30 | csz4/ml4 | csz8/ml7 | ? |
| 0x31 | csz12/ml15 | csz8/ml7 | ? |
| 0x32 | csz-/ml- | csz-/ml- | ? |
| 0x33 | csz-/ml- | csz-/ml- | ? |
| 0x34 | csz1080/ml1074 | csz1048/ml1048 | profile-info get (session+filter, 1024B payload) |
| 0x35 | csz44/ml41 | csz8/ml7 | profile state set/enable (41B req=slot+iccid, 7B ack) |
| 0x36 | csz48/ml48 | csz44/ml31 | profile disable (48B req) |
| 0x37 | csz44/ml45 | csz8/ml7 | profile delete (45B req) |
| 0x38 | csz52/ml42 | csz8/ml7 | ? |
| 0x39 | csz40/ml37 | csz272/ml266 | ??? (37B req, 266B resp) |
| 0x3a | csz8/ml7 | csz3880/ml1530 | ? |
| 0x3b | csz1056/ml1052 | csz1052/ml1045 | ? |
| 0x3c | csz24/ml20 | csz16/ml11 | ??? (20B, 11B resp) |
| 0x3d | csz1040/ml1034 | csz1564/ml1554 | get config/nickname (1034B resp) |
| 0x3e | csz-/ml- | csz-/ml- | ? |
| 0x3f | csz56/ml52 | csz276/ml275 | ? |
| 0x40 | csz304/ml300 | csz8/ml7 | ? |
| 0x41 | csz4/ml4 | csz52/ml48 | GET CARD ATR (live-confirmed) |
| 0x42 | csz52/ml44 | csz276/ml275 | ? |
| 0x43 | csz-/ml- | csz-/ml- | ? |
| 0x44 | csz44/ml45 | csz8/ml7 | ? |
| 0x45 | csz64/ml60 | csz8/ml7 | card memory reset? (60B) |
| 0x46 | csz8/ml11 | csz8/ml7 | ? |
| 0x47 | csz1/ml0 | csz404/ml315 | Get Slot Status ext (live) |
| 0x48 | csz-/ml- | csz-/ml- | ? |
| 0x49 | csz-/ml- | csz-/ml- | ? |
| 0x4a | csz-/ml- | csz-/ml- | ? |
| 0x4b | csz1/ml0 | csz20/ml21 | eUICC version/SVN (live) |
| 0x4c | csz18484/ml11711 | csz12/ml12 | ? |
| 0x4d | csz196/ml191 | csz148/ml150 | ? |
| 0x4e | csz4/ml4 | csz8/ml7 | ? |
| 0x4f | csz12/ml15 | csz272/ml271 | euicc-info query ({slot,u8,u32}, u8[255] varlen resp!) |
| 0x50 | csz-/ml- | csz-/ml- | ? |
| 0x51 | csz56/ml51 | csz276/ml271 | nickname op (51B) |
| 0x52 | csz4/ml4 | csz92/ml86 | get default addr (4B req) |
| 0x53 | csz12/ml15 | csz8/ml7 | set server address ({slot,u32,u8}) |
| 0x54 | csz4/ml4 | csz8/ml7 | user consent (4B req) |
| 0x55 | csz-/ml- | csz-/ml- | ? |
| 0x56 | csz1028/ml1029 | csz1040/ml1036 | ? |
| 0x57 | csz1028/ml1029 | csz1040/ml1036 | ? |
| 0x58 | csz1028/ml1029 | csz1040/ml1036 | ? |
| 0x59 | csz1028/ml1029 | csz1040/ml1036 | ? |
| 0x5a | csz696/ml685 | csz1860/ml1855 | ADD PROFILE (685B req = activation code, 1855B resp!) |
| 0x5b | csz44/ml41 | csz1300/ml1295 | get profiles info (1295B) |
| 0x5c | csz336/ml327 | csz276/ml277 | ??? (327B) |
| 0x5d | csz1040/ml1036 | csz1700/ml1690 | ABSENT |
| 0x5e | csz20/ml14 | csz8/ml7 | ABSENT |
| 0x5f | csz-/ml- | csz-/ml- | ? |
| 0x60 | csz-/ml- | csz-/ml- | ? |
| 0x61 | csz44/ml44 | csz8/ml7 | enable profile (44B req = slot+iccid, ACK resp) |
| 0x62 | csz24/ml24 | csz8/ml7 | disable profile (24B req, 24B resp) |
| 0x63 | csz1/ml0 | csz36/ml31 | eUICC state/phase (live) |
| 0x64 | csz8/ml11 | csz1280/ml1254 | delete profile (11B) |
| 0x65 | csz4/ml4 | csz32/ml27 | GET EID (binary 16B) |
| 0x66 | csz8/ml11 | csz8/ml7 | get EID variant (11B) |
| 0x67 | csz16/ml15 | csz8/ml7 | REGISTER ({slot, u64 token/mask}) |
| 0x68 | csz532/ml530 | csz8/ml7 | set nickname (530B req, ACK) |
| 0x69 | csz80/ml79 | csz8/ml7 | ??? (80B req, ACK resp) |
| 0x6a | csz716/ml568 | csz656/ml555 | ??? (568B req, 555B resp) |
| 0x6b | csz12/ml15 | csz8/ml7 | CRASHED MODEM w/ bare slot — profile switch? ({slot,u8,u32opt}) |
| 0x6c | csz8/ml8 | csz8/ml7 | user consent (8B) |
| 0x6d | csz268/ml263 | csz532/ml525 | ??? (263B, 525B) |
| 0x6e | csz40/ml20 | csz8/ml7 | ? |
| 0x6f | csz72/ml67 | csz4136/ml4134 | ? |
| 0x70 | csz-/ml- | csz-/ml- | ? |
