# Wireshark dissector

This Wireshark dissector tries to parse Codesys V3 network packets.

To use it, copy the .lua file into `~/.local/lib/wireshark/plugins` and start
Wireshark.

You can check out the pcaps in `pcaps` where we added some example traffic that
the dissector should be able to parse.

What's not supported is any kind of traffic going over channels. Only the lower
protocol layers are dissected right now.
