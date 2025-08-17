from bit.format import verify_sig
import binascii

address = binascii.unhexlify("0266173fb4dff0ade10625d42b6ab95a53314f09863a28094d30b06d6a140f4d67")
message = "poll_001|Yes"
signature = binascii.unhexlify("HwlR0BUBLsdDJ0qkmdBHlNRLupEHzzaeBxD/r+kB/mbpckqJVmOsrq1NqP30QgKACnGd1EJj3wqwj1JamSnHZSw=")

print("Valid?", verify_sig(address, signature, message))