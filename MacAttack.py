import io
import struct
import sha1I

bytesPerChunk = 64

initialMessage = "No one has completed lab 2 so give them all a 0"
newMessage = "P.S. Except for Alex, go ahead and give him the full points."
keyByteLength = 16

oldMAC = (
            0xf4b645e8,
            0x9faaec2f,
            0xf8e443c5,
            0x95009c16,
            0xdbdfba4b
        )

initialMessageBytes = bytearray(initialMessage, "ascii")
newMessageBytes = bytearray(newMessage, "ascii")
keyFiller = bytearray(keyByteLength)

arg = io.BytesIO(keyFiller + initialMessageBytes)

# bytes object with 0 <= len < 64 used to store the end of the message
# if the message length is not congruent to 64
_unprocessed = b''
# Length in bytes of all data that has been processed so far
_message_byte_length = 0

chunk = arg.read(64)

totalChunks = 0

# Read the data, 64 bytes at a time
while len(chunk) == 64:
    totalChunks += 1
    _message_byte_length += 64
    chunk = arg.read(64)

_unprocessed = chunk

message = _unprocessed

message_byte_length = _message_byte_length + len(message)

# append the bit '1' to the message
message += b'\x80'
initialMessageBytes += b'\x80'
# append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
# is congruent to 56 (mod 64)
message += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)
initialMessageBytes += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)

# append length of message (before pre-processing), in bits, as 64-bit big-endian integer
message_bit_length = message_byte_length * 8
message += struct.pack(b'>Q', message_bit_length)
initialMessageBytes += struct.pack(b'>Q', message_bit_length)

# Process the final chunk
# At this point, the length of the message is either 64 or 128 bytes.
totalChunks += 1
if len(message) == 128:
    totalChunks += 1

oldMessageByteSize = totalChunks * bytesPerChunk

newMAC = sha1I.sha1(newMessageBytes, oldMAC, oldMessageByteSize)

completeNewMessage = initialMessageBytes + newMessageBytes

print("New message is:")
print(completeNewMessage.decode(encoding='ascii', errors='ignore'))
print("New message hex is:")
print(completeNewMessage.hex())
print("New MAC is:")
print(newMAC)
