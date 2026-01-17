import base64

print("Print your hex here")
text = input().strip()

hex_text = int(text,16)
binary_text = bin(hex_text)[2:]


while len(binary_text) %6 != 0:
    binary_text = '0' + binary_text


print(binary_text)


binaryList = []

for i in range(0,len(binary_text),6):
    chunk = binary_text[i:i+6]
    binaryList.append(chunk)

if len(binaryList[-1])<6:
    binaryList[-1] = binaryList[-1].ljust(6,'0') 

print(binaryList)


decList = []

for item in binaryList:
    decValue = 0
    for count, char in enumerate(reversed(item)):
        decValue += int(char) * (2 ** count)
    decList.append(decValue)

print(decList)

full_binary = ''.join(binaryList)
byte_data = int(full_binary,2).to_bytes((len(full_binary)+7)//8,byteorder='big')

base64_bytes = base64.b64encode(byte_data)
base64_string = base64_bytes.decode('ascii')

print(f"Hex '{text}' to Base64: {base64_string}")