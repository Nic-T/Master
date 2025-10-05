
allowedBinaryCharacters = ["0","1"]

print("Binary to ASCII calculator")
print("Please input your text in Binary")
text = input()


binaryLength = 7
decSum = 0
decList = []
for char in text:
        if (char not in allowedBinaryCharacters):
            print(f"The character you have entered is not a 1 or a 0: {char}")
            break   
        else:
            decSum = decSum + int(char) * pow(2,binaryLength)
            binaryLength = binaryLength - 1
            if(binaryLength == -1):
                decList.append(decSum)
                decSum = 0
                binaryLength = 7
realText=""          
for item in decList:
     realText = realText + chr(item)
print(realText)

