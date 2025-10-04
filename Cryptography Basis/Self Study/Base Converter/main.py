
bases=[["0","1","2","3","4","5","6","7","8","9","A","B","C","D","E","F"]
      ,["0","1","2","3","4","5","6","7","8","9","10","11","12","13","14","15"]
      ,["0000","0001","0010","0011","0100","0101","0110","0111","1000","1001","1010","1011","1100","1101","1110","1111"]
      ]

print(bases[2][1])

print("Enter a number in hex, decimal or binary")
number = input()
print("Specify the type of the number")
print("Options:\n 1 for HEX\n 2 for decimal \n 3 for binary")
numberType = input()
match numberType:

    case "1":
        sum = 0
        allowedCharacters = ["0","1","2","3","4","5","6","7","8","9","A","B","C","D","E","F"]
        convertedToDec = 0
        firstCharacter = number[:1]
        numberLength = len(number) - 1
        binaryString = ""
        if(firstCharacter == "0" and  len(number) >1 ):
            print("You can't put a 0 in front of a number")
        else:    
            for char in number:
                if(char not in allowedCharacters):
                    print(f"You have used a restricted character, {char} it not allowed")
                for baseChars in bases[0]:
                    if(char == baseChars):
                        hexIndex = bases[0].index(char)
                        convertedToDec = convertedToDec + hexIndex*pow(16,numberLength) 
                        numberLength-=1

                        binaryChar = bases[2][hexIndex]
                        binaryString = binaryString + binaryChar
            print(f"Hexadecimal: {number}")
            print(f"Decimal: {convertedToDec}")
            print(f"Binary: {binaryString}")
    case "2":
        allowedCharacters = ["0","1","2","3","4","5","6","7","8","9"]
        firstCharacter = number[:1]
        hexString=""
        binaryString=""
        originalNumber = number
        if(firstCharacter == "0" and  len(number) >1 ):
            print("You can't put a 0 in front of a number")
        else:    
            for char in number:
                if(char not in allowedCharacters):
                    print(f"You have used a restricted character, {char} it not allowed")
                while(int(number) != 0):
                    remainder = int(number)%16
                    hexChar = bases[0][remainder]
                    binaryChar = bases[2][remainder]
                    binaryString =binaryChar + binaryString  
                    hexString =hexChar + hexString
                    number = int(number)/16
            print(f"Hexadecimal: {hexString}")
            print(f"Decimal: {originalNumber}")
            print(f"Binary: {binaryString}")
    case "3":
        binaryString = number
        binaryBase = ""
        allowedCharacters = ["0","1"]
        hexString = ""
        count = 1
        decValue = 0
        numberLength = len(number) -1
        if(len(number) %4 !=0 ):
            print("You didn't format that quite right")
        else:
            for char in number:
                if(char not in allowedCharacters):
                    print(f"You have used a restricted character, {char} it not allowed")
                binaryBase = binaryBase+char
                
                if (count == 4):
                    hexChar = bases[0][bases[2].index(binaryBase)]
                    hexString =hexString + hexChar
                    count = 0
                    binaryBase=""                    
                count= count+1
                decValue = decValue + int(char) * pow(2, numberLength)
                numberLength = numberLength-1
            print(f"Hexadecimal: {hexString}")
            print(f"Decimal: {decValue}")
            print(f"Binary: {binaryString}")

    case _:
        print("You can only choose one of the three options")


