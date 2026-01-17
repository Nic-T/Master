print("Provide a color HEX or RGB")
print("Type 1 for RGB and 2 for HEX")
choice = input()


colorList = []

hexColor = ""

hex16 = {"A": 10, "B": 11, "C": 12, "D":13, "E":14,"F":15}

match choice:
    case "1":
        print("Write the RGB Code like this: 255,255,255")

        color = input()
        color = color + ","
        allowedCharacters = ["0","1","2","3","4","5",","]
        colorFragment = ""
        for char in color:
            if(char not in allowedCharacters):
                print("This is not in the format i requested")
                break
            if(char == ','):
                colorList.append(int(colorFragment))
                colorFragment=""
            else:
                colorFragment = colorFragment + char
        for item in colorList:
            hexItem = hex(item)
            show = str(hexItem)[2:]
            print(show.upper())
            hexColor = hexColor + show.upper()

        print(f"Hex Color: #{hexColor}")
            
    case "2":
        print("Write the hex code with or without #")
        color = input()
        
        allowedCharacters = ["0","1","2","3","4","5","6","7","8","9","A","B","C","D","E","F","#"]
        if("#" in color[1:]):
            print("the format seems wrong")
        for char in color:
            if(char not in allowedCharacters):
                print(f"{char} is not allowed for this operation")
            elif(char=="#"):
                continue
            else:
                if(char in hex16):
                    hex16.get(char)
    case _:
        print("You have to choose between 1 and 2")