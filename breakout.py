def break_and_clean(text):
            broken = text.split(" ")
            cleaned = "-".join(broken[1:]).replace("*","").replace("\n","").replace(",","")
            return cleaned

def create_file(filename, text):
    with open(filename, "w") as file:
         file.write(text)
         return   

with open("./Resources.md", "r") as file:
    keeping_count = 0
    text_to_add = ""
    filename = ""
    lines = file.readlines()
    for each in lines:
        if each[0] == "#":
            print(filename)
            print(text_to_add)
            if filename is not "":
                 create_file(filename, text_to_add)
            cleaned = break_and_clean(each)
            keeping_count = keeping_count+1
            if keeping_count < 10:
                filename = "0" + str(keeping_count) + cleaned + ".md"
            else:
                filename = str(keeping_count) + "-" + cleaned + ".md"
            text_to_add = ""
        else:
            text_to_add = text_to_add + each


