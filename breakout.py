def break_and_clean(text):
            broken = text.split(" ")
            cleaned = "-".join(broken).replace("*","").replace("\n","").replace(",","").replace("#","")
            return cleaned

def create_file(filename, text):
    with open(filename, "w") as file:
         file.write(text)
         return   
    
def test_header(line):
    count_hashtags = 0
    range = 0
    for each in line:
        if each == "#":
            count_hashtags = count_hashtags + 1
        range = range + 1
        if range > 4:
             break
    if count_hashtags == 2:
        return "h2"
    if count_hashtags == 1:
        return "h1"
    else:
        return False

        
with open("./Resources.md", "r") as file:
    keeping_count = 0
    text_to_add = ""
    filename = ""
    lines = file.readlines()
    for each in lines:
        if test_header(each) == "h2":
            print(filename)
            print(text_to_add)
            if filename != "":
                 create_file(filename, text_to_add)
                # continue
            cleaned = break_and_clean(each)
            keeping_count = keeping_count+1
            if keeping_count < 10:
                filename = "0" + str(keeping_count) + cleaned + ".md"
            else:
                filename = str(keeping_count) + "-" + cleaned + ".md"
            text_to_add = "" + filename + "\n"
        else:
            text_to_add = text_to_add + each


