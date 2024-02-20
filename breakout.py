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
    for each_letter in line:
        if each_letter == "#":
            count_hashtags = count_hashtags + 1
    if count_hashtags == 2:
        return 2
    elif count_hashtags == 1:
        return 1
    elif count_hashtags == 0:
        return 0

        
with open("./Resources.md", "r") as file:
    keeping_count = 0
    text_to_add = ""
    filename = ""
    lines = file.readlines()
    for each in lines:
        if test_header(each) == 2:
            print(filename)
            print(text_to_add)
            if filename != "":
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


