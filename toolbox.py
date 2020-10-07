#Random toolbox


### dump_functions : Function made to dump all functions of nrpc.py
def dump_functions(filename):
    f = open(filename, "r")
    line = f.readline()
    res = "{"
    i = 0
    while line:
        if ("def " in line):
            res += str(i)
            function_name = line.split("def ")[1].split("(")[0]
            res += ": [\"" + function_name + "\"," + "nrpc." + function_name + "]"
            res += ",\n"
            i += 1
        line = f.readline()
    print(res)
    f.close()

dump_functions("file.py")