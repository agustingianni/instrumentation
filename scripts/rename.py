import os
import sys
import hashlib

input_dir = "/Users/anon/work/fuzzing/pfa/inputs"

for file_name in map(lambda x: os.path.join(input_dir, x), os.listdir(input_dir)):
    if file_name[0] == ".":
        continue
    
    fileName, fileExtension = os.path.splitext(file_name)
    fileDir = os.path.dirname(file_name)
    hash_ = hashlib.sha224(file(file_name).read()).hexdigest()
    new_file_name = os.path.join(fileDir, hash_ + fileExtension)
    os.rename(file_name, new_file_name)
