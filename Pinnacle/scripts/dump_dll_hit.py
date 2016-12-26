"""
Show a list of the DLLs that contained instructions from a hit trace

@author: sean@heelan.ie
"""

import operator
import sys
import os

from collections import namedtuple

from imgfileparser import ImageFileParser

Image = namedtuple("Image", ["name", "start", "end"])

USAGE = "%s img_load_file.out hit_file.out"

if len(sys.argv) != 3:
    print USAGE % sys.argv[0]
    exit(-1)
    
img_load_file = sys.argv[1]
hit_file = sys.argv[2]

if not os.access(img_load_file, os.R_OK):
    print "Cannot read %s" % img_load_file
    print USAGE % sys.argv[0]
    exit(-1)

if not os.access(hit_file, os.R_OK):
    print "Cannot read %s" % hit_file
    print USAGE % sys.argv[0]
    exit(-1)

ifp = ImageFileParser(img_load_file)

# Load the instruction hit data and find each instruction's image
hit_images = {}
unknown_cnt = 0
hit_fd = open(hit_file, 'r')
for line in hit_fd:
    spl_line = line.strip().split(";")
    img_load_id = int(spl_line[1], 16)
    addr = int(spl_line[2], 16)

    img = ifp.get_addr_img(addr, img_load_id)
    if img is None:
        unknown_cnt += 1
        continue
    
    if img.img_path in hit_images:
        hit_images[img.img_path] += 1
    else:
        hit_images[img.img_path] = 1
        
hit_fd.close()

s = sorted(hit_images.iteritems(), key=operator.itemgetter(1))
for key, val in s:
    print "%d %s" % (val, key)

print "%d instructions with unknown images" % unknown_cnt
