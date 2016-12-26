'''
Created on Jun 4, 2011

@author: gr00vy
'''
from AbstractPintool import AbstractPintool

import os

class PinnaclePintool(AbstractPintool):
    def __init__(self, pin_dir):
        AbstractPintool.__init__(self, pin_dir, os.path.join("source", "tools", "Pinacle"), "Pinnacle")