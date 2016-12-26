'''
Created on Jun 4, 2011

@author: gr00vy
'''

from logging import debug
import os
from subprocess import PIPE, Popen
import shlex

class InvalidPintoolPathException(Exception):
    pass

class AbstractPintool(object):
    def __init__(self, pin_dir, tool_path, tool_name):
        # pin will take a different name in windows, also the pintool will have a diferent extension
        if os.name == "posix":
            pinbin_name = "pin"
            tool_name = tool_name + ".so"
        else:
            pinbin_name = "pin.bat"
            tool_name = tool_name + ".dll"
                
        self.pindir_path = pin_dir
        self.pinbin_path = os.path.join(self.pindir_path, pinbin_name)

        # if we compile in 64 bit the tool dir will be different. try to make an educated guess
        self.tool_path = os.path.join(self.pindir_path, tool_path)
        
        if os.path.exists(os.path.join(self.tool_path, "obj-intel32")):
            self.toolbin_path = os.path.join(self.tool_path, "obj-intel32")
        elif os.path.exists(os.path.join(self.tool_path, "obj-intel64")):
            self.toolbin_path = os.path.join(self.tool_path, "obj-intel64")
        else:
            raise InvalidPintoolPathException("Cannot the path to pintools dir, did you compile?")

        self.tool_name = os.path.join(self.toolbin_path, tool_name)
        
        debug("Tool path :" + self.tool_path)
        debug("Tool bin  :" + self.tool_name)
        debug("Pin path  :" + self.pindir_path)
        debug("Pin bin   :" + self.pinbin_path)
        
    def run(self, command):
        command = "%s -t %s -- %s" % (self.pinbin_path, self.tool_name, command)
        command = " ".join(shlex.split(command))

        debug("Running command:")
        debug(command)

        return Popen(command, shell=True, stdout=PIPE, stderr=PIPE)