'''
Created on Jun 5, 2011

@author: gr00vy
'''

from idaapi import simplecustviewer_t

class AssertionViewer(simplecustviewer_t):
    def __init__(self):
        simplecustviewer_t.Create(self, "Assertion View")
        self.AddLine("HAHAHHAH")
        self.AddLine("HAHAHHAH")
def main():
    view = AssertionViewer()
    view.Show()

main()