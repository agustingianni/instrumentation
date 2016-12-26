'''
Created on Mar 12, 2012

@author: gr00vy
'''

class AddressResolver:
    """
    Given a list of loaded images (probably coming form the trace)
    the AddressResolver will be in charge doing resolution of addresses.
    
    For instance, if we want to export all the information of a trace
    to IDA Pro and the base of the binary is different (which is very 
    likely due to ASLR on most OS's) we need to fix each one of the 
    addresses we get from the trace. To do the fix we need to provide
    the getAddress  method with the new base address of the binary.
    """
    def __init__(self, loaded_images = []):
        self.loaded_images = loaded_images
        self.last_image = None

    def loaded_image(self, image):
        """
        Add a new loaded image. The image contains information about
        where it has been loaded and its size.
        """
        self.loaded_images.append(image)
    
    def isValidAddress(self, address):
        """
        Checks if the given address is valid (ie. it falls into one of the loaded images).
        """
        return self.get_image(address) != None
    
    def get_rva(self, address):
        return address - self.get_image(address).lo_addr
    
    def get_image(self, address):
        """
        Get the backing image of this address
        """
        # Do a bit of caching
        if self.last_image and self.last_image.contains(address):
            return self.last_image
        
        # if it was not cached, traverse all of the loaded images
        for image in self.loaded_images:
            if image.contains(address):
                self.last_image = image
                return image
            
        return None
    
    def getAddress(self, ins_addr, image_base, image_name = ""):
        """
        Get the address of 'ins_addr' with respect to the image 'image_name' 
        relative to the base 'image_base'.
        """
        for image in self.loaded_images:
            if (image_name == "" or image.name == image_name) and image.contains(ins_addr):
                return (image_base + image.get_offset(ins_addr), True)
            
        return (ins_addr, False)
