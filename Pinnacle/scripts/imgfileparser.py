from collections import namedtuple

EV_LOAD = 1
EV_UNLOAD = 2

class ImgEvent:
    
    def __init__(self, ev_type, load_id, img_path, low_addr, high_addr):
        self.ev_type = ev_type
        self.load_id = load_id
        self.img_path = img_path
        self.low_addr = low_addr
        self.high_addr = high_addr

    def __str__(self):
        return "(0x%x) %s 0x%x - 0x%x" % (self.load_id, self.img_path,
                                     self.low_addr, self.high_addr)

class ImgMemoryMap:

    def __init__(self):
        self.mm = []
        
    def load(self, img_event):
        idx = 0
        while idx < len(self.mm):
            if img_event.low_addr > self.mm[idx].high_addr:
                idx += 1
                continue
            else:
                if not img_event.high_addr < self.mm[idx].low_addr:
                    err = "Loading image %s collides with %s" % \
                           (str(img_event), str(self.mm[idx]))
                    raise Exception(err)
                else:
                    break
            idx += 1
            
        self.mm.insert(idx, img_event)

    def unload(self, img_event):
        if len(self.mm) == 0:
            err = "Tried to unload %s but memory map is empty" % str(img_event)
            raise Exception(err)
        
        idx = 0
        found = False
        while idx < len(self.mm):
            if img_event.low_addr == self.mm[idx].low_addr:
                self.mm.pop(idx)
                found = True
                break
            idx += 1

        if not found:
            err = "Failed to unload %s" % str(img_event)
            raise Exception(err)

    def get_image(self, addr):
        for img in self.mm:
            if addr >= img.low_addr and addr <= img.high_addr:
                return img
        return None
    
class ImageFileParser:

    def __init__(self, img_file):
        self.img_file = img_file
        self.img_load_data = []
        
        fd = open(img_file, 'r')
        for line in fd:
            line = line.strip().split(";")
            ev_type = int(line[0], 16)
            if ev_type == 1:
                ev_type = EV_LOAD
            else:
                ev_type = EV_UNLOAD
                
            load_id = int(line[1], 16)
            img_path = line[2]
            low_addr = int(line[3], 16)
            high_addr = int(line[4], 16)

            event = ImgEvent(ev_type, load_id, img_path, low_addr, high_addr)
            self.img_load_data.append(event)
            
        fd.close()

        self.curr_state_marker = 0
        self.img_memory_map = ImgMemoryMap()
        
    def get_addr_img(self, addr, img_load_id):
        if img_load_id != self.curr_state_marker:
            self._update_to_state(img_load_id)

        return self._get_addr_image(addr)

    def _update_to_state(self, img_load_id):
        while img_load_id >= self.curr_state_marker:
            self._process_img_event(
                self.img_load_data[self.curr_state_marker])
            self.curr_state_marker += 1

    def _process_img_event(self, event):
        if event.ev_type == EV_LOAD:
            self.img_memory_map.load(event)
        else:
            self.img_memory_map.unload(event)
        
    def _get_addr_image(self, addr):
        return self.img_memory_map.get_image(addr)
        
                                      
        
