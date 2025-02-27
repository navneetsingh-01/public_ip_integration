class FilterModule(object):
    def filters(self):
        return {
            'get_interfaces': self.get_interfaces,
            'get_info': self.get_info
        }

    def get_interfaces(self, data):
        interfaces = []
        for line in data:
            if line.count(".") == 3:
                line=line.split(" ")
                interfaces.append(line[0])
        return interfaces
    
    def get_info(self, data):
        info = {}
        for line in data:
            if 'ip address' in line:
                line=line.split(" ")
                network = line[-1]
                ip = network.split("/")[0]
                info['ip'] = ip
                info['network'] = network
        return info
      

