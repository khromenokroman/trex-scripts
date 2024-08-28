from trex.astf.api import *
import argparse
 
 
class Prof1():
    def __init__(self):
        pass
 
    def get_profile(self, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)),
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)
 
        args = parser.parse_args(tunables)
        # ip generator
        ip_gen_c1 = ASTFIPGenDist(ip_range=["10.1.0.0", "10.1.0.255"], distribution="seq")
        ip_gen_s1 = ASTFIPGenDist(ip_range=["10.2.0.0", "10.2.255.255"], distribution="seq")
        ip_gen_c2 = ASTFIPGenDist(ip_range=["10.3.0.0", "10.3.0.255"], distribution="seq")
        ip_gen_s2 = ASTFIPGenDist(ip_range=["10.4.0.0", "10.4.255.255"], distribution="seq")
        ip_gen_c3 = ASTFIPGenDist(ip_range=["10.5.0.0", "10.5.0.255"], distribution="seq")
        ip_gen_s3 = ASTFIPGenDist(ip_range=["10.6.0.0", "10.6.255.255"], distribution="seq")
        ip_gen_c4 = ASTFIPGenDist(ip_range=["10.7.0.0", "10.7.0.255"], distribution="seq")
        ip_gen_s4 = ASTFIPGenDist(ip_range=["10.8.0.0", "10.8.255.255"], distribution="seq")
 
        ip_gen1 = ASTFIPGen(glob=ASTFIPGenGlobal(ip_offset="1.0.0.0"),
                            dist_client=ip_gen_c1,
                            dist_server=ip_gen_s1)
        ip_gen2 = ASTFIPGen(glob=ASTFIPGenGlobal(ip_offset="1.0.0.0"),
                            dist_client=ip_gen_c2,
                            dist_server=ip_gen_s2)
        ip_gen3 = ASTFIPGen(glob=ASTFIPGenGlobal(ip_offset="1.0.0.0"),
                            dist_client=ip_gen_c3,
                            dist_server=ip_gen_s3)
        ip_gen4 = ASTFIPGen(glob=ASTFIPGenGlobal(ip_offset="1.0.0.0"),
                            dist_client=ip_gen_c4,
                            dist_server=ip_gen_s4)
 
        return ASTFProfile(default_ip_gen=ip_gen1,
                           cap_list=[
                               ASTFCapInfo(file="/home/user/trex/scripts/avl/delay_10_http_browsing_0.pcap",
                                           ip_gen=ip_gen1, port=80, cps=100),
                               ASTFCapInfo(file="/home/user/trex/scripts/avl/delay_10_http_browsing_0.pcap",
                                           ip_gen=ip_gen2, port=81, cps=100),
                               ASTFCapInfo(file="/home/user/trex/scripts/avl/delay_10_http_browsing_0.pcap",
                                           ip_gen=ip_gen3, port=82, cps=100),
                               ASTFCapInfo(file="/home/user/trex/scripts/avl/delay_10_http_browsing_0.pcap",
                                           ip_gen=ip_gen4, port=83, cps=100)
                           ])
 
 
def register():
    return Prof1()
