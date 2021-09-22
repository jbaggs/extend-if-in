extend-if-in
==========

The `Zeek Intelligence Framework <https://docs.zeek.org/en/current/frameworks/intel.html>`_ allows notices to be raised for an indicator found in any location, or restricting notices 
for an indicator to a single location, by setting it in the "meta.if_in" field of the zeek intel file. The scripts in this repo allow setting additional locations for notices to be raised for an intel indicator. As configured, these scripts will add notices for DNS::IN_REQUEST to the Intel::DOMAIN indicator type for `doh intel <https://github.com/jbaggs/doh-intel>`_.

