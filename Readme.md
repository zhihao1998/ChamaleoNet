# Recorded information for each packet
- header info (as readeable formats)
- complete payload / complete packet (as raw bytes)
- incoming timestamp

# TCP handling
Every time there is a new packet,
* if is SYN
    * check if there is an existing flow (already a SYN packet stored)
        * if so, update the original one with the new packet
        * else, find a new memory slot and store it
* if is SYNACK/RST
    * check if there is an corresponding SYN (direction matters)
        * if so, free the memory (TODO: keep it for next possible response packets)
        * else
    * update the active host table