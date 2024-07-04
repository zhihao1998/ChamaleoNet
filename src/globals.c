#include "tsdn.h"

void InitGlobals(void)
{
    GLOBALS.Max_TCP_Packets = MAX_TCP_PACKETS;
    GLOBALS.Max_UDP_Pairs = MAX_UDP_PAIRS;
    GLOBALS.List_Search_Dept = LIST_SEARCH_DEPT;
    GLOBALS.Hash_Table_Size = HASH_TABLE_SIZE;
    GLOBALS.TCP_Idle_Time = TCP_IDLE_TIME;
}