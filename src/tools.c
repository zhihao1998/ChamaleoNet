
#include "tsdn.h"

/* return elapsed time in microseconds */
/* (time2 - time1) */
double
elapsed(struct timeval time1, struct timeval time2)
{
    struct timeval etime;

    /*sanity check, some of the files have packets out of order */
    if (tv_lt(time2, time1))
    {
        return (0.0);
    }

    etime = time2;
    tv_sub(&etime, time1);

    return (time2double(etime));
}

/* subtract the rhs from the lhs, result in lhs */
void tv_sub(struct timeval *plhs, struct timeval rhs)
{
    if (plhs->tv_usec >= rhs.tv_usec)
    {
        plhs->tv_usec -= rhs.tv_usec;
    }
    else if (plhs->tv_usec < rhs.tv_usec)
    {
        plhs->tv_usec += US_PER_SEC - rhs.tv_usec;
        plhs->tv_sec -= 1;
    }
    plhs->tv_sec -= rhs.tv_sec;
}

/* add the RHS to the LHS, answer in *plhs */
void tv_add(struct timeval *plhs, struct timeval rhs)
{
    plhs->tv_sec += rhs.tv_sec;
    plhs->tv_usec += rhs.tv_usec;

    if (plhs->tv_usec >= US_PER_SEC)
    {
        plhs->tv_usec -= US_PER_SEC;
        plhs->tv_sec += 1;
    }
}

/* are the 2 times the same? */
Bool tv_same(struct timeval lhs, struct timeval rhs)
{
    return ((lhs.tv_sec == rhs.tv_sec) && (lhs.tv_usec == rhs.tv_usec));
}

/*  1: lhs >  rhs */
/*  0: lhs == rhs */
/* -1: lhs <  rhs */
int tv_cmp(struct timeval lhs, struct timeval rhs)
{
    if (lhs.tv_sec > rhs.tv_sec)
    {
        return (1);
    }

    if (lhs.tv_sec < rhs.tv_sec)
    {
        return (-1);
    }

    /* ... else, seconds are the same */
    if (lhs.tv_usec > rhs.tv_usec)
        return (1);
    else if (lhs.tv_usec == rhs.tv_usec)
        return (0);
    else
        return (-1);
}

// /*
//  * Check if the IP adx is included in the internal nets
//  */
Bool internal_ip(struct in_addr adx)
{
    return TRUE;
}

// Bool internal_ip(struct in_addr adx)
// {
//     int i;

//     // fprintf(fp_stdout, "Checking %s \n",inet_ntoa(adx));
//     for (i = 0; i < tot_internal_nets; i++)
//     {
//         // fprintf(fp_stdout, " Against: %s \n",inet_ntoa(internal_net_list[i]));
//         if ((adx.s_addr & internal_net_mask[i]) == internal_net_list[i].s_addr)
//         {
//             // fprintf(fp_stdout, "Internal: %s\n",inet_ntoa(adx));
//             return 1;
//         }
//     }
//     // fprintf(fp_stdout, "External: %s\n",inet_ntoa(adx));
//     return 0;
// }

// int ParseNetFile(FILE *fp, char *qualifier, int max_entries,
//                  struct in_addr *CLASS_net_list,
//                  struct in6_addr *CLASS_net_listv6,
//                  int *CLASS_net_mask,
//                  int *CLASS_net_mask_sizev6,
//                  int *tot_CLASS_nets,
//                  int *tot_CLASS_netsv6)
// {
//     char *line, *ip_string, *mask_string, *err;
//     int i, j, k, len;
//     int is_ipv4;
//     long int mask_bits;
//     unsigned int full_local_mask;
//     struct in_addr mask2;
//     char s[INET6_ADDRSTRLEN];

//     (*tot_CLASS_nets) = 0;
//     (*tot_CLASS_netsv6) = 0;
//     i = 0; // File line
//     j = 0; // Index for IPv4
//     k = 0; // Index for IPv6
//     while (1)
//     {
//         line = readline(fp, 1, 1);
//         if (!line)
//             break;

//         len = strlen(line);
//         if (line[len - 1] == '\n')
//             line[len - 1] = '\0';
//         ip_string = line;

//         if (j == max_entries)
//         {
//             fprintf(fp_stderr, "Maximum number of %s IPv4 hosts/networks (%d) exceeded\n", qualifier, max_entries);
//             return 0;
//         }

//         if (k == max_entries)
//         {
//             fprintf(fp_stderr, "Maximum number of %s IPv6 hosts/networks (%d) exceeded\n", qualifier, max_entries);
//             return 0;
//         }

//         is_ipv4 = 0;
//         // single line format
//         if (strchr(ip_string, '/'))
//         {
//             ip_string = strtok(ip_string, "/");
//             mask_string = strtok(NULL, "/");

//             if (!mask_string)
//             {
//                 fprintf(fp_stderr, "Missing ip or network mask in %s config n.%d\n", qualifier, (i + 1));
//                 return 0;
//             }

//             if (strchr(ip_string, ':'))
//             { // IPv6 Address
//                 if (!inet_pton(AF_INET6, ip_string, &(CLASS_net_listv6[k])))
//                 {
//                     fprintf(fp_stderr, "Invalid ip address in %s config n.%d\n", qualifier, (i + 1));
//                     return 0;
//                 }
//                 is_ipv4 = 0;
//             }
//             else
//             { // IPv4 Address
//                 if (!inet_pton(AF_INET, ip_string, &(CLASS_net_list[j])))
//                 {
//                     fprintf(fp_stderr, "Invalid ip address in %s config n.%d\n", qualifier, (i + 1));
//                     return 0;
//                 }
//                 is_ipv4 = 1;
//             }

//             // network mask as a single number
//             if (!strchr(mask_string, '.'))
//             {
//                 err = NULL;
//                 mask_bits = strtol(mask_string, &err, 10);
//                 if (is_ipv4 == 1)
//                 {
//                     if (*err || mask_bits < 0 || mask_bits > 32)
//                     {
//                         fprintf(fp_stderr, "Invalid network mask in %s config n.%d\n", qualifier, (i + 1));
//                         return 0;
//                     }
//                     else if (mask_bits == 0)
//                     {
//                         fprintf(fp_stderr, ANSI_BOLD "Warning:" ANSI_RESET " IPv4 mask set to 0 bits in %s config n.%d\n\tAny IPv4 address will be considered internal\n",
//                                 qualifier, (i + 1));
//                         CLASS_net_list[j].s_addr = 0;
//                     }

//                     if (CLASS_net_list[j].s_addr == 0)
//                         full_local_mask = 0;
//                     else
//                         full_local_mask = 0xffffffff << (32 - mask_bits);

//                     sprintf(s, "%d.%d.%d.%d",
//                             full_local_mask >> 24,
//                             (full_local_mask >> 16) & 0x00ff,
//                             (full_local_mask >> 8) & 0x0000ff,
//                             full_local_mask & 0xff);
//                     // inet_aton (s, &(CLASS_net_mask2[j]));
//                     CLASS_net_mask[j] = inet_addr(s);
//                     CLASS_net_list[j].s_addr &= CLASS_net_mask[j];
//                 }
//                 else
//                 {
//                     if (*err || mask_bits < 0 || mask_bits > 128)
//                     {
//                         fprintf(fp_stderr, "Invalid network mask in %s config n.%d\n", qualifier, (i + 1));
//                         return 0;
//                     }
//                     else if (mask_bits > 64 && mask_bits != 128)
//                     {
//                         fprintf(fp_stderr, ANSI_BOLD "Warning:" ANSI_RESET " IPv6 mask should not exceed 64 bits in %s config n.%d\n", qualifier, (i + 1));
//                         // mask_bits=64;
//                     }
//                     else if (mask_bits == 0)
//                     {
//                         fprintf(fp_stderr, ANSI_BOLD "Warning:" ANSI_RESET " IPv6 mask set to 0 bits in %s config n.%d\n\tAny IPv6 address will be considered internal\n",
//                                 qualifier, (i + 1));
//                     }

//                     CLASS_net_mask_sizev6[k] = mask_bits;
//                 }
//             }
//             // mask in dotted format
//             else if (is_ipv4 == 1)
//             {
//                 if (!inet_aton(mask_string, &mask2))
//                 {
//                     fprintf(fp_stderr, "Invalid IPv4 network mask in %s config n.%d\n", qualifier, (i + 1));
//                     return 0;
//                 }
//                 CLASS_net_mask[j] = inet_addr(mask_string);
//                 CLASS_net_list[j].s_addr &= CLASS_net_mask[j];
//             }
//             else
//             {
//                 fprintf(fp_stderr, "Invalid IPv6 network mask in %s config n.%d\n", qualifier, (i + 1));
//                 return 0;
//             }
//         }
//         // old format
//         else
//         {
//             if (!inet_aton(ip_string, &(CLASS_net_list[j])))
//             {
//                 fprintf(fp_stderr, "Invalid IPv4 address in %s config n.%d\n", qualifier, (i + 1));
//                 return 0;
//             }

//             mask_string = readline(fp, 1, 1);
//             if (!mask_string)
//             {
//                 fprintf(fp_stderr, "Missing IPv4 network mask in %s config n.%d\n", qualifier, (i + 1));
//                 return 0;
//             }

//             len = strlen(mask_string);
//             if (mask_string[len - 1] == '\n')
//                 mask_string[len - 1] = '\0';
//             if (!inet_aton(mask_string, &mask2))
//             {
//                 fprintf(fp_stderr, "Invalid IPv4 network mask in %s config n.%d\n", qualifier, (i + 1));
//                 return 0;
//             }
//             CLASS_net_mask[j] = inet_addr(mask_string);
//             CLASS_net_list[j].s_addr &= CLASS_net_mask[j];
//             is_ipv4 = 1;
//         }
//         if (debug)
//         {
//             if (is_ipv4 == 1)
//             {
//                 mask2.s_addr = CLASS_net_mask[j];
//                 fprintf(fp_stdout, "Adding: %s as %s ",
//                         inet_ntoa(CLASS_net_list[j]), qualifier);
//                 fprintf(fp_stdout, "with mask %s (%u)\n",
//                         inet_ntoa(mask2),
//                         CLASS_net_mask[j]);
//             }
//             else
//             {
//                 inet_ntop(AF_INET6, &(CLASS_net_listv6[k]), s, INET6_ADDRSTRLEN);
//                 fprintf(fp_stdout, "Adding: %s as %s ", s, qualifier);
//                 fprintf(fp_stdout, "with mask %u\n",
//                         CLASS_net_mask_sizev6[k]);
//             }
//         }

//         if (is_ipv4 == 1)
//         {
//             (*tot_CLASS_nets)++;
//             j++;
//         }
//         else
//         {
//             (*tot_CLASS_netsv6)++;
//             k++;
//         }
//         i++;
//     }
//     return 1;
// }

// int LoadInternalNets(char *file)
// {
//     FILE *fp;
//     int retval;

//     fp = fopen(file, "r");
//     if (!fp)
//     {
//         fprintf(fp_stderr, "Unable to open file '%s'\n", file);
//         return 0;
//     }

//     retval = ParseNetFile(fp, "internal", GLOBALS.Max_Internal_Hosts,
//                           internal_net_list, internal_net_listv6,
//                           internal_net_mask, internal_net_maskv6,
//                           &tot_internal_nets, &tot_internal_netsv6);

//     //			     printf("Read %d IPv4 networks and %d IPv6 networks\n",tot_internal_nets,
//     //				    tot_internal_netsv6);
//     fclose(fp);

//     return retval;
// }