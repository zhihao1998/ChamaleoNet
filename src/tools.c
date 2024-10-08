
#include "tsdn.h"

extern struct in_addr *internal_net_list;
extern int *internal_net_mask;
extern int tot_internal_nets;

/*
 * Time Calculation
 */

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

/* subtract the rhs from the lhs, return time_diff in us */
int tv_sub_2(struct timeval lhs, struct timeval rhs)
{
    return ((lhs.tv_sec - rhs.tv_sec) * US_PER_SEC + lhs.tv_usec - rhs.tv_usec);
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

/*
 * Check if the IP adx is included in the internal nets
 */

Bool internal_ip(struct in_addr adx)
{
    int i;

    // fprintf(fp_stdout, "Checking %s \n", inet_ntoa(adx));
    for (i = 0; i < tot_internal_nets; i++)
    {
        // fprintf(fp_stdout, " Against: %s \n",inet_ntoa(internal_net_list[i]));
        if ((adx.s_addr & internal_net_mask[i]) == internal_net_list[i].s_addr)
        {
            // fprintf(fp_stdout, "Internal: %s\n", inet_ntoa(adx));
            return 1;
        }
    }
    // fprintf(fp_stdout, "External: %s\n", inet_ntoa(adx));
    return 0;
}

int ParseNetFile(FILE *fp, char *qualifier, int max_entries,
                 struct in_addr *CLASS_net_list,
                 int *CLASS_net_mask,
                 int *tot_CLASS_nets)
{
    char *line, *ip_string, *mask_string, *err;
    int i, j, len;
    int is_ipv4;
    long int mask_bits;
    unsigned int full_local_mask;
    struct in_addr mask2;
    char s[INET6_ADDRSTRLEN];

    (*tot_CLASS_nets) = 0;
    i = 0; // File line
    j = 0; // Index for IPv4
    while (1)
    {
        line = readline(fp, 1, 1);
        if (!line)
            break;

        len = strlen(line);
        if (line[len - 1] == '\n')
            line[len - 1] = '\0';
        ip_string = line;

        if (j == max_entries)
        {
            fprintf(fp_stderr, "Maximum number of %s IPv4 hosts/networks (%d) exceeded\n", qualifier, max_entries);
            return 0;
        }

        is_ipv4 = 0;
        // single line format
        if (strchr(ip_string, '/'))
        {
            ip_string = strtok(ip_string, "/");
            mask_string = strtok(NULL, "/");

            if (!mask_string)
            {
                fprintf(fp_stderr, "Missing ip or network mask in %s config n.%d\n", qualifier, (i + 1));
                return 0;
            }

            // IPv4 Address
            if (!inet_pton(AF_INET, ip_string, &(CLASS_net_list[j])))
            {
                fprintf(fp_stderr, "Invalid ip address in %s config n.%d\n", qualifier, (i + 1));
                return 0;
            }
            is_ipv4 = 1;

            // network mask as a single number
            if (!strchr(mask_string, '.'))
            {
                err = NULL;
                mask_bits = strtol(mask_string, &err, 10);
                if (is_ipv4 == 1)
                {
                    if (*err || mask_bits < 0 || mask_bits > 32)
                    {
                        fprintf(fp_stderr, "Invalid network mask in %s config n.%d\n", qualifier, (i + 1));
                        return 0;
                    }
                    else if (mask_bits == 0)
                    {
                        fprintf(fp_stderr, "Warning: IPv4 mask set to 0 bits in %s config n.%d\n\tAny IPv4 address will be considered internal\n",
                                qualifier, (i + 1));
                        CLASS_net_list[j].s_addr = 0;
                    }

                    if (CLASS_net_list[j].s_addr == 0)
                        full_local_mask = 0;
                    else
                        full_local_mask = 0xffffffff << (32 - mask_bits);

                    sprintf(s, "%d.%d.%d.%d",
                            full_local_mask >> 24,
                            (full_local_mask >> 16) & 0x00ff,
                            (full_local_mask >> 8) & 0x0000ff,
                            full_local_mask & 0xff);
                    // inet_aton (s, &(CLASS_net_mask2[j]));
                    CLASS_net_mask[j] = inet_addr(s);
                    CLASS_net_list[j].s_addr &= CLASS_net_mask[j];
                }
            }
            // mask in dotted format
            else if (is_ipv4 == 1)
            {
                if (!inet_aton(mask_string, &mask2))
                {
                    fprintf(fp_stderr, "Invalid IPv4 network mask in %s config n.%d\n", qualifier, (i + 1));
                    return 0;
                }
                CLASS_net_mask[j] = inet_addr(mask_string);
                CLASS_net_list[j].s_addr &= CLASS_net_mask[j];
            }
        }
        // old format
        else
        {
            if (!inet_aton(ip_string, &(CLASS_net_list[j])))
            {
                fprintf(fp_stderr, "Invalid IPv4 address in %s config n.%d\n", qualifier, (i + 1));
                return 0;
            }

            mask_string = readline(fp, 1, 1);
            if (!mask_string)
            {
                fprintf(fp_stderr, "Missing IPv4 network mask in %s config n.%d\n", qualifier, (i + 1));
                return 0;
            }

            len = strlen(mask_string);
            if (mask_string[len - 1] == '\n')
                mask_string[len - 1] = '\0';
            if (!inet_aton(mask_string, &mask2))
            {
                fprintf(fp_stderr, "Invalid IPv4 network mask in %s config n.%d\n", qualifier, (i + 1));
                return 0;
            }
            CLASS_net_mask[j] = inet_addr(mask_string);
            CLASS_net_list[j].s_addr &= CLASS_net_mask[j];
            is_ipv4 = 1;
        }
        
        if (is_ipv4 == 1)
        {
            mask2.s_addr = CLASS_net_mask[j];
            printf("Adding: %s as %s ",
                    inet_ntoa(CLASS_net_list[j]), qualifier);
            printf("with mask %s (%u)\n",
                    inet_ntoa(mask2),
                    CLASS_net_mask[j]);
        }

        if (is_ipv4 == 1)
        {
            (*tot_CLASS_nets)++;
            j++;
        }
        i++;
    }
    return 1;
}

int LoadInternalNets(char *file)
{
    FILE *fp;
    int retval;

    fp = fopen(file, "r");
    if (!fp)
    {
        fprintf(fp_stderr, "Unable to open file '%s'\n", file);
        return 0;
    }

    retval = ParseNetFile(fp, "internal",
                          MAX_INTERNAL_HOSTS,
                          internal_net_list,
                          internal_net_mask,
                          &tot_internal_nets);
    fclose(fp);

    return retval;
}

/*
 * Initialization
 */

void InitGlobalArrays(void)
{
    static Bool initted = FALSE;

    if (initted)
        return;

    initted = TRUE;

    internal_net_list = (struct in_addr *)MallocZ(MAX_INTERNAL_HOSTS * sizeof(struct in_addr));
    internal_net_mask = (int *)MallocZ(MAX_INTERNAL_HOSTS * sizeof(int));
}

/*
 * File Operations
 */
char *readline(FILE *fp, int skip_comment, int skip_void_lines)
{
    static char *buf = NULL;
    static int buf_size = 0;
    static int next_pos = 0;
    char *tmp, curr_c;
    int comment_started = 0;

    if (buf == NULL)
    {
        buf = malloc(BUF_SIZE * sizeof(char));
        buf_size = BUF_SIZE;
        next_pos = 0;
    }

    buf[0] = '\0';
    next_pos = 0;
    while (1)
    {
        if (next_pos + 1 == buf_size)
        {
            buf_size += BUF_SIZE;
            tmp = malloc(buf_size * sizeof(char));
            strcpy(tmp, buf);
            free(buf);
            buf = tmp;
        }

        curr_c = fgetc(fp);
        if (feof(fp))
        {
            buf[next_pos] = '\0';
            break;
        }

        comment_started |= skip_comment && (curr_c == '#');
        if (!comment_started || curr_c == '\n')
        {
            buf[next_pos] = curr_c;
            buf[next_pos + 1] = '\0';
            next_pos++;
        }

        if (curr_c == '\n')
        {
            if (buf[0] == '\n' && skip_void_lines)
            {
                buf[0] = '\0';
                next_pos = 0;
                comment_started = 0;
                continue;
            }
            else
                break;
        }
    }

    if (buf[0] == '\0')
        return NULL;
    return buf;
}

/*
 * Packet sender.
 */
// int SendPkt(char *sendbuf, int tx_len)
// {
//     return 0;
// }

int SendPkt(char *sendbuf, int tx_len)
{
    int r = -1;

    // struct ifreq if_mac;
    struct ether_header *eh = (struct ether_header *)sendbuf;
    struct ip *pip = (struct ip *)(sendbuf + ETH_HLEN);

    /* Check if it's truncated. */
    if (ntohs(pip->ip_len) + ETH_HLEN > tx_len)
    {
        memcpy(sendbuf_padding, sendbuf, tx_len);
        if (sendto(sockfd, sendbuf_padding, ntohs(pip->ip_len) + ETH_HLEN, 0, (struct sockaddr *)&socket_address, sizeof(struct sockaddr_ll)) != -1)
        {
            return 0;
        }
    }
    else
    {
        if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr *)&socket_address, sizeof(struct sockaddr_ll)) != -1)
        {
            return 0;
        }
    }
    return r;
}

void get_date(char *nowtime)
{
    time_t rawtime;
    struct tm *ltime;
    time(&rawtime);
    ltime = localtime(&rawtime);
    strftime(nowtime, 20, "%Y-%m-%d %H:%M:%S", ltime);
}