#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <sys/user.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "gdb-server.h"
#include "debuglib.h"

static pthread_mutex_t _mut,*c_mut=&_mut;
static int cont_stop;
static int client;

static const char hex[] = "0123456789abcdef";

int serve(/*naive_mips_t *sl,*/ st_state_t *st)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    unsigned int val = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&val, sizeof(val));

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(struct sockaddr_in));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(st->listen_port);

    if (bind(sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(sock, 5) < 0) {
        perror("listen");
        return 1;
    }

    printf("Listening at *:%d...\n", st->listen_port);

    client = accept(sock, NULL, NULL);
    //signal (SIGINT, SIG_DFL);
    if (client < 0) {
        perror("accept");
        return 1;
    }

    close(sock);

    // sl->halt();
    // sl->reset();
    /*init_code_breakpoints(sl);
    init_data_watchpoints(sl);*/

    printf("GDB connected.\n");

    /*
     * To allow resetting the chip from GDB it is required to
     * emulate attaching and detaching to target.
     */
    unsigned int attached = 1;

    while (1) {
        char* packet;

        int status = gdb_recv_packet(client, &packet);
        if (status < 0) {
            printf("cannot recv: %d\n", status);
    #ifdef __MINGW32__
            win32_close_socket(sock);
    #endif
            return 1;
        }

        printf("recv: %s\n", packet);

        char* reply = NULL;
        //reg regp;

        switch (packet[0]) {
        case 'q': {
            if (packet[1] == 'P' || packet[1] == 'C' || packet[1] == 'L') {
                reply = strdup("");
                break;
            }

            char *separator = strstr(packet, ":"), *params = "";
            if (separator == NULL) {
                separator = packet + strlen(packet);
            } else {
                params = separator + 1;
            }

            unsigned queryNameLength = (separator - &packet[1]);
            char* queryName = calloc(queryNameLength + 1, 1);
            strncpy(queryName, &packet[1], queryNameLength);

            printf("query: %s;%s\n", queryName, params);

            if (!strcmp(queryName, "Supported")) {
                // reply = strdup("PacketSize=3fff;qXfer:memory-map:read+;qXfer:features:read+");
                reply = strdup("PacketSize=1000"); // JFLFY2255
            } /*else if (!strcmp(queryName, "Xfer")) {
                char *type, *op, *__s_addr, *s_length;
                char *tok = params;
                char *annex __attribute__((unused));

                type     = strsep(&tok, ":");
                op       = strsep(&tok, ":");
                annex    = strsep(&tok, ":");
                __s_addr   = strsep(&tok, ",");
                s_length = tok;

                unsigned addr = strtoul(__s_addr, NULL, 16),
                         length = strtoul(s_length, NULL, 16);

                DLOG("Xfer: type:%s;op:%s;annex:%s;addr:%d;length:%d\n",
                     type, op, annex, addr, length);

                const char* data = NULL;

                if (!strcmp(type, "memory-map") && !strcmp(op, "read"))
                    data = current_memory_map;

                if (!strcmp(type, "features") && !strcmp(op, "read"))
                    data = target_description_mips;

                if (data) {
                    unsigned data_length = strlen(data);
                    if (addr + length > data_length)
                        length = data_length - addr;

                    if (length == 0) {
                        reply = strdup("l");
                    } else {
                        reply = calloc(length + 2, 1);
                        reply[0] = 'm';
                        strncpy(&reply[1], data, length);
                    }
                }
            } else if (!strncmp(queryName, "Rcmd,", 4)) {
                // Rcmd uses the wrong separator
                char *separator = strstr(packet, ","), *params = "";
                if (separator == NULL) {
                    separator = packet + strlen(packet);
                } else {
                    params = separator + 1;
                }


                if (!strncmp(params, "726573756d65", 12)) { // resume
                    DLOG("Rcmd: resume\n");
                    sl->run();

                    reply = strdup("OK");
                } else if (!strncmp(params, "68616c74", 8)) { //halt
                    reply = strdup("OK");

                    // sl->halt();

                    DLOG("Rcmd: halt\n");
                } else if (!strncmp(params, "6a7461675f7265736574", 20)) { //jtag_reset
                    reply = strdup("OK");

                    // stlink_jtag_reset(sl, 0);
                    // stlink_jtag_reset(sl, 1);
                    // sl->halt();

                    DLOG("Rcmd: jtag_reset\n");
                } else if (!strncmp(params, "7265736574", 10)) { //reset
                    reply = strdup("OK");

                    // sl->halt();
                    sl->reset();
                    init_code_breakpoints(sl);
                    init_data_watchpoints(sl);

                    DLOG("Rcmd: reset\n");
                } else {
                    DLOG("Rcmd: %s\n", params);
                }

            }
            free(queryName);*/

            if (reply == NULL)
                reply = strdup("");
            break;
        }

        case 'v': {
            char *params = NULL;
            char *cmdName = strtok_r(packet, ":;", &params);
            cmdName++; // vCommand -> Command
            if (!strcmp(cmdName, "Kill")) {
                attached = 0;
                reply = strdup("OK");
            }
            if (reply == NULL)
                reply = strdup("");
            break;
        }

        case 'c': {
            /*sl->run();

            cont_stop=0;
            pthread_t c_id0,c_id1;
            pthread_mutex_init(c_mut,NULL);
            pthread_create(&c_id0,NULL,wait_for_cc,(void*)(long)0);
            pthread_create(&c_id1,NULL,wait_for_cpu,(void*)(long)0);
            pthread_join(c_id0,NULL);
            pthread_join(c_id1,NULL);*/
            int wait_status = dbglib_continue(st->tracee_pid);
            if(wait_status == 0 || wait_status == -1) {
              reply = strdup("S09"); // killed
            }
            else {
              reply = strdup("S05"); //Stopped
            }
            break;
        }
        case 's': {            //sl->step();
          int wait_status = dbglib_single_step(st->tracee_pid);
          if(wait_status == 0) {
            reply = strdup("S09"); // killed
          }
          else {
            reply = strdup("S05"); //Stopped
          }
          break;
        }
        case '?':
            if (attached) {
                reply = strdup("S05"); // TRAP
            } else {
                // Stub shall reply OK if not attached.
                reply = strdup("OK");
            }
            break;

        case 'g': {
          procmsg("child now at EIP = 0x%08x\n", get_child_eip(st->tracee_pid));
            struct user_regs_struct _regs;
            struct user_regs_struct *regs = &_regs;
            dbglib_get_child_registers(regs, st->tracee_pid);
            int reg_count = dbglib_get_child_register_count(regs);
            reply = calloc(32 * 16 + 1, 1);
            char* pos = reply;
            for (int i = 0; i < reg_count; i++) {
              uint64_t val = 0;
              int bitwidth = 32;
              val = dbglib_get_child_register_by_gdb_index(regs, i, &bitwidth);
              sprintf(pos, "%08x", htonl((uint32_t)val));
              pos += 8;
            }
          }
            /*sprintf(&reply[32 * 8], "%08x", htonl(regp.status));
            sprintf(&reply[33 * 8], "%08x", htonl(regp.lo));
            sprintf(&reply[34 * 8], "%08x", htonl(regp.hi));
            sprintf(&reply[35 * 8], "%08x", htonl(regp.badvaddr));
            sprintf(&reply[36 * 8], "%08x", htonl(regp.cause));
            sprintf(&reply[37 * 8], "%08x", htonl(regp.pc));*/

            break;

        case 'p': {
          unsigned id = strtoul(&packet[1], NULL, 16);
          struct user_regs_struct _regs;
          struct user_regs_struct *regs = &_regs;
          dbglib_get_child_registers(regs, st->tracee_pid);
          int reg_count = dbglib_get_child_register_count(regs);
          uint64_t val = 0;
          int bitwidth = 32;
          if(id < reg_count) {
            val = dbglib_get_child_register_by_gdb_index(regs, id, &bitwidth);
          }
          reply = calloc(8 + 1, 1);
          sprintf(reply, "%08x", htonl((uint32_t)val));
          break;
        }

        case 'P': {
            char* s_reg = &packet[1];
            char* s_value = strstr(&packet[1], "=") + 1;

            unsigned long id   = strtoul(s_reg,   NULL, 16);
            unsigned long value = htonl(strtoul(s_value, NULL, 16));
            struct user_regs_struct _regs;
            struct user_regs_struct *regs = &_regs;
            dbglib_get_child_registers(regs, st->tracee_pid);
            int reg_count = dbglib_get_child_register_count(regs);
            if(id >= reg_count || id < 0) {
              reply = strdup("OK");
              break;
            }
            dbglib_set_child_register_by_gdb_index(regs, id, value);
            dbglib_set_child_registers(regs, st->tracee_pid);
            reply = strdup("OK");
            break;
        }

        case 'G':
            /*for (int i = 0; i < 32; i++) {
                char str[9] = {0};
                strncpy(str, &packet[1 + i * 8], 8);
                uint32_t reg = strtoul(str, NULL, 16);
                // stlink_write_reg(sl, ntohl(reg), i);
            }

            reply = strdup("OK");
            break;*/

        case 'm': {
            char* s_start = &packet[1];
            char* s_count = strstr(&packet[1], ",") + 1;

            uintptr_t start = strtoul(s_start, NULL, 16);
            unsigned count = strtoul(s_count, NULL, 16);

            uint8_t *memory = malloc(count);
            dump_process_memory(st->tracee_pid, start, start + count - 1, memory);

            /*if (start>=0xbe000000 && start<=0xbe000000+0x00800000){
                sl->read_mem32(start, count);

                reply = calloc(count * 2 + 1, 1);
                for (unsigned int i = 0; i < count; i++) {
                    reply[i * 2 + 0] = hex[sl->q_buf[i] >> 4];
                    reply[i * 2 + 1] = hex[sl->q_buf[i] & 0xf];
                }

                if(start%4==2){
                    for (unsigned int i = 0; i < (count+3)/4; i++) {
                        swap(&reply[i*8+0],&reply[i*8+4]);
                        swap(&reply[i*8+1],&reply[i*8+5]);
                        swap(&reply[i*8+2],&reply[i*8+6]);
                        swap(&reply[i*8+3],&reply[i*8+7]);
                    }
                }
            }
            else {
                unsigned adj_start = start % 4;
                unsigned count_rnd = (count + adj_start + 4 - 1) / 4 * 4;

                // DLOG("[m] start=%x count=%d\n", start - adj_start, count_rnd);
                sl->read_mem32(start - adj_start, count_rnd);

                reply = calloc(count * 2 + 1, 1);
                for (unsigned int i = 0; i < count; i++) {
                    reply[i * 2 + 0] = hex[sl->q_buf[i + adj_start] >> 4];
                    reply[i * 2 + 1] = hex[sl->q_buf[i + adj_start] & 0xf];
                }
            }*/
            reply = calloc(count * 2 + 1, 1);
            for (unsigned int i = 0; i < count; i++) {
                reply[i * 2 + 0] = hex[memory[i] >> 4];
                reply[i * 2 + 1] = hex[memory[i] & 0xF];
            }
            break;
        }

        case 'M': {
            char* s_start = &packet[1];
            char* s_count = strstr(&packet[1], ",") + 1;
            char* hexdata = strstr(packet, ":") + 1;

            uintptr_t start = strtoul(s_start, NULL, 16);
            uintptr_t count = strtoul(s_count, NULL, 16);
            char* binaryData = malloc(count);
            for(int i = 0; i < count; i++) {
              char temp[3] = {0};
              temp[0] = hexdata[i * 2];
              temp[1] = hexdata[i * 2 + 1];
              binaryData[i] = strtoul(temp, NULL, 16);
            }
            //if(start < 0x100000000LL)
              modify_process_memory(st->tracee_pid, start, start + count - 1, binaryData);
            free(binaryData);
            reply = strdup("OK");
            break;
        }

        case 'Z': {
            char *endptr;
            uintptr_t addr = strtoul(&packet[3], &endptr, 16);
            //mips_addr_t len  = strtoul(&endptr[1], NULL, 16);

            // if(packet[1]=='0')packet[1]='1';
            switch (packet[1]) {
              case '0': {
                //Software breakpoint.
                /*debug_breakpoint* bp = create_breakpoint(st->tracee_pid, addr);
                reply = strdup("OK");
                break;*/
              }
              case '1': // remove breakpoint
              case '2' : // remove write watchpoint
              case '3' : // remove read watchpoint
              case '4' : {// remove access watchpoint
                reply = strdup("");
                break;
            }

            default:
              reply = strdup("");
            }
            break;
        }
        case 'z': {
            char *endptr;
            uintptr_t addr = strtoul(&packet[3], &endptr, 16);
            //mips_addr_t len  = strtoul(&endptr[1], NULL, 16);

            // if(packet[1]=='0')packet[1]='1';
            switch (packet[1]) {
            case '0': // remove breakpoint
                reply = strdup("");
                break;
            case '1': // remove breakpoint
                reply = strdup("");
                //update_code_breakpoint(sl, addr, 0);
                reply = strdup("OK");
                break;

            case '2' : // remove write watchpoint
            case '3' : // remove read watchpoint
            case '4' : {// remove access watchpoint
              reply = strdup("");
            }

            default:
                reply = strdup("");
            }
            break;
        }

        case '!': {
            /*
             * Enter extended mode which allows restarting.
             * We do support that always.
             */

            /*
             * Also, set to persistent mode
             * to allow GDB disconnect.
             */
            /*st->persistent = 1;

            reply = strdup("OK");

            break;*/
        }

        case 'R': {
            /* Reset the core. */

            /*sl->reset();
            init_code_breakpoints(sl);
            init_data_watchpoints(sl);*/

            attached = 1;

            reply = strdup("OK");

            break;
        }

        default:
            reply = strdup("");
        }

        if (reply) {
            printf("send: %s\n", reply);

            int result = gdb_send_packet(client, reply);
            if (result != 0) {
                printf("cannot send: %d\n", result);
                free(reply);
                free(packet);
                return 1;
            }
            free(reply);
        }
        free(packet);
    }
    return 0;
}
