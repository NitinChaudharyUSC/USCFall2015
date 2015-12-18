/*
 * Client side implementation APIs
 * Author: Nitin Chaudhary <nchaudha@usc.edu>
 */
#ifndef __CLIENT_USC__
#define __CLIENT_USC__

/* data structures */

/* APIs */

#define pr_debug(fmt, ...) \
	            do { if (DEBUG) fprintf(stderr, fmt, __VA_ARGS__); } while(0)

#define CLIENT_TCP_PORT "25525"
#define BACKLOG 5

pthread_mutex_t lock;
static unsigned int srvr_input;
int server_adj_matrix[MAX_SERVER][MAX_SERVER];
struct child_data {
	char *ipstr;
	char *cipstr;
	unsigned short int inport;
	int new_fd;
};

static inline int map_servername_to_id(char *str);
static inline const char * map_serverid_to_name(int server_id);
static unsigned int prepare_message_client(char *buf, unsigned int buf_sz);
static int parse_message(char *buf);
static void check_n_print_ip(struct sockaddr *sa,  char *str);
static int client_udp_send(unsigned int server_id, char * buf, unsigned int buf_sz);
void *do_child_process(void *args);
static int client_tcp_server(void);
static int get_own_ip(char *);

#endif
