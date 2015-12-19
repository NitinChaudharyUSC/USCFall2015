/*
 * Server side implementation APIs and data strucures
 * Author: nchaudha@usc.edu
 */
#ifndef  _SERVER_H_
#define _SERVER_H_

#define MAX_SERVER_NAME 32
#define SERVER_NAME "nunki.usc.edu"
#define payload_size 128

enum servers {
	serverA,
	serverB,
	serverC,
	serverD,
	MAX_SERVER
};

const char server_names[][MAX_SERVER_NAME] = {
	[serverA] = "serverA",
	[serverB] = "serverB",
	[serverC] = "serverC",
	[serverD] = "serverD",
};

const char server_config_files[][MAX_SERVER_NAME] = {
	[serverA] = "serverA.txt",
	[serverB] = "serverB.txt",
	[serverC] = "serverC.txt",
	[serverD] = "serverD.txt",
};

const char static_udp_port[][6] = {
	[serverA] = "21525",
	[serverB] = "22525",
	[serverC] = "23525",
	[serverD] = "24525",
};

struct server_link {
	unsigned int server_id;
	unsigned int linkcost;
};

struct server_descriptor {
	unsigned int server_id;
	const char *server_config_file;
	struct server_link links[MAX_SERVER];
	unsigned int link_count;
};

static struct server_descriptor servers[MAX_SERVER] = {
	{serverA, server_config_files[serverA],{{0,0}}, 0},
	{serverB, server_config_files[serverB],{{0,0}}, 0},
	{serverC, server_config_files[serverC],{{0,0}}, 0},
	{serverD, server_config_files[serverD],{{0,0}}, 0},
};

#define pr_debug(fmt, ...) \
	            do { if (DEBUG) fprintf(stderr, fmt, __VA_ARGS__); } while(0)

static int readServerConfigFile(struct server_descriptor *server);
static inline const char * map_serverid_to_name(int server_id);
static inline int map_servername_to_id(char *str);
static void initiate_server_processes(unsigned int server_id, const char *str);
static int readServerConfigFile(struct server_descriptor *server);
static int create_UDP_server(struct server_descriptor *server);
static int send_message_TCP(struct server_descriptor *server);
static int prepare_message(char *buf, struct server_descriptor *server,
			unsigned int buf_sz);
static int get_own_ip(char *buf);
static inline int check_repeated_entry(struct server_descriptor
			*server, unsigned int id, unsigned int *index);
static inline void *get_in_addr(struct sockaddr *sa);
static inline unsigned short int get_socket_number(
		struct sockaddr *sa);

#endif /* SERVER_H */ 
