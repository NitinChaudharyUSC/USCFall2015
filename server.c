/*
 * server side implementation for the EE450 Lab project
 * author: nchaudha@usc.edu
 * Instructor: Ali Zahid 
 * Session# 5
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/wait.h>

#include "server.h"
#include "client.h"

#define DEBUG 0
/* utility functions to make life easy */
static inline int map_servername_to_id(char *str){
	int i;
	for(i=0; i<MAX_SERVER; i++) {
		if(strcmp(str, server_names[i]) == 0)
			break;
	}
	return i;
}

static inline const char * map_serverid_to_name(int server_id){
	return server_names[server_id];	
}


static inline unsigned short int get_port_number(
		struct sockaddr *sa) {
	if (sa->sa_family == AF_INET){
		/*IPv4*/
		return ntohs(((struct sockaddr_in *)sa)->sin_port);
	} else {
		/*IPv6*/
		return ntohs(((struct sockaddr_in6 *)sa)->sin6_port);
	
	}
}

static inline void *get_in_addr(struct sockaddr *sa) {
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

static inline int check_repeated_entry(struct server_descriptor
			*server, unsigned int id, unsigned int *index) {
	int i;
	for(i = 0; i<MAX_SERVER; i++) {
		if((server->links[i]).server_id > 0 &&
				(server->links[i]).server_id == id) {
			*index = i;
			return 1;
		}
	}
	return 0;
}

static int get_own_ip(char *buf){
	struct addrinfo hints, *res, *p;
	int status;
	char ipstr[INET6_ADDRSTRLEN];
	
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6 to force version
	hints.ai_socktype = SOCK_STREAM;

	if ((status = getaddrinfo(SERVER_NAME, NULL, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
		return 2;
	}

	for(p = res;p != NULL; p = p->ai_next) {
		void *addr;

		// get the pointer to the address itself,
		// different fields in IPv4 and IPv6:
		if (p->ai_family == AF_INET) { // IPv4
			struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
			addr = &(ipv4->sin_addr);
		} else { // IPv6
			struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
			addr = &(ipv6->sin6_addr);
		}

		// convert the IP to a string and print it:
		inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
	}

	freeaddrinfo(res); // free the linked list

	strncpy(buf, ipstr, INET6_ADDRSTRLEN);
}

/*
 * This function converts the adjacency matrix read by server from its
 * descriptor (an integer array) into string and stores it into buffer
 * passed to it and returns the number of bytes written in the buffer
 * Message Format: Sever_identfier(1Byte) |blankspace| server--cost pair
 */
static int prepare_message(char *buf, struct server_descriptor *server,
			unsigned int buf_sz) {
	int i;
	int numbytes = 0;
	/* append sender's identity first*/
	numbytes = sprintf(buf+numbytes,"%c",
			(map_serverid_to_name(server->server_id))[6]);

	for(i = 0; (i < server->link_count) ; i++) {
		numbytes += sprintf(buf+numbytes," %s %d",
				map_serverid_to_name(server->links[i].server_id),
				server->links[i].linkcost);
		if(numbytes >= buf_sz) {
			printf("Write Buffer Overflow!");
			break;
		}
	}
	buf[numbytes] = '\0';
	pr_debug("%s: i %d numbytes %d, strlen(buf): %d max_sz: %d\n",
			__func__,i, numbytes, strlen(buf), buf_sz);
	return numbytes+1;
}

/* End of Helper functions */

/*
 * This function is responsible for creating a TCP connection from
 * "server" to the client and send the connectivity information to
 * via TCP Packets in a reliable fashion and print logs on console
 * We use recommended API getaddrinfo() instead of gethostbyname()
 * This code is inspired by the references mentioned in the [Beej's
 * Guide to Network Programmming] and has been redesigned as per
 * the project requirements.
 * */
static int send_message_TCP(struct server_descriptor *server) {
	int sockfd, numbytes;
	char buf[payload_size];
	struct addrinfo hints, *servinfo, *p;
	int ret, msg_sz = 0;
	char ipstr[INET6_ADDRSTRLEN];
	char own_ipstr[INET6_ADDRSTRLEN];
	struct sockaddr my_info;
	unsigned short int myport;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if((ret = getaddrinfo(SERVER_NAME, CLIENT_TCP_PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
		return 1;
	}

	for(p = servinfo; p!= NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
					p->ai_protocol)) == -1) {
			perror("Server: socket() failed\n");
			continue;
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("Server: connect() failed\n");
			continue;
		}
		break;
	}

	if(p == NULL) {
		fprintf(stderr, "%s: failed to connect to client using TCP\n",
				map_serverid_to_name(server->server_id));
		return 2;
	}
	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
			ipstr, sizeof(ipstr));
	pr_debug("%s connecting to client %s\n",
			map_serverid_to_name(server->server_id), ipstr);

	freeaddrinfo(servinfo);

	msg_sz = prepare_message(buf, server, sizeof(buf));

	if (send(sockfd, buf, msg_sz - 1, 0) == -1)
		perror("server send() fail\n");
	/*message 3*/
	printf("The server %c finishes sending its neighbor information to the Client",
			(map_serverid_to_name(server->server_id)[6]));
	printf(" with TCP port number %s and IP address %s\n", CLIENT_TCP_PORT, ipstr);
	/*message 3*/
	get_own_ip(own_ipstr);

	ret = sizeof(my_info);
	if((getsockname(sockfd, &my_info, &ret)) == -1) {
		perror("getsockname() fail\n");
	}
	if(my_info.sa_family == AF_INET) {
		/*IPv4 Socket*/
		myport = ((struct sockaddr_in *)&my_info)->sin_port;
	} else {
		myport = ((struct sockaddr_in6 *)&my_info)->sin6_port;
	}
	printf("For this connection with the Client, the Server %c has TCP port number",
			(map_serverid_to_name(server->server_id)[6]));
	printf(" %d and IP address %s\n", myport, own_ipstr);
	
	close(sockfd);
	return 0;
}

/*
 * This function creates a UDP server for a given "server" ID and
 * waits on blocking call "recvfrom()" to till it recieves the 
 * UDP datagram from client with the topology information. The code
 * here follows the methodology mentioned in [Beej's Guide to Network
 * Programming] to create UDP Sockets to recieve the packets but has
 * been optimized and adapted to suit the project requirements.
 */
static int create_UDP_server(struct server_descriptor *server) {
	int sockfd;
	struct addrinfo hints, *servinfo, *p;
	int rv, buf_sz;
	int numbytes;
	char *c, *token;
	struct sockaddr_storage their_addr;
	socklen_t addr_len;
	char s[INET6_ADDRSTRLEN];
	char own_ipstr[INET6_ADDRSTRLEN];
	char buf[payload_size * 2];

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC; // set to AF_INET to force IPv4
	hints.ai_socktype = SOCK_DGRAM;

	if ((rv = getaddrinfo(SERVER_NAME, static_udp_port[server->server_id],
					&hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and bind to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("listener: socket");
			continue;
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("listener: bind");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "listener: failed to bind socket\n");
		return 2;
	}

	freeaddrinfo(servinfo);

	pr_debug("%s: waiting to recvfrom...\n",map_serverid_to_name(server->server_id));

	addr_len = sizeof(their_addr);
	if ((numbytes = recvfrom(sockfd, buf, (payload_size * 2) -1 , 0,
		(struct sockaddr *)&their_addr, &addr_len)) == -1) {
		perror("recvfrom");
		exit(1);
	}
	buf[numbytes] = '\0';
	pr_debug("%s: client packet is %d bytes long\n",
		map_serverid_to_name(server->server_id), numbytes);
	pr_debug("%s: recieved packet contains \"%s\"\n",
		map_serverid_to_name(server->server_id), buf);
	/*message 4*/
	printf("\nThe server %c has recieved the network topology from the Client",
		(map_serverid_to_name(server->server_id))[6]);
	printf(" with UDP Port Number %d and IP address %s as follows\n",
		get_port_number((struct sockaddr *)&their_addr),
		inet_ntop(their_addr.ss_family,
			get_in_addr((struct sockaddr *)&their_addr),
			s, sizeof s));
	printf("Edge\t\tCost\n");
	buf_sz = numbytes;
	numbytes = 0;
	c = (char *)malloc(sizeof(char) * buf_sz);
	if(c == NULL) {
		perror("Out of Memory!\n");
		return -ENOMEM;
	}
	memcpy(c, buf, sizeof(char) * buf_sz);
	token = strtok(c, " ");
	while(token != NULL){
		if(numbytes & 0x1)
			printf("\t\t%s\n",token);
		else
			printf("%s", token);

		token = strtok(NULL, " ");
		numbytes++;
	}
	get_own_ip(own_ipstr);
	printf("For this connection with the Client, the Server %c has UDP port number",
			(map_serverid_to_name(server->server_id)[6]));
	printf(" %s and IP address %s\n",static_udp_port[server->server_id], own_ipstr);

	close(sockfd);
}

/*
 * This function is responsible for reading the server Configuration
 * files as specified by <server_name>.txt and store the read data in
 * the data structures describing the server. It also checks for a
 * duplicate entry in the server configuration file and replaces the
 * one with new one.
 */
static int readServerConfigFile(struct server_descriptor *server) {
	FILE *fp;
	int count;
	unsigned int i, cost, id, index;
	char buf[MAX_SERVER_NAME];

	if (!server) {
		printf("Server Descriptor is NULL!\n");
		return -EINVAL;
	}
	memset(server->links, 0, sizeof(struct server_link) * MAX_SERVER);
	/*message 1*/
	printf("\nThe Server %c is up and running.\n",
				(map_serverid_to_name(server->server_id))[6]);

	/*open server configuration file*/
	fp = fopen(server->server_config_file, "r");
	if(feof(fp)) {
		printf("Empty server input file!\n");
		return -EINVAL;
	}
	if(ferror(fp)) {
		printf("Error while opening server configuration file\n");
		return -EINVAL;
	}
	
	id = count = 0;

	/*read (servername, cost) tuple, stopping on EOF or error:*/
	while(fscanf(fp, "%s %d", buf, &cost) != EOF) {
		id = map_servername_to_id(buf);
		pr_debug("server %d read %s(%d) %d\n",
					server->server_id, buf, id, cost);

		if (!check_repeated_entry(server, id, &index)){
			/*count non repeated entries only*/
			server->links[count].linkcost = cost;
			server->links[count].server_id = id;
			count++;
		 } else {
			pr_debug("%s: duplicate entries for server--cost pair\n",__func__);
			server->links[index].linkcost = cost;
			server->links[index].server_id = id;
		 }

	}
	/*close the file*/
	fclose(fp);

	server->link_count = count;
	/*message 2*/
	printf("The Server %c has the following neighbor information:\n",
			map_serverid_to_name(server->server_id)[6]);
	printf("Neighbor\tCost\n");
	for (i = 0; i < count; i++){
		printf("%s\t\t%d\n",
			map_serverid_to_name(server->links[i].server_id),
			server->links[i].linkcost);
	}
	return 0;
}

/*
 * This is the first function whill will called by any server process which
 * is forked. This first prepares the server to know its neighbour, send the
 * info to the client using TCP and then recieve information about whole of
 * the network using UDP datagrams from the Client.
 */
static void initiate_server_processes(unsigned int server_id, const char *str){

	/* read the server configuration files and store in
	 * the structure server_links array as (name, cost)
	 * tuples, it fills up server_descriptor array 
	 */
	int i;
	if (readServerConfigFile(servers[server_id])){
		perror("Server Configuration Read Fail\n");
		exit(1);
	}
#if DEBUG
	printf("%s Matrix\nNeighbor\tCost\n",
			map_serverid_to_name(server_id));

	for (i = 0; i < servers[server_id]->link_count; i++){
		printf("%d\t\t%d\n",
			servers[server_id]->links[i].server_id,
			servers[server_id]->links[i].linkcost);
	}
#endif
	/*get the TCP Message from the client*/
	send_message_TCP(servers[server_id]);

	/*get the UDP Message from the client*/
	create_UDP_server(servers[server_id]);
	
}

/*
 * The entry point for the execution of server, forks out MAX_SERVER
 * processes each representing a server
 */
int main( int argc, char *argv[])
{
	unsigned int i;
	pid_t pid;

	if (argc != 1) {
		fprintf(stderr,"usage: server\n");
		return 1;
	}

	for(i = 0; i < MAX_SERVER; i++){

		pid = fork();
		if(pid < 0) {
			printf("Forking for %s Process failed\n",
				map_serverid_to_name(servers[i]->server_id));
			exit(1);
		} else if (pid == 0) {
			pr_debug("Forking for %s Process success\n",
				map_serverid_to_name(servers[i]->server_id));
			initiate_server_processes(i, SERVER_NAME);
			exit(0);
		} else {
			sleep(4);
			pr_debug("\nParent pid: %d\n",(int)pid);
		}
	}
	return 0;
}
