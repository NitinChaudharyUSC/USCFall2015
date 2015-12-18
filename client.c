/*
 * Client side implementation for the EE450 Lab project
 * WARNING!!! Copying & redistribution this code in any 
 * form is a offense on the USC Academic Integrity code.
 * author: Nitin Chaudhary <nchaudha@usc.edu>
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
#include <signal.h>
#include <pthread.h>
#include <limits.h>
#include "server.h"
#include "client.h"

#define DEBUG 0


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
 * Generate the Minimum Spanning Tree(MST) for the network on basis
 * of the Network Adjacency Matrix which we obtained as per inputs
 * from the servers using Prim's Algorithm for MST
 */
int findMinKey(int * key, char *mstSet) {
	int i, index, minval;
	minval = INT_MAX;
	for(i = 0; i < MAX_SERVER; i++) {
		if(!mstSet[i] && key[i] < minval) {
			minval = key[i];
			index = i;
		}
	}
	return index;
}

void generate_MST(void){
	int i,j,iter, cost;
	char str[3];
	int mst[MAX_SERVER];	/*Stores constructed MST*/
	int key[MAX_SERVER];	/*Stores key values to pick a cut*/
	char mstSet[MAX_SERVER];/*Tracks edges not yet included in MST*/

	/*Initialize all the keys*/
	for(i = 0;i < MAX_SERVER;i++) {
		mstSet[i] = 0;
		key[i] = INT_MAX;
	}

	key[0] = 0;	/*Make sure the first node is picked up*/
	mst[0] = -1;	/*Add the root node unconditionally in MST*/
	str[2] = '\0';

	pr_debug("%s: Start\n",__func__);

	for(iter = 0; iter < MAX_SERVER-1; iter++) {
		/*find the node with minimum cost not yet include in MST*/
		i = findMinKey(key, mstSet);
		/*add node i to the MST set*/
		mstSet[i] = 1;
		/*Update the adjacent nodes cost*/
		for(j = 0; j <MAX_SERVER; j++) {
			if(server_adj_matrix[i][j] && !mstSet[j] &&
					server_adj_matrix[i][j] < key[j]) {
				mst[j] = i;
				key[j] = server_adj_matrix[i][j];
			}
		}	
	}

	cost = 0;
	for(i = 1 ;i < MAX_SERVER; i++) {
		cost += server_adj_matrix[i][mst[i]];
	}
	printf("\nThe Client has calculated a tree. The tree cost is %d\n", cost);
	printf("Edge\t\tCost\n");
	for(i = 1; i < MAX_SERVER; i++) {
		str[0] = 'A' + mst[i];
		str[1] = 'A' + i;
		printf("%s\t\t%d\n", str, server_adj_matrix[i][mst[i]]);
	}
	
}

/*
 * This function prepares the network topology message to be sent as
 * string with entities delimited by spaces. We send them as edges
 * followed by its cost. Note only need to send it above the diag-
 * onal of the Adjacency Matrix.
 */
static unsigned int prepare_message_client(char *buf, unsigned int buf_sz) {
	int i,j;
	unsigned int numbytes;
	char str[2];
	numbytes = 0;

	for(i = 0; i < MAX_SERVER; i++) {
		str[0] = 'A' + i;
		for(j = i; j < MAX_SERVER; j++) {
			if(server_adj_matrix[i][j]) {
				str[1] = 'A' + j;
				numbytes += sprintf(buf + numbytes, "%s %d ",
						str, server_adj_matrix[i][j]);
			}
			if(numbytes > buf_sz) {
				perror("Write Buffer Overflow!");
				break;
			} 
		}
	}
	/* Termiate the string*/
	buf[numbytes] = '\0';

	return numbytes + 1;
}


/*
 * This function parses the input string from server TCP messages and
 * fills up a array for client to represent connections for server
 * sending the information
 */
static int parse_message(char *buf) {
	/*buf[0] is the server id*/
	char srvr_id, *cptr;
	int i, id, cost, index;
	unsigned int flag = 0x00000000;
	
	index = -1;
	srvr_id = buf[0];

	for(i = 0; i < MAX_SERVER; i++) {
		if(srvr_id == (server_names[i])[6]) {
			index = i;
			break;
		}
	}

	if(index < 0) {
		perror("Error in data input, Server Not Found!");
		return -1;
	}

	/* 
	 * server_name & linkcosts are seperated by space
	 * parse the tokens as strings and converts the 
	 * strings to the integer representation
	 */
	cptr = strtok(buf + 1, " ");
	while(cptr != NULL) {
		if(!flag) {
			/*First value in tuple is Server Name*/
			id = map_servername_to_id(cptr);
		} else {
			/*Second value in tuple is link cost*/
			cost = atoi(cptr);
			/* We can update the data here*/
			/*printf("index %d id %d cost %d", index, id, cost);*/
			pthread_mutex_lock(&lock);
			server_adj_matrix[index][id] = cost;
			pthread_mutex_unlock(&lock);
		}
		flag = flag ^ 0xFFFFFFFF;
		cptr = strtok(NULL, " ");
	}
	return index;
}

/*
 * This function figures out which version of IP address is being used
 * and accordingly returns the human readable form of IP address using
 * inet_ntop() API
 */
static void check_n_print_ip(struct sockaddr *sa,  char *str){
	if(sa->sa_family == AF_INET) {
		/*IPv4*/
		inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr,
				str, INET_ADDRSTRLEN);
	} else {
		/*IPv6*/
		inet_ntop(AF_INET6, &((struct sockaddr_in6 *)sa)->sin6_addr,
				str, INET6_ADDRSTRLEN);
	}
}

/* 
 * This code is inspired from [Beej's Guide to Network Programming]
 * The code has been adapted as per the requirements of the project
 * To send/recieve UDP Message in the format defined for the project
 */
static int client_udp_send(unsigned int server_id, char * buf, unsigned int buf_sz) {
	int sockfd;
	struct addrinfo hints, *servinfo, *p;
	int rv;
	int numbytes;
	char *token, *c;
	char ipstr[INET6_ADDRSTRLEN];
	char own_ipstr[INET6_ADDRSTRLEN];

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	struct sockaddr my_info;
	unsigned short int myport;

	if ((rv = getaddrinfo(SERVER_NAME, static_udp_port[server_id], &hints, 
					&servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and make a socket
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("client: UDP socket() fail\n");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "client: failed to create UDP socket\n");
		return 2;
	}

	if ((numbytes = sendto(sockfd, buf, buf_sz, 0,
			 p->ai_addr, p->ai_addrlen)) == -1) {
		perror("client: UDP sendto()\n");
		exit(1);
	}

	freeaddrinfo(servinfo);

	check_n_print_ip(p->ai_addr, ipstr);
	/*message 3*/
	pr_debug("client: sent %d bytes data \"%s\" to server through UDP\n", numbytes, buf);
	printf("\nThe Client has sent the network topology to the network topology to the Server");
	printf(" %c with UDP port number %s and IP Address %s as follows:\n",
				(map_serverid_to_name(server_id)[6]),
				static_udp_port[server_id], ipstr);
	printf("Edge\t\tCost\n");
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

	rv = sizeof(my_info);
	if((getsockname(sockfd, &my_info, &rv)) == -1) {
		perror("getsockname() fail\n");
	}
	get_own_ip(own_ipstr);
	if(my_info.sa_family == AF_INET) {
		/*IPv4 Socket*/
		myport = ((struct sockaddr_in *)&my_info)->sin_port;
	} else {
		myport = ((struct sockaddr_in6 *)&my_info)->sin6_port;
	}

	printf("For this connection with the the Server %c, The client has UDP port number",
			(map_serverid_to_name(server_id)[6]));
	printf(" %d and IP address %s\n", myport, own_ipstr);
	
	
	close(sockfd);

	return 0;
}

void *do_child_process(void *args){ // this is the child process
        int new_fd;	
        int index,i,j;
        int numbytes = 0;
        char buf[payload_size];
	new_fd = ((struct child_data *)args)->new_fd;
        memset(buf,'\0',sizeof(char)*payload_size);

        if((numbytes = recv(new_fd, buf, payload_size-1, 0)) == -1) {
                perror("client faced recv() fail");
                exit(1);
        }

        buf[numbytes] = '\0';
	/*message 2*/
	printf("\nThe Client receives neighbor information from the Server %c", buf[0]);
	printf(" with TCP port number %d and IP address %s\n",
				((struct child_data *)args)->inport,
				((struct child_data *)args)->ipstr);

        pr_debug("client recieved \"%s\" from server, bytes size: %d\n", buf, numbytes);

        index = parse_message(buf);
        if(index <0) {
                perror("Message Parse Error!\n");
        }

        printf("The Server %c has the following neighbouring information\n",
                                (map_serverid_to_name(index)[6]));
        printf("Neighbor\tcost\n");
        for(i = 0; i < MAX_SERVER; i++) {
                if(server_adj_matrix[index][i]) {
                        printf("%s\t\t%d\n", map_serverid_to_name(i),
                                server_adj_matrix[index][i]);
                }
        }

        /*message 2*/
        printf("For this connection with Server %c The Client has TCP port number",
                                (map_serverid_to_name(index)[6]));
        printf(" %s and IP Address %s\n", CLIENT_TCP_PORT,
				((struct child_data *)args)->cipstr);
#if DEBUG 
        for(i = 0; i < MAX_SERVER; i++) {
                for(j = 0;j < MAX_SERVER; j++){
                        printf("%-4d ", server_adj_matrix[i][j]);
                }
                printf("\n");
        }
#endif
        close(new_fd);
	
	pthread_exit(NULL); 
}

/* 
 * This code is inspired from [Beej's Guide to Network Programming]
 * The code has been adapted as per the requirements of the project
 * To send/recieve TCP Messages in the format defined for the project
 * The function to create TCP type socket for the client, BUT! UNLIKE
 * the reference, we are using pthreads with mutexes instead of fork
 */
static int client_tcp_server(void){
	char yes = '1';
	unsigned short int incoming_port = 0;
	unsigned int size_sockaddr_storage;
	pthread_t thread[MAX_SERVER];
	int sockfd, new_fd; /* sockfd is parent socket, childs ger new_fd*/
	struct addrinfo hints, *p, *res;
	struct sockaddr_storage in_connect_addr; /*incoming connections address*/
	struct sockaddr *ptr = NULL;
	int id, exit_flag, ret = 0;
	char ipstr[INET6_ADDRSTRLEN];
	char client_ipstr[INET6_ADDRSTRLEN];
	struct child_data child_data;
	exit_flag = 0;
	
	pr_debug("%s Start\n",__func__);
	/* fill up the structure using getaddrinfo()*/
	memset(&hints, 0, sizeof(hints));
	/*hints.ai_flags = AI_PASSIVE;*//*let getaddrinfo() get & fill Host IP*/
	hints.ai_family = AF_UNSPEC;	/*don't care if its IPv6 or IPv4*/
	hints.ai_socktype = SOCK_STREAM;/*TCP Sockets*/

	if((ret = getaddrinfo(SERVER_NAME, CLIENT_TCP_PORT, &hints, &res))
									!= 0) {
		fprintf(stderr,"getaddrinfo: %s\n",gai_strerror(ret));
		return 1;
	}

	/* loop through all the results and connect to first one which we can!*/
	for(p = res; p != NULL; p = p->ai_next) {

		if((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("client socket() error\n");
			continue;
		}
		/*sucessfully got the client socket and make sure the ports are
		 * available for the bind() call*/
		if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
						sizeof(int)) == -1) {
			perror("client setsockopt() fail, ports acquired\n");
			exit(1);
		}
		/*bind the PORT to this sockfd (parent socket)*/
		if((bind(sockfd, p->ai_addr, p->ai_addrlen)) == -1) {
			close(sockfd);
			perror("client bind() failed\n");
			continue;
		}
		break;
	}

	freeaddrinfo(res);
	if(p == NULL) {
		fprintf(stderr, "%s Client TCP server failed to bind\n",__func__);
		exit(1);
	}

	/* Start listening to the incoming connection */
	if((listen(sockfd, BACKLOG)) == -1) {
		perror("client listen() failed\n");
		exit(1);
	}

	check_n_print_ip(p->ai_addr, client_ipstr);

	/*message 1*/
	printf("\nThe Client has TCP Port Number %s and IP address %s\n",
						CLIENT_TCP_PORT, client_ipstr);
	pr_debug("%s Client TCP server is UP & awaiting connections... \n", __func__);
	
	/*infinite accept loop*/
	while(1) {
		size_sockaddr_storage = sizeof(in_connect_addr);
		new_fd = accept(sockfd, (struct sockaddr *)&in_connect_addr,
			        &size_sockaddr_storage);
		if(new_fd == -1) {
			/*check errno for reason and do the needful*/
			if (errno != EINTR)
				perror("\naccept failed, retrying...\n");
			continue;
		}

		/*type cast the sockaddr_storage pointer to sockaddr*/
		ptr = (struct sockaddr *)(&in_connect_addr);
		if(ptr->sa_family == AF_INET) {
			/*IPv4*/
			inet_ntop(in_connect_addr.ss_family,
					&(((struct sockaddr_in *)ptr)->sin_addr),
					ipstr, INET_ADDRSTRLEN);
			incoming_port = ntohs(((struct sockaddr_in *)ptr)->sin_port);
		
		} else {
			/*IPv6*/
			inet_ntop(in_connect_addr.ss_family,
					&(((struct sockaddr_in6 *)ptr)->sin6_addr),
					ipstr, INET6_ADDRSTRLEN);
			incoming_port = ntohs(((struct sockaddr_in6 *)ptr)->sin6_port);
		}

		pthread_mutex_lock(&lock);
		srvr_input++;
		if(srvr_input == 4)
			exit_flag = 1;
		srvr_input = srvr_input % 4;

		child_data.cipstr = client_ipstr;
		child_data.ipstr = ipstr;
		child_data.inport = incoming_port;
		child_data.new_fd = new_fd;
		pthread_mutex_unlock(&lock);

		/*lets create a child thread to do the job*/
		ret = (int)pthread_create(&thread[srvr_input], NULL,
					do_child_process, (void *)(&child_data));
		if (ret) {
		         printf("server; return code from pthread_create() is %d\n", ret);
		         exit(-1);
	        }
		if (exit_flag) {
			/*We have got the adjacency matrix filled up*/
			break;
		}
	}
	pr_debug("%s End\n", __func__);
}

int main(int argc, char *argv[]){
	int i,j;
	unsigned int buf_sz;
	char buf[256];
	
	/*initalize the lock*/
	pthread_mutex_init(&lock, NULL);

	for(i=0; i<MAX_SERVER; i++)
		for(j=0;j<MAX_SERVER; j++)
			server_adj_matrix[i][j] = 0;

	/* start client's TCP Server*/
	client_tcp_server();
	sleep(1);

	buf_sz = prepare_message_client(buf, 256);

	/*send the topology to the servers*/
	for(i = 0; i<MAX_SERVER; i++) {
		client_udp_send(i, buf, buf_sz);
	}

	generate_MST();

	pthread_mutex_destroy(&lock);
	pthread_exit(NULL);

	return 0;
}
