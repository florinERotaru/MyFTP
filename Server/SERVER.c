#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <signal.h>
#include "parson.c"
#include "parson.h"

/* setting a PORT */
#define PORT 9001


extern int errno;

/* sizes */
#define CMD_SIZE 100
#define LGN_SIZE 100
#define USER_INFO_SIZE 100
#define USER_HASH_SIZE 200

/* command codes */
#define LOGIN_REQ 0
#define INSPECT_REQ 1
#define DOWNLOAD_REQ 2
#define UPLOAD_REQ 3
#define QUIT 4
#define SIGNUP_REQ 5

char USERS_JSON[30] ="user_data.json";

int chartohex(char chr)     /* will return smth in [00 to FF] */
{
    if( chr>='0' && chr<='9' )
        return(chr - 48);
    if( chr>='A' && chr<='F' )
        return( chr - 'A' + 10);
    return(-1);
}

const char* Encode(const char* decrypted_msg)
{
    char *encrypted_message=(char*)calloc(strlen(decrypted_msg)*2, sizeof(char));
    sprintf(&encrypted_message[0], "%02X", decrypted_msg[0]);
    for(int i=1; i<strlen(decrypted_msg); i++)
    {
        char byte[3];
        sprintf(byte, "%02X", (unsigned char) (decrypted_msg[i] - decrypted_msg[i-1]));
        strcat(encrypted_message, byte);
    }
    return encrypted_message;
}

const char* Decode(const char* encrypted_msg)
{
    char *decrypted_message=(char*)calloc(strlen(encrypted_msg)/2+1, sizeof(char));
    int first, second;
    int symbol=0;
    int i=0;
    while(i<strlen(encrypted_msg)-1)
    {
        if ( (first=chartohex(encrypted_msg[i++]) ) == -1)
        { 
            perror("Error at receiving user data ");
            break;
        }
        if ( (second=chartohex(encrypted_msg[i++]) ) == -1)
        { 
            perror("Error at receiving user data");
            break;
        }

        symbol += second + (first*16); 
        unsigned char new_char=symbol;
        strncat(decrypted_message, &new_char, 1);
    }
    return decrypted_message;
} /*Decode is not used at all, presented just for the sake of it */

void add_user_to_json(const char * usr, const char* pas)
{

}

void init_json()
{
    JSON_Value* val=json_value_init_array();
    JSON_Value* users_info=json_value_init_object();
    json_object_set_value(json_object(users_info), "users", val);
    json_serialize_to_file_pretty(users_info, USERS_JSON);

}
int HandleSignup(int client_connection)
{
    printf("user wants to sign up \n");
    char usr_hash[USER_HASH_SIZE];
    if( read(client_connection, usr_hash, USER_HASH_SIZE) == -1 )
    {
        perror("Error at transfering user data \n");
        return -1;
    }

    char pass_hash[USER_HASH_SIZE];
    if( read(client_connection, pass_hash, USER_HASH_SIZE) == -1 )
    {
        perror("Error at transfering user data \n");
        return -1;
    }

    


}
int HandleLogin(int client_connection)
{
    char usr_hash[USER_HASH_SIZE];
    char pass_hash[USER_HASH_SIZE];

    printf("user wants to log in \n");
    if (read(client_connection, usr_hash, USER_HASH_SIZE) == -1)
    {
        perror("problem at trasnfering user data \n");
    }
    if (read(client_connection, pass_hash, USER_HASH_SIZE) == -1)
    {
        perror("problem at trasnfering user data \n");
    }

    return 0;
}
/* descriptors */
int client_connection=0;
int sd=0;	

/* on exit instructions */
void end_server()
{
    close(client_connection);
    close(sd);
    exit(1);
}

int main()
{
    signal(SIGTSTP, end_server); /* for ctrl + z */
    atexit(end_server);
    
    /* init user info base */
    if (access(USERS_JSON, F_OK) != 0)
    {
        init_json();
    }


    struct sockaddr_in server_main;	// server main socket
    struct sockaddr_in server_to_client;    //client socket
    bzero (&server_main, sizeof (server_main));
    bzero (&server_to_client, sizeof (server_to_client));

    server_main.sin_family = AF_INET;
    server_main.sin_addr.s_addr = htonl (INADDR_ANY);
    server_main.sin_port = htons (PORT);
    if ((sd = socket (AF_INET, SOCK_STREAM, 0)) == -1)
    {
    	perror ("Socket Error.\n");
    	return errno;
    }

    /* attach the socket */
    if (bind (sd, (struct sockaddr *) &server_main, sizeof (struct sockaddr)) == -1)
    {
    	perror ("Error at binding().\n");
    	return errno;
    }

    if (listen (sd, 1) == -1)
    {
    	perror ("Erorr at listening.\n");
    	return errno;
    }    
    
    printf("Server is up and running, awaiting users on PORT %d \n", PORT);
    while(1)
    {
        int clients_length=sizeof(server_to_client);

        client_connection=accept(sd, (struct sockaddr*)&server_to_client, &clients_length);
        if(client_connection<0)
        {
            perror("Error at establishing connection \n");
            return errno;
        }
        char ip[30];
        inet_ntop(AF_INET, &server_to_client.sin_addr, ip,30);
        printf("One Client has just connected, IP: %s \n", ip);
        int client_pid=fork();
        if (client_pid == 0)
        {
            //children; serving the client
            close(sd);
            while(1)
            {
                int cmd_id=0;
                if (read(client_connection, &cmd_id, sizeof(int)) <= 0)
                {
                    printf("Client disconnected \n");
                    close(client_connection);
                    return 0;
                }
                if (cmd_id == LOGIN_REQ)
                {
                    HandleLogin(client_connection);
                    continue;
                }
                if (cmd_id == SIGNUP_REQ)
                {
                    HandleLogin(client_connection);
                    continue;
                }
                if (cmd_id == QUIT)
                {
                    close(client_connection);
                    return 0;
                }
            }
        }
        //in parent or error at fork
        close(client_connection);
    }


    return 0;
}
