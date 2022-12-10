#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

/* setting a PORT */
#define PORT 9002


extern int errno;



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
}



int main()
{
    struct sockaddr_in server_main;	// server main socket
    struct sockaddr_in server_to_client;    //client socket
    bzero (&server_main, sizeof (server_main));
    bzero (&server_to_client, sizeof (server_to_client));

    
    server_main.sin_family = AF_INET;
    server_main.sin_addr.s_addr = htonl (INADDR_ANY);
    server_main.sin_port = htons (PORT);

    int sd;	
    if ((sd = socket (AF_INET, SOCK_STREAM, 0)) == -1)
    {
    	perror ("[server]Socket Error().\n");
    	return errno;
    }

    /* attach the socket */
    if (bind (sd, (struct sockaddr *) &server_main, sizeof (struct sockaddr)) == -1)
    {
    	perror ("[server]Error at binding().\n");
    	return errno;
    }

    if (listen (sd, 1) == -1)
    {
    	perror ("[server]Erorr at listening.\n");
    	return errno;
    }    
    printf("Server is up and running, awaiting users on PORT %d", PORT);
    while(1)
    {
        int client_connection=0;
        int clients_length=sizeof(server_to_client);

        client_connection=accept(sd, (struct sockaddr*)&server_to_client, &clients_length);
        if(client_connection<0)
        {
            perror("[server] Error at establishing connection");
        }
        int client_pid=fork();
        if (client_pid == 0)
        {
            //children; serving the client
            while(1)
            {
                char *username_hash;
                char *password_hash;
            }
        }
        //error at fork or parent
        close(client_connection);
    }


    return 0;
}
