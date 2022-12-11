#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
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


/* error codes */
#define SERVER_DOWN -2



int ValidatePassword(const char* password)
{
    if (strchr(password, ' ') || strlen(password)==0)
    {
        printf("Invalid Password - no blank spaces or null words allowed, try again \n");
        return -1;
    }
    return 0;
}

int ValidateUsername(const char* username, int sd)
{
    if (strchr(username, ' ') || strlen(username)==0)
    {
        printf("Invalid Username - no blank spaces or null words allowed, try again \n");
        return -1;
    }

    if (write(sd, Encode(username), USER_HASH_SIZE) == -1)
    {
        perror("Error ar transfering user data \n");
        return -1;
    }

    return 0;
}


int GetUsername( char* login_command, char username[LGN_SIZE])
{
    if (!strchr(login_command, ' '))
        return -1;
    int counter=0;
    char *word;
    word=strtok(login_command, " ");
    while( word != NULL)
    {
        if(counter==1)
        {   
            strcpy(username, word);
            
        }
        if(counter==2)
        {
            return -1;

        }
        word = strtok (NULL, " ");
        counter++;
    }
    if (strlen(username) == 1)
    {
        return -1;
    }
    if (counter == 1)
        return -1;
    return 0;
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
void read_input(char* buffer, int size)
{
    fgets(buffer, size, stdin);
    buffer[strlen(buffer)-1]='\0';
    /* remove \n character */
}
int SendCommand( int socket_des, int COMMAND_ID)
{
    if (write(socket_des, &COMMAND_ID, sizeof(int))<=0)
    {
        printf("Server Unable to Receive Requests \n");
        return -1;
    }
    return 0;
}
void check_server_state(int sd)
{
    if (recv(sd, NULL, 1,  MSG_PEEK | MSG_DONTWAIT) == 0)
    {
        printf("~~~Server is down \n");
        exit(1);
    }
} /* checks when reading */

void sigpipe_handler()
{
    printf("~~~Server is Down.\n");
    exit(1);
} /* checks when writing */

int HandleLogin(int sd, char* command)
{
    check_server_state(sd);
    char username[USER_INFO_SIZE];
    if(GetUsername(command, username) == -1)
    {
        printf("syntax error - login syntax: login <username> \n");
        return -1;
    }
    if (SendCommand(sd, LOGIN_REQ) == -1)
    {
        printf("Server is Down \n");
        return SERVER_DOWN;
    }
    char password[USER_INFO_SIZE];
    printf("Enter password: "); fflush(stdout);
    read_input(password, USER_INFO_SIZE);
    if(ValidatePassword(password) == -1)
    {
        return -1;
    }

    /* send user data to server */

    if( write(sd, Encode(username), USER_HASH_SIZE) <=0 )
    {
        printf("Unable to Receive Requests. \n");
        return -1;
    }

    if( write(sd, Encode(password), USER_HASH_SIZE) <=0 )
    {
        printf("Unable to Receive Requests. \n");
        return -1;
    }
    return 0;
}

int confirm_password(const char *pas1, const char *pas2)
{
    if (strcmp(pas1, pas2)!=0)
    {
        printf("Passwords don't match.\n");
        return -1;
    }
    return 0;
}
int HandleSignup(int sd)
{
    check_server_state(sd);

    char username[USER_INFO_SIZE];
    do
    {
        printf("Set Username:"); fflush(stdout);
        read_input(username, USER_INFO_SIZE);
    } while (ValidateUsername(username) == -1);

    char password[USER_INFO_SIZE];
    char second_password[USER_INFO_SIZE];
    do 
    {
        do
        {
            printf("Set Password:"); fflush(stdout);
            read_input(password, USER_INFO_SIZE);
        } while (ValidatePassword(password) == -1);
        printf("Confirm Password:"); fflush(stdout);
        read_input(second_password, USER_INFO_SIZE);

    }while ( (confirm_password(password, second_password)) == -1);    
     /* account data validated */


    return 0;
}


int main(int argc, char* argv[])
{
    if (argc!=3)
    {
        printf("Command syntax:%s <IP Address> <PORT> \n", argv[0]);
        return -1;
    }
    int port=atoi(argv[2]);
    int sd=socket(AF_INET, SOCK_STREAM, 0);
    if (sd == -1)
    {
        perror("Error at socket \n");
        return errno;
    }/* the socket */

    struct sockaddr_in server;
    server.sin_family = AF_INET;
    inet_aton(argv[1], &server.sin_addr);
    server.sin_port = htons (port);
    /* the sockaddr_in structure */

    if(connect(sd, (struct sockaddr*) &server, sizeof(struct sockaddr)) == -1)
    {
        perror("Error at establishing connection \n");
        return errno;
    }

    signal(SIGPIPE,sigpipe_handler);


    printf("~~CONNECTED TO MyFTP SERVER... \n");
    char client[100]="Client";
    while(1)
    {
        char command[CMD_SIZE];
        printf("%s>", client); fflush(stdout);
        read_input(command, CMD_SIZE);

        /*interpret command */
        if (strstr(command, "login"))
        {
             /* user wants to log in*/
            int code=HandleLogin(sd, command);
            if (code == -1)
                continue;
            continue;
        }

        if (strcmp(command, "sign up") ==0
            || strcmp(command," sign up ")==0)
        {
            if (HandleSignup(sd) == -1)
                continue;
            continue;
        }

        if (strcmp(command, "quit") ==0
            || strcmp(command,"quit ")==0)
        {
            SendCommand(sd, QUIT);
            exit(1) ;
        }
    }

    return 0;
}