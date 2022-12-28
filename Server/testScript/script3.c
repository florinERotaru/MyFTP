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
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
extern int errno;

/* signal */
#define USER_EXSTS 30
#define USER_VALID 31
#define SGNUP_SUCC 32
#define INCRCT_DATA 33
#define LOGIN_SUCC 34
#define ERRMKDIR 35
#define MKDIRSUCC 36
#define STOP_DWNLD 37
#define OK 38

/* sizes */
#define CMD_SIZE 100
#define LGN_SIZE 100
#define USER_INFO_SIZE 100
#define USER_HASH_SIZE 200
#define DIRLEN 50

/* command codes */
#define LOGIN_REQ 0
#define INSPECT_REQ 1
#define DOWNLOAD_REQ 2
#define UPLOAD_REQ 3
#define QUIT 4
#define SIGNUP_REQ 5
#define DISCON 6
#define LOGIN_INTRP 7
#define LOGIN_CONT 8
#define DONE_F 9
#define NAVIGATE 10
#define INCOMING_DATA 11
#define INV_PATH 12
#define DONE_INSPECTING 13
#define REACHED_ROOT 14
#define NEW_DIR 15
#define GETFILE 16

/* error codes */
#define SERVER_DOWN -2


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

int SendCommand( int socket_des, int COMMAND_ID)
{
    if (write(socket_des, &COMMAND_ID, sizeof(int))<=0)
    {
        printf("Server Unable to Receive Requests \n");
        return -1;
    }
    return 0;
}

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

    if (write(sd, Encode(username), USER_HASH_SIZE) <= 0)
    {
        perror("Error ar transfering user data \n");
        return -1;
    }

    int signal;
    read(sd, &signal, sizeof(int));

    /* user exists */
    if (signal == USER_EXSTS) 
    {
        printf("~~~Username is taken.\n");
        return -1;

    }
    if (signal == USER_VALID)
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


int GetDirArg( char* login_command, char dirname[DIRLEN])
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
            strcpy(dirname, word);
            
        }
        if(counter==2)
        {
            return -1;

        }
        word = strtok (NULL, " ");
        counter++;
    }
    if (strlen(dirname) == 1)
    {
        return -1;
    }
    if (counter == 1)
        return -1;
    return 0;
}


 
void read_input(char* buffer, int size)
{
    fgets(buffer, size, stdin);
    buffer[strlen(buffer)-1]='\0';
    /* remove \n character */
}

void check_server_state(int sd)
{
    if (recv(sd, NULL, 1,  MSG_PEEK | MSG_DONTWAIT) == 0)
    {
        perror("~~~Server is down(r) \n");
        exit(1);
    }
} /* checks when reading */

void sigpipe_handler()
{
    perror("~~~Server is Down(w)\n");
    exit(1);
} /* checks when writing */

int HandleLogin(int sd, char* command, char* res_username)
{
    if (SendCommand(sd, LOGIN_REQ) == -1)
    {
        printf("Server is Down \n");
        return SERVER_DOWN;
    }
    int CONNECTED;
    read(sd, &CONNECTED, sizeof(int));
    if (CONNECTED == 1)
    {
        printf("~~User already logged in. ('sign out' first) \n");
        return 1;
    }
    char username[USER_INFO_SIZE];
    int cmd=LOGIN_INTRP;
    if(GetUsername(command, username) == -1)
    {
        printf("syntax error - login syntax: login <username> \n");
        write(sd, &cmd, sizeof(int));
        return -1;
    }
    
    
    char password[USER_INFO_SIZE]="123";
    if(ValidatePassword(password) == -1)
    {
        cmd=LOGIN_INTRP;
        write(sd, &cmd, sizeof(int));
        return -1;
    }
    cmd=LOGIN_CONT;
    write(sd, &cmd, sizeof(int));

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

    int signal;
    read(sd, &signal, sizeof(int));
    if (signal == INCRCT_DATA)
    {
        printf("~~~Wrong login or password \n");
        return -1;
    }
    if (signal == LOGIN_SUCC)
    {
        printf("~~~User logged in successfully \n");
        strcpy(res_username, username);
        return 0;
    }
    printf("%d \n", signal);
    return -1;
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

int ReceiveEntryList(int sd)
{
    int signal=0;
    read(sd, &signal, sizeof(int));
    if(signal==REACHED_ROOT)
    {
        printf("~~~Root Reached. \n");
        return -1;
    }
    if(signal==INV_PATH)
    {
        printf("~~~Invalid directory name. \n");
        return -1;
    } /* confirm that transmission will start */

    char* dirname=(char*)calloc(30, sizeof(char));
    if(read(sd, dirname, 30) <= 0)
    {
        printf("Error at retreiving dirnam \n");
        return -1;
    } /* get current file name */
    printf("===%s", dirname);
    for (int i=0; i<35-strlen(dirname); i++)
    {
        printf("=");
    }
    //printf("Size(bytes) \n");
    printf("\n");

    free(dirname);
    
    char entryname[50];
    //int size=0;
    read(sd, &signal, sizeof(int));
    while(signal==INCOMING_DATA)
    {
        read(sd, entryname, 50);
        //read(sd, &size, sizeof(int));
        printf("   %s", entryname);
        for(int i=0; i<40-strlen(entryname); i++)
        {
            printf(".");
        }
        //printf("%d \n", size);
        printf("\n");

        read(sd, &signal, sizeof(int));
    }
    
    if(signal==DONE_INSPECTING)
    {
        return 0;
    }
    return 0;
}

int HandleMkdir(int sd, char* command)
{
    char dirname[DIRLEN];
    if (GetDirArg(command, dirname)==-1)
    {
        printf("syntax error - mkdir syntax: mkdir <directory name> \n");
        return -1;
    }
    SendCommand(sd, NEW_DIR);
    write(sd, dirname, DIRLEN);
    /* sent dir. name*/

    /* check status: */
    int signal=0;
    read(sd, &signal, sizeof(int));
    if(signal==ERRMKDIR)
    {
        printf("~~~Could not create specified directory \n");
        return -1;
    }
    if(signal==MKDIRSUCC)
    {
        printf("~~~Directory created: \n");
        ReceiveEntryList(sd);

    }
    return 0;
}
int GetFile(int sd, char* filename)
{
    int signal=0;
    struct stat statbuf;
    if (stat(filename, &statbuf) == 0)
    {
        if(statbuf.st_size != 0)
        {
            printf("~~~Overwrite the file? (y/n) \n");
            char answ;
            do
            {
                printf("-->>y/n: "); fflush(stdout);
                scanf("%c", &answ);
                fgetc(stdin);

            }while(answ != 'y' && answ!= 'n');

            if (answ == 'n')
            {
                signal=STOP_DWNLD;
                write(sd, &signal, sizeof(int));
                return -1;      /* send not ok to server */
            }
            
        }
    }
    
	int newfile=open("cartea3.pdf", O_RDWR|O_TRUNC|O_CREAT, S_IRWXU);
    if(newfile==-1)
    {
        perror("~~~File download failed. \n");
        close(newfile);
        signal=STOP_DWNLD;
        write(sd, &signal, sizeof(int));
        return -1;      /* send not ok to server */
    }
    signal=OK;
    write(sd, &signal, sizeof(int));

    write(sd, filename, DIRLEN); /* sent requested file name */

    signal=0;
    read(sd, &signal, sizeof(int));
    if(signal == STOP_DWNLD)
    {
        printf("~~~No such file in the database. \n");
        //remove(filename);
        close(newfile);
        return -1;      /* get ok from server*/
    }

    unsigned char buffer[4096];
	bzero(buffer, 4096);
	int count=0;

	printf("starting to transfer... \n");
    sleep(1);
    while ((count = recv(sd, buffer, sizeof buffer, MSG_DONTWAIT)) > 0)
  	{
        // printf("%d \n", count);
        // perror(" ");
    	if ( (write(newfile, buffer, count)) < 0)
    	{
     		perror("write"); //  at least
      		return -1;
    	}
        if (count<0)
  		{
   			perror("[server] reading \n");
            return -1;
 	 	}
 	}
    printf("reached here \n");
    close(newfile);
    return 0;
}
int HandleDownload(int sd, char* command)
{
    char filename[DIRLEN];
    if (GetDirArg(command, filename)==-1)
    {
        printf("syntax error - get syntax: get <filename> \n");
        return -1;
    }
    SendCommand(sd, GETFILE);
    GetFile(sd, filename);
    return 0;
}
int Handle_ls(int sd)
{

    if (SendCommand(sd, INSPECT_REQ)==-1)
    {
        perror("Sever is down.\n");
        return -1;
    }
    int CONNECTED;
    if(read(sd, &CONNECTED, sizeof(int))<=0)
    {
        perror("problem at receiving conn \n");
        return -1;
    }
    if (CONNECTED == 0)
    {
        printf("~~Log in to perform this action.\n");
        return 1;
    }


    ReceiveEntryList(sd);
    char command[200]="get Ion-Creanga_Amintiri-din-copilarie.pdf";

        printf("[filesystem]>"); fflush(stdout);
        if(strcmp(command, "done")==0)
        {
            SendCommand(sd, DONE_F);
            return 0;
        }
        if(strstr(command, "mkdir"))
        {
            HandleMkdir(sd, command);
        }
        if(strstr(command, "get"))
        {
            HandleDownload(sd, command);
            return -1;
        }
        SendCommand(sd, NAVIGATE);
        write(sd, command, 30);
        ReceiveEntryList(sd);
    return 0;
}
int HandleSignup(int sd, char* final_username)
{
    //check_server_state(sd);
    SendCommand(sd, SIGNUP_REQ);
    int CONNECTED;
    read(sd, &CONNECTED, sizeof(int));
    if (CONNECTED == 1)
    {
        printf("~~User already logged in ('sign out' first).\n");
        return 1;
    }
    char username[USER_INFO_SIZE];
    do
    {
        printf("Set Username:"); fflush(stdout);
        read_input(username, USER_INFO_SIZE);
    } while (ValidateUsername(username, sd) == -1);
    strncpy(final_username, username, USER_INFO_SIZE);
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

    write(sd, Encode(password), USER_HASH_SIZE);

    int signal;
    read(sd, &signal, sizeof(int));
    if(signal==SGNUP_SUCC)
        printf("~~~Account created.\n");

    return 0;
}
int sd=0;
void end_conn()
{
    close(sd);
    exit(1);
}
int main(int argc, char* argv[])
{
    if (argc!=3)
    {
        printf("Command syntax:%s <IP Address> <PORT> \n", argv[0]);
        return -1;
    }
    atexit(end_conn);
    int port=atoi(argv[2]);
    sd=socket(AF_INET, SOCK_STREAM, 0);
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

    signal(SIGPIPE, sigpipe_handler);  
    signal(SIGTSTP, end_conn); /* for ctrl + z */
    signal(SIGINT, end_conn); /* for ctrl + c */  

    char command[256]="login amageala";
    char res[256];
    HandleLogin(sd, command, res);
    Handle_ls(sd);


    return 0;
}