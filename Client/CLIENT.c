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
#include <sys/sendfile.h>
#include <termios.h>
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
#define OKAY 38

/* sizes */
#define CMD_SIZE 100
#define LGN_SIZE 100
#define USER_INFO_SIZE 100
#define USER_HASH_SIZE 200
#define DIRLEN 100

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
#define UPLFILE 17
#define NO_PERM 18



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
void PrintInstructions()
{
    printf("    In order to interact with the server, sign in to your account or sign up if you don't have one. \n ");
    printf("('login <username>' OR 'sign up') \n");
    printf("    Once in your account, use 'seefiles' to see, download or upload files. \n");

}
void PrintInstructionsLs()
{
    printf("1.  Navigate through the filesystem using $<directoryname> and $back.\n");
    printf("2.  Download files with $get <filename>.\n");
    printf("3.  Upload files with $upload <filename>, where <filename> is a local file in your directory.\n");
    printf("4.  Create your own remote directory with $mkdir <directory_name>.\n");
    printf("5.  Once done, use $done to return to the account interface.\n");
    printf("(N.B.) $ indicates the terminal, do not use it in commands.\n");

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
void read_password(char*buffer, int size)
{
    struct termios old_termios, new_termios;
    tcgetattr(STDIN_FILENO, &old_termios);
    new_termios = old_termios;
    new_termios.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_termios);

    fgets(buffer, size, stdin);
    buffer[strlen(buffer)-1]='\0';

    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_termios);

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
    
    
    char password[USER_INFO_SIZE];
    printf("Enter password: "); fflush(stdout);
    //read_input(password, USER_INFO_SIZE);
    read_password(password, USER_INFO_SIZE);
    printf("\n");
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

    char* dirname=(char*)calloc(DIRLEN, sizeof(char));
    if(read(sd, dirname, DIRLEN) <= 0)
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
    
    char entryname[DIRLEN];
    //int size=0;
    read(sd, &signal, sizeof(int));
    while(signal==INCOMING_DATA)
    {
        read(sd, entryname, DIRLEN);
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
    int signal=0;
    read(sd, &signal, sizeof(int));
    if(signal==NO_PERM)
    {
        printf("~~~User has no write permissions. \n");
        return -1;
    }

    write(sd, dirname, DIRLEN);
    /* sent dir. name*/

    /* check status: */
    signal=0;
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
                return -1;      /* send notOKAYto server */
            }
            
        }
    }
    
    printf("%s \n", filename);
	int newfile=open(filename, O_RDWR|O_TRUNC|O_CREAT, S_IRWXU);
    if(newfile==-1)
    {
        perror("~~~File download failed. \n");
        close(newfile);
        signal=STOP_DWNLD;
        write(sd, &signal, sizeof(int));
        return -1;      /* send notOKAYto server */
    }
    signal=OKAY;
    write(sd, &signal, sizeof(int));

    write(sd, filename, DIRLEN); /* sent requested file name */

    signal=0;
    read(sd, &signal, sizeof(int));
    if(signal == STOP_DWNLD)
    {
        printf("~~~No such file in the database. \n");
        //remove(filename); /*bug*/
        close(newfile);
        return -1;      /* getOKAYfrom server*/
    }

    unsigned char buffer[4096];
	bzero(buffer, 4096);
	int count=0;

	printf("starting to transfer... \n");
    /* send the size to the receiver */
    sleep(1);
    off_t recvsize=0;
    read(sd, &recvsize, sizeof(off_t));
    printf("%ld \n", recvsize);
    off_t sum=0;
    while ((count = read(sd, buffer, sizeof buffer)) > 0)
  	{
        sum+=count;
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
        if (sum >= recvsize)
        {
            break;
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

int SendFile(int sd, char* filename, int sentfile)
{
    write(sd, filename, DIRLEN);
    int signal=0;
    read(sd, &signal, sizeof(int));
    if(signal == STOP_DWNLD)
    {
        printf("~~~Error at uploading. \n");

    }
    int count;
    unsigned char buffer[4096];
    bzero(buffer, 4096);
    off_t offset=0;
    off_t sendsize=0;
    struct stat statbuf;
    stat(filename, &statbuf);
    sendsize=statbuf.st_size;
    write(sd, &sendsize, sizeof(off_t));
    sleep(1);
    while(count = sendfile(sd,sentfile,&offset,4096)>0) 
    { 
        if (count<0)
        {
            perror("errr \n");
            return -1;
        }
    }


    return 0;
}


int HandleUpload(int sd, char* command)
{
    
    char filename[DIRLEN];
    if(GetDirArg(command, filename) == -1)
    {
        printf("syntax error - get syntax: upload <filename> \n");
        return -1;
    }
    int sentfile=open(filename, O_RDWR);
    if (sentfile == -1)
    {
        printf("~~~No such local file. \n");
        return -1;
    }
    SendCommand(sd, UPLFILE);

    int signal=0;
    read(sd, &signal, sizeof(int));
    if(signal==NO_PERM)
    {
        printf("~~~User has no write permissions. \n");
        return -1;
    }
    SendFile(sd,filename, sentfile);
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
    sleep(1);
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
    while(1)
    {
        char command[CMD_SIZE];
        printf("[filesystem]>"); fflush(stdout);
        read_input(command, CMD_SIZE);
        if(strcmp(command, "done")==0)
        {
            SendCommand(sd, DONE_F);
            return 0;
        }
        if(strstr(command, "mkdir"))
        {
            HandleMkdir(sd, command);
            continue;
        }
        if(strstr(command, "get"))
        {
            HandleDownload(sd, command);
            continue;
        }
        if(strstr(command, "upload"))
        {
            HandleUpload(sd, command);
            continue;
        }
        if(strcmp(command, "cmds ")==0 || strcmp(command, "cmds")==0)
        {
            PrintInstructionsLs();
            continue;
        }
        SendCommand(sd, NAVIGATE);
        write(sd, command, CMD_SIZE);
        sleep(1);
        ReceiveEntryList(sd);
    }
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
            //read_input(password, USER_INFO_SIZE);
            read_password(password, USER_INFO_SIZE);
            printf("\n");
        } while (ValidatePassword(password) == -1);
        printf("Confirm Password:"); fflush(stdout);

        //read_input(second_password, USER_INFO_SIZE);
        read_password(second_password, USER_INFO_SIZE);
        printf("\n");
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

    printf("~~~CONNECTED TO MyFTP SERVER... \n");
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
            char username[USER_INFO_SIZE];
            int code=HandleLogin(sd, command, username);
            if (code == -1)
                continue;
            strcpy(client, username);
            continue;
        }

        if (strcmp(command, "sign up") ==0
            || strcmp(command," sign up ")==0)
        {
            char username[USER_INFO_SIZE];
            if (HandleSignup(sd, username) == -1)
                continue;
            strcpy(client, username);
            continue;
        }
        if (strcmp(command, "seefiles ")==0 || strcmp(command, "seefiles")==0)
        {
            Handle_ls(sd);
            continue;
        }

        if (strcmp(command, "sign out ") ==0
            || strcmp(command,"sign out")==0)
        {
            if (SendCommand(sd, DISCON) == -1)
                continue;
            strcpy(client, "Client");
            printf("~~~User signed out. \n");
            continue;
        }

        

        if (strcmp(command, "quit") ==0
            || strcmp(command,"quit ")==0)
        {
            SendCommand(sd, QUIT);
            close(sd);
            return 0;
        }

        if(strcmp(command, "cmds ")==0 || strcmp(command, "cmds")==0)
        {
            PrintInstructions();
            continue;
        }
        printf("~~~Unknown command. Run'cmds' for instructions. \n");
    }

    return 0;
}