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
#include <dirent.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <fcntl.h>


#define FILESYS "filesystem"


/* setting a PORT */
#define PORT 9010


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
#define PATH_SZ 200
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


char USERS_JSON[30] ="user_data.json";
struct user_record{
    char usr_hash[USER_HASH_SIZE];
    char pass_hash[USER_HASH_SIZE];
    char perm[3];
};
int chartohex(char chr)     /* will return smth in [00 to FF] */
{
    if( chr>='0' && chr<='9' )
        return(chr - 48);
    else
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
    /* creating the new user */
    JSON_Value* new_user = json_value_init_object();
    json_object_set_string(json_object(new_user), "name", usr);
    json_object_set_string(json_object(new_user), "password", pas);
    json_object_set_string(json_object(new_user), "permissions", "rw");
    
    /* getting the actual array to which we will append */
    JSON_Value* users_info = json_parse_file(USERS_JSON);
    JSON_Value* val = json_value_init_array();
    val->value.array=json_object_get_array(json_object(users_info), "users");
    json_array_append_value(val->value.array, new_user);

    /*setting the new value & serializing*/
    users_info=json_value_init_object();
    json_object_set_value(json_object(users_info), "users", val);
    json_serialize_to_file_pretty(users_info, USERS_JSON);

}

void init_json()
{
    JSON_Value* val=json_value_init_array();
    JSON_Value* users_info=json_value_init_object();
    json_object_set_value(json_object(users_info), "users", val);
    json_serialize_to_file_pretty(users_info, USERS_JSON);

}

int get_user_from_json(const char* usr_hash, struct user_record *user)
{
    JSON_Value* users_info=json_parse_file(USERS_JSON);
    JSON_Array* users_array=json_object_get_array(json_object(users_info), "users");
    
    JSON_Value* found_user=json_value_init_object();
    int nr_of_users=json_array_get_count(users_array);
    for(int i=0; i<nr_of_users; i++)
    {
        found_user=json_array_get_value(users_array, i);
        if (
            strcmp(
                usr_hash,
                json_object_get_string(json_object(found_user), "name")
                )==0
            )
        {
            strncpy(user->pass_hash, 
                    json_object_get_string(json_object(found_user), "password"), USER_HASH_SIZE);
            strncpy(user->usr_hash, usr_hash, USER_HASH_SIZE);
            strncpy(user->perm, 
                    json_object_get_string(json_object(found_user), "permissions"), 3);
            
            return 0;
        }
    }
    return -1;

}

void read_input(char* buffer, int size)
{
    fgets(buffer, size, stdin);
    buffer[strlen(buffer)-1]='\0';
    /* remove \n character */
}

int HandleSignup(int client_connection)
{
    int signal;
    perror("user wants to sign up \n");
    char usr_hash[USER_HASH_SIZE];
    if( read(client_connection, usr_hash, USER_HASH_SIZE) <= 0)
    {
        perror("Error at transfering user data \n");
        return -1;
    }

    struct user_record user;
    while (get_user_from_json(usr_hash, &user) != -1)
    {
        //Username already exists
        signal=USER_EXSTS;
        write(client_connection, &signal, sizeof(int));
        if( read(client_connection, usr_hash, USER_HASH_SIZE) <=0 )
        {
            perror("(2)Error at transfering user data \n");
            return -1;
        }
    }
    signal=USER_VALID;
    write(client_connection, &signal, sizeof(int));

    char pass_hash[USER_HASH_SIZE];
    if( read(client_connection, pass_hash, USER_HASH_SIZE) == -1 )
    {
        perror("(1)Error at transfering user data \n");
        return -1;
    }

    add_user_to_json(usr_hash, pass_hash);
    
    signal=SGNUP_SUCC;
    write(client_connection, &signal, sizeof(int));
    return 0;


}
int HandleLogin(int client_connection)
{
    char usr_hash[USER_HASH_SIZE];
    char pass_hash[USER_HASH_SIZE];

    perror("user wants to log in \n");

    int cmd;
    read(client_connection, &cmd, sizeof(int));
    if (cmd==LOGIN_INTRP)
    {
        return -1;
    }
    
    if (read(client_connection, usr_hash, USER_HASH_SIZE) <= 0)
    {
        perror("problem at trasnfering user data \n");
    }
    if (read(client_connection, pass_hash, USER_HASH_SIZE) <= 0)
    {
        perror("problem at trasnfering user data \n");
    }

    /* check if login/password is right */

    struct user_record check_user;
    int signal=0;
    if (get_user_from_json(usr_hash, &check_user) == -1)
    {
        signal=INCRCT_DATA;
        write(client_connection, &signal, sizeof(int));
        return -1;
    } /* check login */

    if(strcmp(check_user.pass_hash, pass_hash) !=0 ) 
    {
        signal=INCRCT_DATA;
        write(client_connection, &signal, sizeof(int));
        return -1;
    }

    signal=LOGIN_SUCC;
    write(client_connection, &signal, sizeof(int));
    return 0;
}

char* revv(const char* accept)
{
    char *res=(char*)calloc(200, sizeof(char));
    strncpy(res, accept, 200);
    char * c1=res;
    char * c2=res+strlen(res)-1;
    while( c1 < c2)
    {
        /* swap */
        *c1 ^= *c2;
        *c2 ^= *c1;
        *c1 ^= *c2;
        c1++;
        c2--;
    }
    return res;
}

void trimback(char* accept)
{
    int t=strlen(accept)-strcspn(revv(accept), "/")-1;
    accept[t]='\0';
}


int InspectDir(int client_connection, const char* dirname, char* dirpath)
{
    int signal=0;
    printf("%s \n", dirpath);
    DIR* dir=opendir(dirpath);
    if(dir == NULL)
    {
        printf("Invalid dir %s \n", dirpath);
        signal=INV_PATH;
        write(client_connection, &signal, sizeof(int));
        return -1;
    }
    /* let the client know that all is ok*/
    signal=INCOMING_DATA;
    write(client_connection, &signal, sizeof(int));

    write(client_connection, dirname, 30); /* send dirname */

    struct dirent* fidir;
    fidir=readdir(dir);
    struct stat st;
    while(fidir!=NULL)
    {
        if(strcmp(fidir->d_name, ".") != 0 && strcmp(fidir->d_name, "..") != 0)
        {
            signal=INCOMING_DATA;
            write(client_connection, &signal, sizeof(int));
            write(client_connection, fidir->d_name, 50);
            /* make the path to get the size */
            //stat(dirpath, &st);
            //write(client_connection, &st.st_size, sizeof(int));
            
            printf("%s \n", fidir->d_name);//send name
        }
        fidir=readdir(dir);
    }
    signal=DONE_INSPECTING;
    write(client_connection, &signal, sizeof(int));
    closedir(dir);
    return 0;

}

int HandleNavigation(int client_connection, char* path, char name[30])
{
    if(read(client_connection, name, 30) <= 0)
        {
            perror("no more \n");
            return -1;
        }
        if(strlen(name)==0 || name[0]=='/' 
                                || 
                                (strlen(name) == 1 &&
                                !isalpha(name[0]) && 
                                !isdigit(name[0]))
                                )/* blank space or action code */
        {
            int signal=INV_PATH;
            write(client_connection, &signal, sizeof(int));
            return -1;
        }
        if(strcmp(name, "back")==0)
        {
            if(strcmp(path, FILESYS)==0)
            {
                int signal=REACHED_ROOT;
                write(client_connection, &signal, sizeof(int));
                return -1;
            }
            trimback(path);
        }
        else
        {
            strcat(path, "/");
            strcat(path, name);
        }
        if(strcmp(name, "menu")==0)
        {
            return -1;
        }
        
        if (InspectDir(client_connection, name, path) != 0)
        {
            trimback(path);
        }
    return 0;
}

int HandleMkdir(int client_connection, char* path, char current_name[30])
{
    char dirname[DIRLEN];
    if (read(client_connection, dirname, DIRLEN) <= 0)
    {
        perror("Error at getting the newdir name \n");
        return -1;
    }
    strcat(path, "/");
    strcat(path, dirname);
    printf("%s \n", path);
    int signal=0;
    if (mkdir(path, 0777) == -1)
    {
        signal=ERRMKDIR;
        write(client_connection, &signal, sizeof(int));
        return -1;
    }
    signal=MKDIRSUCC;
    write(client_connection, &signal, sizeof(int));
    trimback(path);
    InspectDir(client_connection, current_name, path);

    return 0;
}
int SendFile(int client_connection, char* path)
{
    int signal=0;
    read(client_connection, &signal, sizeof(int));
    if(signal == STOP_DWNLD)
    {
        return -1;
    }               /* get ok from client */

    char filename[DIRLEN];
    read(client_connection, filename, DIRLEN);
    strcat(path, "/");
    strcat(path, filename);
    printf("%s \n", path);
    int sentfile=open(path, O_RDWR);
    if (sentfile == -1)
    {
        printf("could not open \n");
        signal=STOP_DWNLD;
        write(client_connection, &signal, sizeof(int));
        trimback(path);
        return -1;
    }
    perror("opened \n");
       
    signal=OK;   /* send ok to client */
    write(client_connection, &signal, sizeof(int));

    int count;
    unsigned char buffer[4096];
    bzero(buffer, 4096);
    off_t offset=0;

    int signal=SENDING;
    while(count = sendfile(client_connection,sentfile,&offset,4096)>0) 
    { 
        write(client_connection, &signal, sizeof(int));
        if (count<0)
        {
            perror("errr \n");
            return -1;
        }
    }
    perror("done sending \n");
    close (sentfile);
    trimback(path);
    return 0;
}
// int HandleDownload(int client_connection, char* path)
// {
//     char filename[DIRLEN];
//     if (read(client_connection, filename, DIRLEN) <= 0)
//     {
//         perror("Error at getting the filename(d) name \n");
//         return -1;
//     }
//     strcat(path, "/");
//     strcat(path, filename);
//     printf("%s \n", path);
//     int signal=0;

//     return 0;
// }
int Handle_ls(int client_connection)
{

    char path[PATH_SZ]=FILESYS;
    InspectDir(client_connection, FILESYS, path);
    int cmd_id=0;
    char current_name[30];
    while(1)
    {
        if(read(client_connection, &cmd_id, sizeof(int))<=0)
        {
            return -1;
        }
        if(cmd_id==DONE_F)
        {
            return 0;
        }
        if (cmd_id==NAVIGATE)
        {
            HandleNavigation(client_connection, path, current_name);
            continue;
        }
        if (cmd_id==NEW_DIR)
        {
            HandleMkdir(client_connection, path, current_name);
            continue;
        }
        if (cmd_id==GETFILE)
        {
            SendFile(client_connection, path);
            continue;
        }
        
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
// int HandleServerTerminal()
// {
//     char command[CMD_SIZE];
//     while(1)
//     {
//         printf("SERVER> "); fflush(stdout);
//         read_input(command, CMD_SIZE);
//     }
//     return 0;
// }
int main()
{
    signal(SIGTSTP, end_server); /* for ctrl + z */
    signal(SIGINT, end_server); /* for ctrl + c */
    
    atexit(end_server);
    
    if (access(USERS_JSON, F_OK) != 0)
    {
        init_json();
    }

    // int server_terminal=fork();
    // if (server_terminal==0)
    // {
    //     HandleServerTerminal();
    //     return 0;
    // }

    /* init user info base */
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
            int CONNECTED=0;
            while(1)
            {

                int cmd_id=0;
                if (read(client_connection, &cmd_id, sizeof(int)) <= 0)
                {
                    perror("Client disconnected \n");
                    close(client_connection);
                    return 0;
                }
                if (cmd_id == LOGIN_REQ)
                {
                    if (write(client_connection, &CONNECTED, sizeof(int)) == -1)
                    {
                       return -1;
                    }
                    if(CONNECTED == 1)
                    {
                        continue;
                    }
                    if(HandleLogin(client_connection)==0)
                    {
                        CONNECTED=1;
                    }
                    continue;
                }
                if (cmd_id == SIGNUP_REQ)
                {
                    if (write(client_connection, &CONNECTED, sizeof(int)) <= 0)
                    {
                       return -1;
                    }
                    if(CONNECTED == 1)
                    {
                        continue;
                    }
                    if(HandleSignup(client_connection) == 0)
                    {
                        CONNECTED=1;
                    }
                    continue;
                }
                if (cmd_id == INSPECT_REQ)
                {
                    if (write(client_connection, &CONNECTED, sizeof(int)) <= 0)
                    {
                       return -1;
                    }
                    if(CONNECTED == 0)
                    {
                        continue;
                    }
                    printf("User wants to ls \n");
                    Handle_ls(client_connection);
                    continue;
                }
                if(cmd_id==DISCON)
                {
                    CONNECTED=0;
                    continue;
                }
                if (cmd_id == QUIT)
                {
                    close(client_connection);
                    perror("Client disconnected \n");
                    return 0;
                }
            }
        }
        //in parent or error at fork
        close(client_connection);
    }

    return 0;
}
