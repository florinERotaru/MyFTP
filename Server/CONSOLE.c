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
#define USER_INFO_SIZE 100
#define USER_HASH_SIZE 200
char USERS_JSON[30] ="user_data.json";

struct user_record{
    char usr_hash[USER_HASH_SIZE];
    char pass_hash[USER_HASH_SIZE];
    char perm[3];
};

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

int change_perm(const char* usr_hash, char* newperm)
{
    if (strcmp(newperm, "r") !=0  && strcmp(newperm, "rw")!=0 )
    {
        printf("Invalid Permission. \n");
        exit(1);
    }
    /* lock for writing the json file */ 
    struct flock lock;
    lock.l_type   = F_RDLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start  = 0;
    lock.l_len    = 1;
    int jsnfd=open(USERS_JSON, O_RDWR);
    if(jsnfd == -1)
    {
        perror("could not open json file \n");
        return -1;
    }
    if(-1==fcntl(jsnfd, F_SETLKW, &lock))
    {
        printf("could not lock \n");
        return -1;
    }

    JSON_Value* users_info=json_parse_file(USERS_JSON);
    JSON_Value* users_array=json_value_init_array();
    users_array->value.array=json_object_get_array(json_object(users_info), "users");
    
    JSON_Value* found_user=json_value_init_object();
    int nr_of_users=json_array_get_count(users_array->value.array);
    for(int i=0; i<nr_of_users; i++)
    {
        found_user=json_array_get_value(users_array->value.array, i);
        if (
            strcmp(
                usr_hash,
                json_object_get_string(json_object(found_user), "name")
                )==0
            )
        {
            json_object_set_string(json_object(found_user),"permissions", newperm);


            users_info=json_value_init_object();
            json_object_set_value(json_object(users_info), "users", users_array);
            json_serialize_to_file_pretty(users_info, USERS_JSON);
            close(jsnfd);
            return 0;
        }
    }
    close(jsnfd);
    printf("No such user \n");
    exit(1);

}
int chartohex(char chr)     /* will return smth in [00 to FF] */
{
    if( chr>='0' && chr<='9' )
        return(chr - 48);
    else
        if( chr>='A' && chr<='F' )
            return( chr - 'A' + 10);
    return(-1);
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

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        printf("syntax: ./CONSOLE <USERNAME> <NEW_PERM> \n");
        exit(1);
    }
    change_perm( Encode(argv[1]), argv[2]);
    printf("successfully updated permissions for user %s to %s \n", argv[1], argv[2]);
    
    return 0;
}
