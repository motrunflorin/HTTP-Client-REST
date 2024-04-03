#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <poll.h>

// locals
#include "helpers.h"
#include "requests.h"
#include "parson.h"
#include "buffer.h"
#include "client.h"

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, BUFSIZ);

    int sockfd;
    char buffer[MAXLINE];
    char *cookie = calloc(BUFLEN, sizeof(char));
    char *jwt = calloc(BUFLEN, sizeof(char));

    sockfd = open_connection(SERV_ADDR, SERV_PORT, AF_INET, SOCK_STREAM, 0);

    // create a pollfd struct
    struct pollfd fds[2];
    fds[0].fd = sockfd;
    fds[0].events = POLLIN;
    fds[1].fd = STDIN_FILENO;
    fds[1].events = POLLIN;

    // poll for input
    while (1)
    {
        poll(fds, 2, -1);

        // if there is input from the server
        if (fds[0].revents & POLLIN)
        {
            // server closed connection
            // reconnect
            close(sockfd);
            sockfd = open_connection(SERV_ADDR, SERV_PORT, AF_INET, SOCK_STREAM, 0);
            // add the socket to the pollfd struct
            fds[0].fd = sockfd;
            fds[0].events = POLLIN;
        }

        // if there is input from stdin
        if (fds[1].revents & POLLIN)
        {
            // read from stdin
            memset(buffer, 0, MAXLINE);
            if (read(STDIN_FILENO, buffer, MAXLINE) < 0)
            {
                perror("read");
                continue;
            }
            // remove the newline
            buffer[strlen(buffer) - 1] = '\0';

            // find the command in the commands_str array
            char *command = strtok(buffer, " ");
            int command_index = -1;
            for (int i = 0; i < COMMANDS_COUNT; i++)
            {
                if (strcmp(command, commands_str[i]) == 0)
                {
                    command_index = i;
                    break;
                }
            }
            if (command_index == -1)
            {
                printf("Invalid command\n");
                continue;
            }

            // switch on the command
            // 0 - register, 1 - login, 2 - enter_library
            // 3 - get_books, 4 - get_book, 5 - add_book
            // 6 - delete_book, 7 - logout, 8 - exit
            switch (command_index)
            {
            case 0:
            {
                if (strcmp(cookie, "") != 0)
                {
                    printf("You are already logged in\n");
                    break;
                }
                // register
                char username[BUFLEN];
                char password[BUFLEN];
                memset(username, 0, BUFLEN);
                memset(password, 0, BUFLEN);

                printf("username=");
                if (read(STDIN_FILENO, username, BUFLEN) < 0)
                {
                    perror("read");
                    break;
                }
                printf("password=");
                if (read(STDIN_FILENO, password, BUFLEN) < 0)
                {
                    perror("read");
                    break;
                }
                if (strlen(username) == 0 || strlen(password) == 0)
                {
                    printf("Empty username or password\n");
                    break;
                }
                username[strlen(username) - 1] = '\0';
                password[strlen(password) - 1] = '\0';
                if (strchr(username, ' ') != NULL || strchr(password, ' ') != NULL)
                {
                    printf("Username and password cannot contain spaces\n");
                    break;
                }

                char *body_data = calloc(BUFLEN, sizeof(char));
                sprintf(body_data, "{\"username\":\"%s\",\"password\":\"%s\"}", username, password);

                char *message = compute_post_request(SERV_ADDR, "/api/v1/tema/auth/register", "application/json", &body_data, 1, NULL, 0, NULL, 0);
                send_to_server(sockfd, message);

                char *response = receive_from_server(sockfd);

                if (strcmp(response, "") == 0)
                {
                    free(response);
                    close(sockfd);
                    sockfd = open_connection(SERV_ADDR, SERV_PORT, AF_INET, SOCK_STREAM, 0);
                    // add the socket to the pollfd struct
                    fds[0].fd = sockfd;
                    fds[0].events = POLLIN;

                    send_to_server(sockfd, message);

                    response = receive_from_server(sockfd);
                }
                else if (strstr(response, "HTTP/1.1 400 Bad Request"))
                {
                    JSON_Value *json_value = json_parse_string(strstr(response, "{"));
                    if (json_value == NULL)
                    {
                        printf("Invalid JSON\n");
                        break;
                    }
                    char *error_message = json_serialize_to_string_pretty(json_value);
                    printf("%s\n", error_message);
                    free(json_value);
                    free(error_message);
                }
                else
                {
                    printf("Registered successfully\n");
                }
                free(body_data);
                free(message);
                free(response);
                break;
            }
            case 1:
            {
                if (strcmp(cookie, "") != 0)
                {
                    printf("You are already logged in\n");
                    break;
                }
                // login
                char username[BUFLEN];
                char password[BUFLEN];
                memset(username, 0, BUFLEN);
                memset(password, 0, BUFLEN);

                printf("username=");
                if (read(STDIN_FILENO, username, BUFLEN) < 0)
                {
                    perror("read");
                    exit(EXIT_FAILURE);
                }
                printf("password=");
                if (read(STDIN_FILENO, password, BUFLEN) < 0)
                {
                    perror("read");
                    exit(EXIT_FAILURE);
                }
                if (strlen(username) == 0 || strlen(password) == 0)
                {
                    printf("Empty username or password\n");
                    break;
                }
                username[strlen(username) - 1] = '\0';
                password[strlen(password) - 1] = '\0';
                if (strchr(username, ' ') != NULL || strchr(password, ' ') != NULL)
                {
                    printf("Username and password cannot contain spaces\n");
                    break;
                }

                char *body_data = calloc(BUFLEN, sizeof(char));
                sprintf(body_data, "{\"username\":\"%s\",\"password\":\"%s\"}", username, password);

                char *message = compute_post_request(SERV_ADDR, "/api/v1/tema/auth/login", "application/json", &body_data, 1, NULL, 0, NULL, 0);
                send_to_server(sockfd, message);

                char *response = receive_from_server(sockfd);

                if (strcmp(response, "") == 0)
                {
                    free(response);
                    close(sockfd);
                    sockfd = open_connection(SERV_ADDR, SERV_PORT, AF_INET, SOCK_STREAM, 0);
                    // add the socket to the pollfd struct
                    fds[0].fd = sockfd;
                    fds[0].events = POLLIN;

                    send_to_server(sockfd, message);

                    response = receive_from_server(sockfd);
                }
                else if (strstr(response, "HTTP/1.1 400 Bad Request"))
                {
                    JSON_Value *json_value = json_parse_string(strstr(response, "{"));
                    if (json_value == NULL)
                    {
                        printf("Invalid JSON\n");
                        break;
                    }
                    char *error_message = json_serialize_to_string_pretty(json_value);

                    free(json_value);
                    free(error_message);
                    printf("%s\n", error_message);
                }
                else
                {
                    // get session cookie
                    char *cookie_start = strstr(response, "connect.sid");
                    char *cookie_end = strstr(cookie_start, ";");
                    strncpy(cookie, cookie_start, cookie_end - cookie_start);
                    cookie[cookie_end - cookie_start] = '\0';

                    printf("Logged in successfully\n");
                }

                free(body_data);
                free(message);
                free(response);
                break;
            }
            case 2:
            {
                // enter library
                if (strcmp(cookie, "") == 0)
                {
                    printf("You are not logged in\n");
                    break;
                }
                if (strcmp(jwt, "") != 0)
                {
                    printf("You are already in the library\n");
                }
                char *message = compute_get_request(SERV_ADDR, "/api/v1/tema/library/access", NULL, cookie, 1, NULL, 0);
                send_to_server(sockfd, message);

                char *response = receive_from_server(sockfd);

                if (strcmp(response, "") == 0)
                {
                    free(response);
                    close(sockfd);
                    sockfd = open_connection(SERV_ADDR, SERV_PORT, AF_INET, SOCK_STREAM, 0);
                    // add the socket to the pollfd struct
                    fds[0].fd = sockfd;
                    fds[0].events = POLLIN;

                    send_to_server(sockfd, message);

                    response = receive_from_server(sockfd);
                }
                else if (strstr(response, "HTTP/1.1 400 Bad Request"))
                {
                    JSON_Value *json_value = json_parse_string(strstr(response, "{"));
                    if (json_value == NULL)
                    {
                        printf("Invalid JSON\n");
                        break;
                    }
                    char *error_message = json_serialize_to_string_pretty(json_value);

                    free(json_value);
                    free(error_message);
                    printf("%s\n", error_message);
                }
                else
                {
                    // get jwt
                    char *jwt_start = strstr(response, "token\":\"");
                    char *jwt_end = strstr(jwt_start, "}");
                    strncpy(jwt, jwt_start + 8, jwt_end - jwt_start + 8);
                    jwt[strlen(jwt) - 2] = '\0'; // remove last "} from jwt

                    printf("Entered library successfully\n");
                }

                free(message);
                free(response);
                break;
            }
            case 3:
            {
                if (strcmp(cookie, "") == 0)
                {
                    printf("You are not logged in\n");
                    break;
                }
                if (strcmp(jwt, "") == 0)
                {
                    printf("You are not in the library\n");
                    break;
                }
                // get books
                char *message = compute_get_request(SERV_ADDR, "/api/v1/tema/library/books", NULL, cookie, 1, jwt, 1);
                send_to_server(sockfd, message);

                char *response = receive_from_server(sockfd);
                if (strcmp(response, "") == 0)
                {
                    free(response);
                    close(sockfd);
                    sockfd = open_connection(SERV_ADDR, SERV_PORT, AF_INET, SOCK_STREAM, 0);
                    // add the socket to the pollfd struct
                    fds[0].fd = sockfd;
                    fds[0].events = POLLIN;

                    send_to_server(sockfd, message);

                    response = receive_from_server(sockfd);
                }
                JSON_Value *json_value = json_parse_string(strstr(response, "["));
                if (json_value == NULL)
                {
                    printf("Invalid JSON\n");
                    break;
                }
                char *books_json = json_serialize_to_string_pretty(json_value);

                printf("%s\n", books_json);

                json_value_free(json_value);
                json_free_serialized_string(books_json);
                free(response);
                free(message);
                break;
            }
            case 4:
            {
                if (strcmp(cookie, "") == 0)
                {
                    printf("You are not logged in\n");
                    break;
                }
                if (strcmp(jwt, "") == 0)
                {
                    printf("You are not in the library\n");
                    break;
                }
                // get book
                char id[BUFLEN];
                memset(id, 0, BUFLEN);

                printf("id=");
                if (read(0, id, BUFLEN) < 0)
                {
                    perror("read");
                    exit(EXIT_FAILURE);
                }
                if (strlen(id) == 0)
                {
                    printf("Invalid id\n");
                    break;
                }
                id[strlen(id) - 1] = '\0';
                if (strspn(id, "0123456789") != strlen(id))
                {
                    printf("Invalid id\n");
                    break;
                }

                char *message = compute_get_request(SERV_ADDR, "/api/v1/tema/library/books/", id, cookie, 1, jwt, 1);
                send_to_server(sockfd, message);

                char *response = receive_from_server(sockfd);
                if (strcmp(response, "") == 0)
                {
                    free(response);
                    close(sockfd);
                    sockfd = open_connection(SERV_ADDR, SERV_PORT, AF_INET, SOCK_STREAM, 0);
                    // add the socket to the pollfd struct
                    fds[0].fd = sockfd;
                    fds[0].events = POLLIN;

                    send_to_server(sockfd, message);

                    response = receive_from_server(sockfd);
                }
                JSON_Value *json_value = json_parse_string(strstr(response, "{"));
                if (json_value == NULL)
                {
                    printf("Invalid JSON\n");
                    break;
                }
                char *book_json = json_serialize_to_string_pretty(json_value);

                printf("%s\n", book_json);

                json_value_free(json_value);
                json_free_serialized_string(book_json);
                free(response);
                free(message);
                break;
            }
            case 5:
            {
                if (strcmp(cookie, "") == 0)
                {
                    printf("You are not logged in\n");
                    break;
                }
                if (strcmp(jwt, "") == 0)
                {
                    printf("You are not in the library\n");
                    break;
                }

                // add book
                char title[BUFLEN], author[BUFLEN], genre[BUFLEN], publisher[BUFLEN], page_count[BUFLEN];
                memset(title, 0, BUFLEN);
                memset(author, 0, BUFLEN);
                memset(genre, 0, BUFLEN);
                memset(publisher, 0, BUFLEN);
                memset(page_count, 0, BUFLEN);

                printf("title=");
                if (read(0, title, BUFLEN) < 0)
                {
                    perror("read");
                    exit(EXIT_FAILURE);
                }
                printf("author=");
                if (read(0, author, BUFLEN) < 0)
                {
                    perror("read");
                    exit(EXIT_FAILURE);
                }
                printf("genre=");
                if (read(0, genre, BUFLEN) < 0)
                {
                    perror("read");
                    exit(EXIT_FAILURE);
                }
                printf("publisher=");
                if (read(0, publisher, BUFLEN) < 0)
                {
                    perror("read");
                    exit(EXIT_FAILURE);
                }
                printf("page_count=");
                if (read(0, page_count, BUFLEN) < 0)
                {
                    perror("read");
                    exit(EXIT_FAILURE);
                }
                title[strlen(title) - 1] = '\0';
                author[strlen(author) - 1] = '\0';
                genre[strlen(genre) - 1] = '\0';
                publisher[strlen(publisher) - 1] = '\0';
                page_count[strlen(page_count) - 1] = '\0';
                if (strlen(title) == 0 || strlen(author) == 0 || strlen(genre) == 0 || strlen(publisher) == 0 || strlen(page_count) == 0)
                {
                    printf("Invalid book\n");
                    break;
                }
                if (strspn(page_count, "0123456789") != strlen(page_count))
                {
                    printf("Invalid page_count\n");
                    break;
                }

                // create json
                JSON_Value *json_value = json_value_init_object();
                JSON_Object *json_object = json_value_get_object(json_value);
                json_object_set_string(json_object, "title", title);
                json_object_set_string(json_object, "author", author);
                json_object_set_string(json_object, "genre", genre);
                json_object_set_string(json_object, "publisher", publisher);
                json_object_set_number(json_object, "page_count", atoi(page_count));
                char *book_json = json_serialize_to_string_pretty(json_value);

                char *message = compute_post_request(SERV_ADDR, "/api/v1/tema/library/books", "application/json", &book_json, strlen(book_json), cookie, 1, jwt, 1);
                send_to_server(sockfd, message);

                char *response = receive_from_server(sockfd);

                if (strcmp(response, "") == 0)
                {
                    free(response);
                    close(sockfd);
                    sockfd = open_connection(SERV_ADDR, SERV_PORT, AF_INET, SOCK_STREAM, 0);
                    // add the socket to the pollfd struct
                    fds[0].fd = sockfd;
                    fds[0].events = POLLIN;

                    send_to_server(sockfd, message);

                    response = receive_from_server(sockfd);
                }

                if (strstr(response, "200 OK") == NULL)
                {
                    printf("Invalid book\n");
                    json_value_free(json_value);
                    json_free_serialized_string(book_json);
                    free(response);
                    free(message);
                    break;
                }
                printf("Book added successfully\n");
                json_value_free(json_value);
                json_free_serialized_string(book_json);
                free(response);
                free(message);
                break;
            }
            case 6:
            {
                if (strcmp(cookie, "") == 0)
                {
                    printf("You are not logged in\n");
                    break;
                }
                if (strcmp(jwt, "") == 0)
                {
                    printf("You are not in the library\n");
                    break;
                }
                // get book
                char id[BUFLEN];
                memset(id, 0, BUFLEN);

                printf("id=");
                if (read(0, id, BUFLEN) < 0)
                {
                    perror("read");
                    exit(EXIT_FAILURE);
                }
                if (strlen(id) == 0)
                {
                    printf("Invalid id\n");
                    break;
                }
                id[strlen(id) - 1] = '\0';
                if (strspn(id, "0123456789") != strlen(id))
                {
                    printf("Invalid id\n");
                    break;
                }
                char *message = compute_delete_request(SERV_ADDR, "/api/v1/tema/library/books/", id, cookie, 1, jwt, 1);
                send_to_server(sockfd, message);

                char *response = receive_from_server(sockfd);
                if (strcmp(response, "") == 0)
                {
                    free(response);
                    close(sockfd);
                    sockfd = open_connection(SERV_ADDR, SERV_PORT, AF_INET, SOCK_STREAM, 0);
                    // add the socket to the pollfd struct
                    fds[0].fd = sockfd;
                    fds[0].events = POLLIN;

                    send_to_server(sockfd, message);

                    response = receive_from_server(sockfd);
                }
                if (strstr(response, "200 OK") == NULL)
                {
                    printf("Invalid id\n");
                    free(response);
                    free(message);
                    break;
                }

                printf("Book deleted successfully\n");
                free(response);
                free(message);
                break;
            }
            case 7:
            {
                if(strcmp(cookie, "") == 0)
                {
                    printf("You are not logged in\n");
                    break;
                }
                memset(cookie, 0, BUFLEN);
                memset(jwt, 0, BUFLEN);
                printf("You have been logged out\n");
                break;
            }
            case 8:
            {
                // exit
                printf("Exiting...\n");
                free(cookie);
                free(jwt);
                close(sockfd);
                return 0;
            }
            }
        }
    }
    return 0;
}