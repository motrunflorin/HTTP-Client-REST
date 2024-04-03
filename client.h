#ifndef CLIENT_H_
#define CLIENT_H_

#define SERV_ADDR "34.254.242.81"
#define SERV_PORT 8080
#define HOST "34.254.242.81:8080"
#define MAXLINE 1024
#define BUFLEN 4096


#define COMMANDS_COUNT 9
enum commands{
    REGISTER = 0,
    LOGIN,
    ENTER_LIBRARY,
    GET_BOOKS,
    GET_BOOK,
    ADD_BOOK,
    DELETE_BOOK,
    LOGOUT,
    EXIT
};

const char * commands_str[] = {
    [REGISTER] = "register",
    [LOGIN] = "login",
    [ENTER_LIBRARY] = "enter_library",
    [GET_BOOKS] = "get_books",
    [GET_BOOK] = "get_book",
    [ADD_BOOK] = "add_book",
    [DELETE_BOOK] = "delete_book",
    [LOGOUT] = "logout",
    [EXIT] = "exit"
};

#endif