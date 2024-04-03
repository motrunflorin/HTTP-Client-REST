# HTTP Client application
## Main Functionality:

    Starting from the code provided in the HTTP laboratory, modifying it
    by adding the **compute_delete_request()** which is 99% the same with
    **compute_get_request()**, the only difference being the keyword
    in the request changing from _GET_ to _DELETE_. Apart from this the only
    files I implemented are client.h, holding the enum for commands and useful
    macros, and client.c.

## Request generation procedure:

    In order to generate a request we need to parse a command from the terminal,
    find what command we are dealing with using the enum and then switch through
    the command indexes/codes in order to read the required data (if needed),
    compute the request using the functions in requests.c/.h and try and send
    it to the server. One issue is the TTL the server provides for the connection,
    only 5 seconds. This is raising a problem when trying to send after the server
    closed the connection. Through debugging I noticed that the server sends an empty
    string when the connection has been closed, so if during the sending process
    the response is an empty string, the connection is reopened and the request is 
    resent.

## Data reading and validation:
    
    Data is being read from STIND using the read function. All the buffers/char arrays
    are memset to 0 beforehand. The trailing '\n' is being removed and then the data
    tested for conformity. It is then added to a JSON variable using parson and sent
    to the request generating functions.

## Useful information:

    All the commands have been implemented. I have tried my best to test the code
    in any way, shape or form in order to make sure that there are no bugs or
    security slips present. All the restrictions from the homework paper are in
    place. No memory leaks have been identified during testing.
    I have used parson for JSON manipulation. All messages provided by the server
    that have a JSON attatched to them are being printed into the terminal as is
    (as a JSON).