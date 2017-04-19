#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pkcs12.h> // For that p12 file format

#include <stdio.h>
#include <unistd.h>

#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

#define MAXDATASIZE 512

int create_socket (char *host, char *port) {

    struct addrinfo hints, *servinfo, *p;
    int rc, tcpfd;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // Can be IPV4 or IPV6
    hints.ai_socktype = SOCK_STREAM; // TCP connection
    hints.ai_flags = AI_PASSIVE; // assign address of local host to the socket

    // Get host server info
    if ((rc = getaddrinfo(host, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo Error: %s\n", gai_strerror(rc));
        return -1;
    }

    // loop through the resulting linked list and connect to whichever socket
    // we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((tcpfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("TCP: socket");
            continue;
        }

        if (connect(tcpfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(tcpfd);
            perror("TCP: connect");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "TCP: failed to connect\n");
        return -1;
    }
    
    return tcpfd;
}

int init_openssl (BIO *inputbio, BIO *outputbio) {

    /* initialize openssl */    
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

    /* Initialize the input and output bios */
    inputbio = BIO_new(BIO_s_file());
    outputbio = BIO_new_fp(stdout, BIO_NOCLOSE);
    
    /*initialize SSL*/
    if(SSL_library_init() < 0) {
        BIO_printf(outputbio, "Error: Could not initialize openssl\n");
        return -1;
    }
    
    return 0;

}


int create_context (SSL_CTX *context, char *certificateFile, char *keyFile) {
    
    /* Use ssl3 for encryption */
    const SSL_METHOD *method = SSLv3_method();
    
    /*Create context*/
    if ((context = SSL_CTX_new(method)) == NULL) {
        fprintf(stderr, "Error: Could not create context\n");
        return -1;
    }
    
    /* Load certificate into the context */
    if (SSL_CTX_use_certificate_file (context, certificateFile, SSL_FILETYPE_PEM) 
            <= 0) {
        fprintf (stderr, "Error: could not load certificate file\n");
        return -1;
    }
    
    /* Load the private key */
    if (SSL_CTX_use_PrivateKey_file (context, keyFile, SSL_FILETYPE_PEM) <= 0) {
        fprintf (stderr, "Error: private key could not be loaded\n");
        return -1;
    }
    
    return 0;
}

int main () {

    char *host = "https://debatedecide.fit.edu";
    char *certificateFile = "cert_public.pem";
    char *keyFile = "private.pem";

    BIO *inputbio = NULL;
    BIO *outputbio = NULL;
    X509 *certificate = NULL;
    X509_NAME *certificateName = NULL;
    
    SSL_CTX *context;
    SSL *ssl;
    int server = 0;
    int rc, i, tcpfd;
    
    /* initialize openssl local method*/
    if (init_openssl (inputbio, outputbio) < 0)
        exit (1);
        
    /* create context with client certificate local method */
    if (create_context (context, certificateFile, keyFile) < 0)
        exit (1);
    
        
    /* Create new SSL connection state object */
    ssl = SSL_new(context);
    
    /* open up a regular socket */
    if ((tcpfd = create_socket(host, "8080")) <= 0) {
        BIO_printf(outputbio, "Error: Failed TCP connection\n");
        exit (1);
    }

    /* Attach the SSL session to the socket descriptor */
    SSL_set_fd(ssl, tcpfd);
    
    if ( SSL_connect(ssl) != 1 )
        BIO_printf(outputbio, "Error: Could not build a SSL session\n");
    else
        BIO_printf(outputbio, "Successfully established SSL session to: %s.\n", host);
  
   /* Get the remote certificate into the X509 structure */
    certificate = SSL_get_peer_certificate(ssl);
    
    if (certificate == NULL)
        BIO_printf(outputbio, "Error: Could not get a certificate from host.\n");
    else
        BIO_printf(outputbio, "Retrieved the server's certificate.\n");

    /* get certificates */
    certificateName = X509_NAME_new();
    certificateName = X509_get_subject_name (certificate);
    
    BIO_printf(outputbio, "Displaying the certificate subject data:\n");
    X509_NAME_print_ex(outputbio, certificateName, 0, 0);
    BIO_printf(outputbio, "\n");
  
    //bio = BIO_new_connect ("https://debatedecide.fit.edu/proposals.php?organizationID=376&msg=&secure=on:80");
    
    SSL_CTX_free (context);
    SSL_shutdown (ssl);

}

