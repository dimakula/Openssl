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
    
    printf ("Connection established\n");
    return tcpfd;
}

int main () {

    char wbuf[1000]="GET /index.html HTTP/1.1\n\n";
    
    char *host = "163.118.78.40";
    char *port = "443";
    char *certificateFile = "cert_public.pem";
    char *keyFile = "private.pem";

    BIO *inputbio = NULL;
    BIO *outputbio = NULL;
    X509 *certificate = NULL;
    X509_NAME *certificateName = NULL;
    
    SSL_CTX *context = NULL;
    SSL *ssl;
    int server = 0;
    int rc, i, tcpfd;
    
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
        exit (1);
    }
    
    /* Use ssl2 or ssl3 for encryption */
    const SSL_METHOD *method = SSLv23_client_method();

    /*Create context*/
    if ((context = SSL_CTX_new(method)) == NULL) {
        fprintf(stderr, "Error: Could not create context\n");
        exit (1);
    }
    
    /* disable ssl2 */
    SSL_CTX_set_options(context, SSL_OP_NO_SSLv2);
    
    /* Load certificate into the context */
    if (SSL_CTX_use_certificate_file (context, certificateFile, SSL_FILETYPE_PEM) 
            <= 0) {
        fprintf (stderr, "Error: could not load certificate file\n");
        exit (1);
    }
    
    /* Load the private key */
    if (SSL_CTX_use_PrivateKey_file (context, keyFile, SSL_FILETYPE_PEM) <= 0) {
        fprintf (stderr, "Error: private key could not be loaded\n");
        exit (1);
    }
     
    /* Create new SSL connection state object */
    ssl = SSL_new(context);
    
    /* open up a regular socket */
    if ((tcpfd = create_socket(host, port)) <= 0) {
        BIO_printf(outputbio, "Error: Failed TCP connection\n");
        exit (1);
    }

    /* Attach the SSL session to the socket descriptor */
    SSL_set_fd(ssl, tcpfd);
    
    if ( SSL_connect(ssl) != 1 )
        BIO_printf(outputbio, "Error: Could not build a SSL session\n");
    else
        BIO_printf(outputbio, "Successfully established SSL session to: %s.\n", host);
  
    SSL_set_connect_state(ssl);
   
    /* Get the remote certificate into the X509 structure */
    certificate = SSL_get_peer_certificate(ssl);
    if (certificate == NULL)
        BIO_printf(outputbio, "Error: Could not get a certificate from host.\n");
    else
        BIO_printf(outputbio, "Retrieved the server's certificate.\n");

    SSL_write(ssl, wbuf, strlen(wbuf));
    
    /* get certificates */
    certificateName = X509_NAME_new();
    certificateName = X509_get_subject_name (certificate);
    
    BIO_printf(outputbio, "Displaying the certificate subject data:\n");
    X509_NAME_print_ex(outputbio, certificateName, 0, 0);
    BIO_printf(outputbio, "\n");
  
    /* Write GET request */
    rc = SSL_write(ssl, wbuf, strlen(wbuf));
    if(rc <= 0) 
        printf("%d: %s\n", SSL_get_error(ssl, rc), ERR_error_string(rc, NULL));
    
    if (SSL_read(ssl, wbuf, sizeof(wbuf)-1) <= 0)
        BIO_printf (outputbio, "Mission failed, we'll get them next time\n");
    
    else
        printf ("%s\n", wbuf);
    
    BIO_printf(outputbio, "Finished connection\n");
    
    /* free resources */
    SSL_CTX_free (context);
    SSL_free (ssl);
    close (tcpfd);
    X509_free(certificate);
    BIO_free (outputbio);
    BIO_free (inputbio);
    return 0;
}

