/*
 * REQUIREMENT:
 * - OpenSSL 1.1
 *
 * RUN INSTRUCTIONS:
 *    To run this example program:
 *    0) Create certificates and key files. See ../doc/config.notes.txt for
 *       instructions. If a local/private root CA is going to be used then
 *       then it must be created first.
 *    1) Start the server program,
 *       $ run server
 *    2) Start the client program on this same system,
 *       $ run client
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
 
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
 
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
 
#define RSA_SERVER_CERT     "./ec.crt"
#define RSA_SERVER_KEY      "./ec.key"
#define RSA_SERVER_CA_CERT  "./root-ca.crt"
 
#define ON   1
#define OFF  0
 
#define RETURN_NULL(x)    if ((x)==NULL) exit(1)
#define RETURN_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define RETURN_SSL(err)   if ((err)==-1) { ERR_print_errors_fp(stderr); exit(1); }
 

int main( int c, char * a[] )
{
	int verify_client = (c > 1 && *a[1] == 'Y' )?ON:OFF; /* To verify a client certificate, set ON */
	
	short int s_port = 5555;

	/*----------------------------------------------------------------*/
	/* Load encryption & hashing algorithms for the SSL program */
	SSL_library_init();
	
	/* Load the error strings for SSL & CRYPTO APIs */
	SSL_load_error_strings();
	
	/* Create a SSL_METHOD structure (choose a SSL/TLS protocol version) */
	const SSL_METHOD * meth = TLS_method();
	
	/* Create a SSL_CTX structure */
	SSL_CTX * ctx = SSL_CTX_new(meth);
	
	int secp256k1 = NID_secp256k1;
	SSL_CTX_set1_curves( ctx, &secp256k1, 1 );

	if (!ctx) 
	{
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	
	/* Load the server certificate into the SSL_CTX structure */
	if (SSL_CTX_use_certificate_file(ctx, RSA_SERVER_CERT, SSL_FILETYPE_PEM) <= 0) 
	{
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	
	/* Load the private-key corresponding to the server certificate */
	if (SSL_CTX_use_PrivateKey_file(ctx, RSA_SERVER_KEY, SSL_FILETYPE_PEM) <= 0) 
	{
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	
	/* Check if the server certificate and private-key matches */
	if (!SSL_CTX_check_private_key(ctx)) 
	{
		fprintf(stderr,"Private key does not match the certificate public key\n");
		exit(1);
	}
	
	if(verify_client == ON)
	{
		/* Load the RSA CA certificate into the SSL_CTX structure */
		if (!SSL_CTX_load_verify_locations(ctx, RSA_SERVER_CA_CERT, NULL)) 
		{
			ERR_print_errors_fp(stderr);
			exit(1);
		}
	
		/* Set to require peer (client) certificate verification */
		SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
	
		/* Set the verification depth to 1 */
		SSL_CTX_set_verify_depth(ctx,1);
	}

	/* Set up a TCP socket */
	int listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);   
	
	RETURN_ERR(listen_sock, "socket");

	struct sockaddr_in sa_serv;

	memset (&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family      = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port        = htons (s_port);          /* Server Port number */

	int err = bind(listen_sock, (struct sockaddr*)&sa_serv,sizeof(sa_serv));
	
	RETURN_ERR(err, "bind");
	
	/* Wait for an incoming TCP connection. */
	err = listen(listen_sock, 5);                    
	
	RETURN_ERR(err, "listen");

	struct sockaddr_in sa_cli;
	socklen_t client_len = sizeof(sa_cli);
	
	/* Socket for a TCP/IP connection is created */
	int sock = accept(listen_sock, (struct sockaddr*)&sa_cli, &client_len);
	
	RETURN_ERR(sock, "accept");
	close (listen_sock);
	
	printf ("Connection from %x, port %x\n", sa_cli.sin_addr.s_addr, sa_cli.sin_port);
	
	/* TCP connection is ready. */
	/* A SSL structure is created */
	SSL * ssl = SSL_new(ctx);
	
	RETURN_NULL(ssl);
	
	/* Assign the socket into the SSL structure (SSL and socket without BIO) */
	SSL_set_fd(ssl, sock);
	
	/* Perform SSL Handshake on the SSL server */
	err = SSL_accept(ssl);
	
	RETURN_SSL(err);
	
	/* Informational output (optional) */
	printf("SSL connection using %s\n", SSL_get_cipher (ssl));
	
	if (verify_client == ON)
	{
		/* Get the client's certificate (optional) */
		X509 * client_cert = SSL_get_peer_certificate(ssl);

		if (client_cert != NULL) 
		{
			printf ("Client certificate:\n");     

			char * str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
			RETURN_NULL(str);

			printf ("\t subject: %s\n", str);
			free (str);
			str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
			RETURN_NULL(str);

			printf ("\t issuer: %s\n", str);
			free (str);
			X509_free(client_cert);
		} 
		else
			printf("The SSL client does not have certificate.\n");
	}
	
	/*------- DATA EXCHANGE - Receive message and send reply. -------*/
	while(true)
	{
		char buf[4096];

		err = SSL_read(ssl, buf, sizeof(buf) - 1);
		RETURN_SSL(err);
	
		if(err == 0 )
			break;

		buf[err] = '\0';
		printf ("Received %d chars:'%s'\n", err, buf);
	
		/* Send data to the SSL client */
		err = SSL_write(ssl, "This message is from the SSL server", 
	
		strlen("This message is from the SSL server"));
	
		RETURN_SSL(err);
	}
	
	/*--------------- SSL closure ---------------*/
	err = SSL_shutdown(ssl);
	RETURN_SSL(err);
	
	err = close(sock);
	RETURN_ERR(err, "close");
	
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	
	return 0;
}
