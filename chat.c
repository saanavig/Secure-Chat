#include <gtk/gtk.h>
#include <glib/gunicode.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <getopt.h>
#include "dh.h"

#include "keys.h"
#include "util.h"

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 256
#endif

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

#define SYMM_KEY_LEN 32
unsigned char shared_key[SYMM_KEY_LEN] = {0};

static GtkTextBuffer* tbuf;
static GtkTextBuffer* mbuf;
static GtkTextView*  tview;
static GtkTextMark*   mark;

static pthread_t trecv;
void* recvMsg(void*);

#define max(a, b) \
	({ typeof(a) _a = a; \
		typeof(b) _b = b; \
		_a > _b ? _a : _b; })

static int listensock, sockfd;
static int isclient = 1;

static void error(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

int encrypt_message(const unsigned char *plaintext, int plaintext_len,
                    const unsigned char *key, unsigned char *iv,
                    unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        return -1;

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        return -1;
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        return -1;
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int decrypt_message(const unsigned char *ciphertext, int ciphertext_len,
                    const unsigned char *key, const unsigned char *iv,
                    unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        return -1;

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        return -1;
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        return -1;
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int initServerNet(int port)
{
	int reuse = 1;
	struct sockaddr_in serv_addr;
	listensock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	if (listensock < 0)
		error("ERROR opening socket");
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);
	if (bind(listensock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR on binding");
	fprintf(stderr, "listening on port %i...\n",port);
	listen(listensock,1);
	socklen_t clilen;
	struct sockaddr_in  cli_addr;
	sockfd = accept(listensock, (struct sockaddr *) &cli_addr, &clilen);
	if (sockfd < 0)
		error("error on accept");
	close(listensock);
	fprintf(stderr, "connection made, starting session...\n");
	return 0;
}

static int initClientNet(char* hostname, int port)
{
	struct sockaddr_in serv_addr;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	struct hostent *server;
	if (sockfd < 0)
		error("ERROR opening socket");
	server = gethostbyname(hostname);
	if (server == NULL) {
		fprintf(stderr,"ERROR, no such host\n");
		exit(0);
	}
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);
	serv_addr.sin_port = htons(port);
	if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)
		error("ERROR connecting");
	return 0;
}

static int shutdownNetwork()
{
	shutdown(sockfd,2);
	unsigned char dummy[64];
	ssize_t r;
	do {
		r = recv(sockfd,dummy,64,0);
	} while (r != 0 && r != -1);
	close(sockfd);
	return 0;
}

static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Secure chat (CCNY computer security project).\n\n"
"   -c, --connect HOST  Attempt a connection to HOST.\n"
"   -l, --listen        Listen for new connections.\n"
"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
"   -h, --help          show this message and exit.\n";

static void tsappend(char* message, char** tagnames, int ensurenewline)
{
	GtkTextIter t0;
	gtk_text_buffer_get_end_iter(tbuf,&t0);
	size_t len = g_utf8_strlen(message,-1);
	if (ensurenewline && message[len-1] != '\n')
		message[len++] = '\n';
	gtk_text_buffer_insert(tbuf,&t0,message,len);
	GtkTextIter t1;
	gtk_text_buffer_get_end_iter(tbuf,&t1);
	t0 = t1;
	gtk_text_iter_backward_chars(&t0,len);
	if (tagnames) {
		char** tag = tagnames;
		while (*tag) {
			gtk_text_buffer_apply_tag_by_name(tbuf,*tag,&t0,&t1);
			tag++;
		}
	}
	if (!ensurenewline) return;
	gtk_text_buffer_add_mark(tbuf,mark,&t1);
	gtk_text_view_scroll_to_mark(tview,mark,0.0,0,0.0,0.0);
	gtk_text_buffer_delete_mark(tbuf,mark);
}

static void sendMessage(GtkWidget* w, gpointer)
{
	char* tags[2] = {"self",NULL};
	tsappend("me: ",tags,0);
	GtkTextIter mstart;
	GtkTextIter mend;
	gtk_text_buffer_get_start_iter(mbuf,&mstart);
	gtk_text_buffer_get_end_iter(mbuf,&mend);
	char* message = gtk_text_buffer_get_text(mbuf,&mstart,&mend,1);
	size_t len = g_utf8_strlen(message,-1);

	unsigned char iv[16];
	unsigned char ciphertext[1024];
	RAND_bytes(iv, sizeof(iv));

	int ciphertext_len = encrypt_message((unsigned char *)message, len, shared_key, iv, ciphertext);

	if (ciphertext_len == -1) {
		fprintf(stderr, "Encryption failed\n");
		return;
	}

	unsigned char to_send[16 + ciphertext_len];
	memcpy(to_send, iv, 16);
	memcpy(to_send + 16, ciphertext, ciphertext_len);

	ssize_t nbytes = send(sockfd, to_send, sizeof(to_send), 0);
	if (nbytes == -1)
		error("send failed");

	tsappend(message,NULL,1);
	free(message);
	gtk_text_buffer_delete(mbuf,&mstart,&mend);
	gtk_widget_grab_focus(w);
}

static gboolean shownewmessage(gpointer msg)
{
	char* tags[2] = {"friend",NULL};
	char* friendname = "mr. friend: ";
	tsappend(friendname,tags,0);
	char* message = (char*)msg;
	tsappend(message,NULL,1);
	free(message);
	return 0;
}

void perform_key_exchange(int is_client);

int main(int argc, char *argv[])
{
	if (init("params") != 0) {
		fprintf(stderr, "could not read DH params from file 'params'\n");
		return 1;
	}
	static struct option long_opts[] = {
		{"connect",  required_argument, 0, 'c'},
		{"listen",   no_argument,       0, 'l'},
		{"port",     required_argument, 0, 'p'},
		{"help",     no_argument,       0, 'h'},
		{0,0,0,0}
	};
	char c;
	int opt_index = 0;
	int port = 1337;
	char hostname[HOST_NAME_MAX+1] = "localhost";
	hostname[HOST_NAME_MAX] = 0;

	while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'c':
				if (strnlen(optarg,HOST_NAME_MAX))
					strncpy(hostname,optarg,HOST_NAME_MAX);
				break;
			case 'l':
				isclient = 0;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'h':
				printf(usage,argv[0]);
				return 0;
			case '?':
				printf(usage,argv[0]);
				return 1;
		}
	}

	if (isclient) 
	{
		initClientNet(hostname,port);
	}
	else
	{
		initServerNet(port);
	}
	perform_key_exchange(isclient);


	GtkBuilder* builder;
	GObject* window;
	GObject* button;
	GObject* transcript;
	GObject* message;
	GError* error = NULL;
	gtk_init(&argc, &argv);
	builder = gtk_builder_new();
	if (gtk_builder_add_from_file(builder,"layout.ui",&error) == 0) 
	{
		g_printerr("Error reading %s\n", error->message);
		g_clear_error(&error);
		return 1;
	}

	mark  = gtk_text_mark_new(NULL,TRUE);
	window = gtk_builder_get_object(builder,"window");
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);

	transcript = gtk_builder_get_object(builder, "transcript");
	tview = GTK_TEXT_VIEW(transcript);

	message = gtk_builder_get_object(builder, "message");
	tbuf = gtk_text_view_get_buffer(tview);
	mbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(message));

	button = gtk_builder_get_object(builder, "send");
	g_signal_connect_swapped(button, "clicked", G_CALLBACK(sendMessage), GTK_WIDGET(message));
	gtk_widget_grab_focus(GTK_WIDGET(message));
	GtkCssProvider* css = gtk_css_provider_new();

	gtk_css_provider_load_from_path(css,"colors.css",NULL);
	gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
			GTK_STYLE_PROVIDER(css),
			GTK_STYLE_PROVIDER_PRIORITY_USER);

	gtk_text_buffer_create_tag(tbuf,"status","foreground","#657b83","font","italic",NULL);
	gtk_text_buffer_create_tag(tbuf,"friend","foreground","#6c71c4","font","bold",NULL);
	gtk_text_buffer_create_tag(tbuf,"self","foreground","#268bd2","font","bold",NULL);

	if (pthread_create(&trecv,0,recvMsg,0)) {
		fprintf(stderr, "Failed to create update thread.\n");
	}

	gtk_main();
	shutdownNetwork();
	return 0;
}

void perform_key_exchange(int is_client)
{
    dhKey long_term, eph;
    dhKey peer_long_term, peer_eph;
    initKey(&long_term);
    initKey(&eph);
    initKey(&peer_long_term);
    initKey(&peer_eph);

    const char* my_priv = is_client ? "client_rsa.pem" : "server_rsa.pem";
    const char* peer_pub = is_client ? "server_rsa_pub.pem" : "client_rsa_pub.pem";

    // long term key
    fprintf(stderr, "Reading %s...\n", is_client ? "client.key" : "server.key");
    int status = readDH(is_client ? "client.key" : "server.key", &long_term);
    if (status != 0) {
        fprintf(stderr, "Failed to read %s!\n", is_client ? "client.key" : "server.key");
    }

    //genkey
    dhGenk(&eph);

    //fingerprints
    char* long_pk = mpz_get_str(NULL, 16, long_term.PK);
    char* eph_pk = mpz_get_str(NULL, 16, eph.PK);
    printf("[%s] Long-term PK (hex): %.8s...\n", is_client ? "CLIENT" : "SERVER", long_pk);
    printf("[%s] Ephemeral PK (hex): %.8s...\n", is_client ? "CLIENT" : "SERVER", eph_pk);
    free(long_pk);
    free(eph_pk);

    //signown ephemeral key 
    char* eph_str = mpz_get_str(NULL, 10, eph.PK);
    unsigned char* signature = NULL;
    unsigned int sig_len = sign_with_rsa(my_priv, eph_str, &signature);
    printf("[%s] Signed ephemeral key.\n", is_client ? "CLIENT" : "SERVER");

    if (is_client) {
        // client sends own keys and signature, then receive peer's
        serialize_mpz(sockfd, long_term.PK);
        serialize_mpz(sockfd, eph.PK);
        send(sockfd, &sig_len, sizeof(sig_len), 0);
        send(sockfd, signature, sig_len, 0);

        deserialize_mpz(peer_long_term.PK, sockfd);
        deserialize_mpz(peer_eph.PK, sockfd);

        unsigned int recv_sig_len;
        recv(sockfd, &recv_sig_len, sizeof(recv_sig_len), 0);
        unsigned char* recv_sig = malloc(recv_sig_len);
        recv(sockfd, recv_sig, recv_sig_len, 0);

        char* peer_eph_str = mpz_get_str(NULL, 10, peer_eph.PK);
        int verified = verify_rsa_signature(peer_pub, peer_eph_str, recv_sig, recv_sig_len);
        if (!verified) {
            fprintf(stderr, "CLIENT: Signature verification failed!\n");
            exit(1);
        } else {
            printf("CLIENT: Signature verified.\n");
        }

        free(peer_eph_str);
        free(recv_sig);
    } else {
        // server receives first, then send
        deserialize_mpz(peer_long_term.PK, sockfd);
        deserialize_mpz(peer_eph.PK, sockfd);

        unsigned int recv_sig_len;
        recv(sockfd, &recv_sig_len, sizeof(recv_sig_len), 0);
        unsigned char* recv_sig = malloc(recv_sig_len);
        recv(sockfd, recv_sig, recv_sig_len, 0);

        char* peer_eph_str = mpz_get_str(NULL, 10, peer_eph.PK);
        int verified = verify_rsa_signature(peer_pub, peer_eph_str, recv_sig, recv_sig_len);
        if (!verified) {
            fprintf(stderr, "SERVER: Signature verification failed!\n");
            exit(1);
        } else {
            printf("SERVER: Signature verified.\n");
        }

        free(peer_eph_str);
        free(recv_sig);

        serialize_mpz(sockfd, long_term.PK);
        serialize_mpz(sockfd, eph.PK);
        send(sockfd, &sig_len, sizeof(sig_len), 0);
        send(sockfd, signature, sig_len, 0);
    }

    free(signature);
    free(eph_str);

    // print keys (16 bytes only) for testing
    char* peer_long_pk = mpz_get_str(NULL, 16, peer_long_term.PK);
    char* peer_eph_pk = mpz_get_str(NULL, 16, peer_eph.PK);
    printf("[%s] Received peer long-term PK: %.8s...\n", is_client ? "CLIENT" : "SERVER", peer_long_pk);
    printf("[%s] Received peer ephemeral PK: %.8s...\n", is_client ? "CLIENT" : "SERVER", peer_eph_pk);
    free(peer_long_pk);
    free(peer_eph_pk);

    // final key exchange
    dh3Finalk(&long_term, &eph, &peer_long_term, &peer_eph, shared_key, SYMM_KEY_LEN);
    printf("[INFO] Shared key (hex): ");
    for (int i = 0; i < SYMM_KEY_LEN; i++) printf("%02x", shared_key[i]);
    printf("\n");
    fflush(stdout);

    shredKey(&long_term);
    shredKey(&eph);
    shredKey(&peer_long_term);
    shredKey(&peer_eph);
}


void* recvMsg(void*)
{
    size_t maxlen = 1024;
    unsigned char buf[maxlen];
    ssize_t nbytes;

    while (1) {
        nbytes = recv(sockfd, buf, maxlen, 0);
        if (nbytes == -1) error("recv failed");
        if (nbytes == 0) return 0;

        if (nbytes < 16) {
            fprintf(stderr, "Received message too short to contain IV\n");
            continue;
        }

        unsigned char iv[16];
        memcpy(iv, buf, 16);

        unsigned char plaintext[1024];
        int decrypted_len = decrypt_message(buf + 16, nbytes - 16, shared_key, iv, plaintext);
        if (decrypted_len == -1) {
            fprintf(stderr, "Decryption failed\n");
            continue;
        }

        plaintext[decrypted_len] = 0;
        char* m = malloc(decrypted_len + 2);
        memcpy(m, plaintext, decrypted_len + 1);
        g_main_context_invoke(NULL, shownewmessage, (gpointer)m);
    }
    return 0;
}