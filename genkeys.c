#include <stdio.h>
#include <string.h>

#include "keys.h"
#include "dh.h"

int main() {
    if (init("params") != 0) {
        fprintf(stderr, "Failed to load params\n");
        return 1;
    }

    dhKey k;

    //client key
    initKey(&k);
    dhGenk(&k);
    strncpy(k.name, "client", MAX_NAME);
    writeDH("client.key", &k);
    shredKey(&k);

    //server key
    initKey(&k);
    dhGenk(&k);
    strncpy(k.name, "server", MAX_NAME);
    writeDH("server.key", &k);
    shredKey(&k);

    return 0;
}
