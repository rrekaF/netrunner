#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OK       0
#define NO_INPUT 1
#define TOO_LONG 2

static int getLine (char *prmpt, char *buff, size_t sz) {
    int ch, extra;

    // Get line with buffer overrun protection.
    if (prmpt != NULL) {
        printf ("%s", prmpt);
        fflush (stdout);
    }
    if (fgets (buff, sz, stdin) == NULL)
        return NO_INPUT;

    // If it was too long, there'll be no newline. In that case, we flush
    // to end of line so that excess doesn't affect the next call.
    if (buff[strlen(buff)-1] != '\n') {
        extra = 0;
        while (((ch = getchar()) != '\n') && (ch != EOF))
            extra = 1;
        return (extra == 1) ? TOO_LONG : OK;
    }

    // Otherwise remove newline and give string back to caller.
    buff[strlen(buff)-1] = '\0';
    if(!strcmp(buff, "\0")){
	return NO_INPUT;
    }
    return OK;
}

void connect_wifi(const char* interface, const char* ssid, const char* password, const char* username) {
    char command[512];

    // Create temporary configuration file
    char tempConfigPath[128];
    strcpy(tempConfigPath, "/etc/network/temp.conf");

    printf("(+) Creating temporary interface config file\n"); 
    FILE *file = fopen("/etc/network/temp.conf", "w");
    if (!file) {
        perror("Error creating temporary configuration file");
        return;
    }

    // Write configuration to the file
    fprintf(file, "auto %s\n", interface);
    fprintf(file, "iface %s inet dhcp\n", interface);
    fprintf(file, "    wpa-ssid \"%s\"\n", ssid);
    fprintf(file, "    wpa-psk \"%s\"\n", password);
    if (strlen(username) > 0) {
        fprintf(file, "    pre-up echo -e 'POST /login HTTP/1.0\\n\\nusername=%s&password=%s' | nc -w1 1.1.1.1 80 > /dev/null\n", username, password);
    }
    fclose(file);

    // Move the temporary file to the correct location
    sprintf(command, "mv /etc/network/temp.conf /etc/network/interfaces");
    system(command);

    // Bring up interface
    printf("(+) restarting networking service\n");
    system("sudo service networking restart");
}

int main(int argc, char *argv[]) {
    if (argc < 4 && argc > 1) {
        printf("(-) Usage: sudo %s [<interface> <SSID> <password> [username]]\n", argv[0]);
        printf("  If the network requires a login page, provide the username argument.\n");
        return 1;
    }

    char* interface;
    char* ssid;
    char* password;

    size_t size = 128;
    char* input = malloc(size * sizeof(char));

    // INTERFACE
    int error = getLine("Interface (default wlp3s0): ", input, size);
    switch(error){
	case 0:
	    strcpy(interface, input);
	    break;
	case 1:
	    printf("No input, using default.\n", input);
	    break;
	case 2:
	    printf("Input too long (over %d characters). Aborting.\n", size);
	    free(input);
	    exit(2);
	default:
	    printf("Unknow error code: %d. Aborting.\n");
	    free(input);
	    exit(3);
    }

    // SSID
	error = getLine("SSID (required): ", input, size);
	switch(error){
	    case 0:
		    printf("Using SSID %s.\n", input);
		    printf("strcpy\n");
		    printf("%s\n", input);
		    strcpy(ssid, input);
		    printf("strcpy\n");
		    break;
	    case 1:
		printf("Please input SSID (can not be empty)\n");
		break;
	    case 2:
		printf("SSID too long (over %s characters). Aborting.\n", size);
		free(input);
		exit(2);
	}

    // PASSWORD
	error = getLine("password: ", input, size);
	switch(error){
	    case 0:
		    printf("Using password %s.\n", input);
		    strcpy(password, input);
		    break;
	    case 1:
		printf("Using empty password.\n");
		break;
	    case 2:
		printf("Password too long (over %s characters). Aborting.\n", size);
		free(input);
		exit(2);
	}

    free(input);

    const char* username = "";
    if (argc > 4) {
        username = argv[4];
    }

    connect_wifi(interface, ssid, password, username);

    return 0;
}

