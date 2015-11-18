#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUFFERSIZE 1024

int exists(char * filepath){
	if( access( filepath, F_OK ) != -1 ) {
		return 1;
	} else {
   		return 0;
	}
}

int is_port(int port){
	if(port > 0 && port < 65535){
		return 1;
	} else {
		return 0;
	}

} 

int executable(char * filepath){
	if( access( filepath, X_OK ) != -1 ) {
		return 1;
	} else {
   		return 0;
	}
}

int readFile(char * filePath)
{
	FILE * fp;
	int res;	
	fp = fopen (filePath, "r");
	char line[BUFFERSIZE];
	
   	while ( fgets(line, BUFFERSIZE, fp)){
		
		int curport;
		char  *filepath;
		res = sscanf(line, "%i %ms", &curport, &filepath);
		memset(line, 0, BUFFERSIZE);
		if(res != 2){
			fprintf(stderr, "ERROR: Ill-formed file\n");
			exit(1);
		}
		printf("port: %i Path: %s\n", curport, filepath);

	
		if(!is_port(curport)){
			fprintf(stderr,"Not valid port\n");
		}		
		
		if(!executable(filepath)){
			fprintf(stderr,"ERROR: Cannot execute file\n");
		}
	}
	fclose(fp);
   
	return 0;
}

int main (int argc, char **argv) {
    
	char filepath[BUFFERSIZE];

    
	if(argc == 2 && strncmp(argv[1], "L", 2) == 0){
		printf("WIN\n");
	}else if(argc == 3 && strncmp(argv[1], "W", 2) == 0){
		strncpy(filepath, argv[2], BUFFERSIZE -1);
		filepath[BUFFERSIZE -1] = '\0';
		if(!exists(filepath)){
			fprintf(stderr, "file '%s' DOES NOT EXIST\n", filepath);
			exit(1);
		}
		readFile(filepath);
	
	
	}else {
		fprintf (stderr, "Usage:\n firewallSetup L \n firewallSetup W <filepath>\n");
		fprintf (stderr, "E.g.: ./firewallSetup W /home/Documents/firewallrulles.txt\n");
		exit (1);
	}

	
    return 0;
}


