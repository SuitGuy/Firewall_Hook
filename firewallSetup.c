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
	int curport;
	char  *filepath;
	fp = fopen (filePath, "r");

	res = fscanf(fp, "%i %ms", &curport, &filepath);
   	while ( res == 2){
		printf("port: %i Path: %s\n", curport, filepath);
		if(executable(filepath)){
			printf("EXECUTABLE\n");
		}else{
			printf("NOTEXECUTABLE\n");
		}
		res = fscanf(fp, "%i %ms", &curport, &filepath); 
	}
	
	if(res != EOF){
		fprintf(stderr,"ERROR:\n   mallformed file supplied. file should be in the form <port> <filename>\n");
		exit(1);
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


