#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUFFERSIZE 1024

int sendFile(char * filepath){
	FILE *fp = fopen(filepath, "r");
	long filesize;
	char * content = NULL;
	if(fp != NULL){
		if(fseek(fp, 0L, SEEK_END) == 0){
			filesize = ftell(fp);
			if(filesize != -1){
				content = malloc(sizeof(char) * (filesize +1));
			}
			if(fseek(fp, 0L, SEEK_SET) == 0){
			size_t readlen = fread(content, sizeof(char), filesize, fp);			
				if(readlen > 0){
					content[++readlen] = '\0';
				}
			}	
		}

			
	}else {
		fprintf(stderr, "ERROR: could not read file\n");
		fclose(fp);
		return -1;
	}
	char * msg = malloc(sizeof(char) * (filesize +3));
	strcat(msg, "W ");
	strcat(msg, content);


	FILE * procfp;
	procfp = fopen("/proc/firewallExtension", "w");
	if(procfp == NULL){
		fprintf(stderr,"ERROR: could not wrtie to /proc file\n");
		fclose(fp);
		exit(1);
	}
	fwrite(msg,(filesize +3), sizeof(char), procfp);
	fclose(procfp);



	free(content);
	fclose(fp);
	return 0;
}

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
			fprintf(stderr,"Not valid port number '%i'\n", curport);
			fprintf(stderr, "ERROR: Ill-formed file\n");
			exit(1);
		}
		
		if(!executable(filepath)){
			fprintf(stderr,"ERROR: Cannot execute file\n");
			exit(1);
		}
	}
	fclose(fp);
	
	return 0;
}

int main (int argc, char **argv) {
    
	char filepath[BUFFERSIZE];
	FILE * procfp;
    
	if(argc == 2 && strncmp(argv[1], "L", 2) == 0){
		procfp = fopen("/proc/firewallExtension", "w");
		if(procfp == NULL){
			fprintf(stderr, "ERROR: could not write to /proc file\n");
			exit(1);
		}
		fwrite("L ",3, sizeof(char), procfp);
		fclose(procfp);

	}else if(argc == 3 && strncmp(argv[1], "W", 2) == 0){
		strncpy(filepath, argv[2], BUFFERSIZE -1);
		filepath[BUFFERSIZE -1] = '\0';
		if(!exists(filepath)){
			fprintf(stderr, "ERROR: \n     file '%s' does not exist\n", filepath);
			exit(1);
		}
		readFile(filepath);
		sendFile(filepath);
	
	
	}else {
		fprintf (stderr, "Usage:\n firewallSetup L \n firewallSetup W <filepath>\n");
		fprintf (stderr, "E.g.: ./firewallSetup W /home/Documents/firewallrulles.txt\n");
		exit (1);
	}

	
    return 0;
}


