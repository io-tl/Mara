#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>


void trace(const char* format, ...) {
    va_list param;
    struct timeval tv;
    struct tm *nowtm;
    time_t nowtime;
    char tmbuf[64], buf[512];

    gettimeofday(&tv, NULL);
    nowtime = tv.tv_sec;
    nowtm = localtime(&nowtime);
    strftime(tmbuf, sizeof tmbuf, "%H:%M:%S", nowtm);
    snprintf(buf, sizeof buf, "%s.%03ld", tmbuf, tv.tv_usec);
    FILE *out = fopen("/dev/stdout","a+");
    va_start(param, format);
    fprintf(out, "(%d) %s: " , getpid(), buf);
    vfprintf(out, format, param);
    fprintf(out, "\n");
    va_end(param);
    fclose(out);
}


void hd(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}
