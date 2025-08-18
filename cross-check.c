#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_LINE 1024

char* to_hex_str(const char *s) {
    size_t len = strlen(s);
    char *hexstr = malloc(len * 2 + 1);
    if (!hexstr) return NULL;

    for (size_t i = 0; i < len; i++) {
        sprintf(&hexstr[i * 2], "%02x", (unsigned char)s[i]);
    }

    hexstr[len * 2] = '\0';
    return hexstr;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: echo \"test\" | %s <file-to-search>\n", argv[0]);
        return 1;
    }

    // open already cracked passwords file
    FILE *file = fopen(argv[1], "r");
    if (!file) {
        perror("Error opening file");
        return 1;
    }

    // Read all lines into memory
    char **lines = NULL;
    size_t count = 0;
    char buffer[MAX_LINE];

    while (fgets(buffer, sizeof(buffer), file)) {
        char *line = strdup(buffer);                 // allocate memory for whole line
        line[strcspn(line, "\r\n")] = 0;             // remove newline

        // Find first ':' in line
        char *after_colon = strchr(line, ':');
        if (!after_colon) {
            free(line);                              // free unused line
            continue;                                // skip lines without ':'
        }
        after_colon++;                               // move past ':'

        char *copy = strdup(after_colon);            // copy the part after ':'
        free(line);                                  // free original line

        lines = realloc(lines, (count + 1) * sizeof(char*));
        lines[count++] = copy;                         // store copy safely
    }
    fclose(file);
    //printf("cound = %d\n", count);

    // disable buffering
    setvbuf(stdout, NULL, _IONBF, 0);

    char candidate[MAX_LINE];
    while (fgets(candidate, sizeof(candidate), stdin)) {
        // Remove newline if present
        candidate[strcspn(candidate, "\r\n")] = 0;

        // start from beginning of already cracked passwords file
        for (size_t i = 0; i < count; i++) {
            if (lines[i]) {
                /*printf("%s == %s\t", candidate, lines[i]);
                char *candidate_hex = to_hex_str(candidate);
                if (candidate_hex) {
                    printf("(0x%s == ", candidate_hex);
                    free(candidate_hex);
                }
                char *line_hex = to_hex_str(lines[i]);
                if (line_hex) {
                    printf("0x%s)\n", line_hex);
                    free(line_hex);
                }*/

                if (strcmp(lines[i], candidate) == 0) {
                    printf("%s\n", candidate);
                    free(lines[i]);    // free memory for removed line
                    lines[i] = NULL;   // mark as removed
                }
            }
        }
    }

    for (size_t i = 0; i < count; i++) {
        if (lines[i]) {
            //printf("%s", lines[i]);
            free(lines[i]);
        }
    }
    free(lines);
    return 0;
}
