#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>

int main(int argc, char *argv[])
{
   // Open syslog
   openlog("writer", LOG_PID | LOG_CONS, LOG_USER);

   // Check if the correct number of arguments is provided
   if (argc != 3)
   {
      syslog(LOG_ERR, "Invalid number of arguments. Usage: %s <writefile> <writestr>", argv[0]);
      printf("Invalid number of arguments. Usage: %s <writefile> <writestr>\n", argv[0]);
      exit(1);
   }

   char *writefile = argv[1];
   char *writestr = argv[2];

   // Open the file for writing
   FILE *file = fopen(writefile, "w");

   if (file == NULL)
   {
      syslog(LOG_ERR, "Could not open file %s for writing", writefile);
      printf("Could not open file %s for writing\n", writefile);
      exit(1);
   }

   // Write the string to the file
   fprintf(file, "%s", writestr);
   fclose(file);

   // Log the successful write operation
   syslog(LOG_DEBUG, "Writing %s to %s", writestr, writefile);

   // Close syslog
   closelog();

   return 0;
}
