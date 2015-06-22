# banned_functions
IDAPython script to check ELF &amp; PE/COFF for MS SDL banned.h policy violations and set breakpoints.

Simply copy it to your IDA python folder and hit Alt-F7 in IDA to execute the script. The first run will display any violations and set breakpoints on all calls to those functions. Running the script again will disable the breakpoints. 

Feel free to send me any features you'd like to see added. stephen <at> deadlisting <dot> com
