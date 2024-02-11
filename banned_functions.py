"""
Author: Stephen Sims - @Steph3nSims
Topic: IDAPython scripting - SANS SEC760 - http://www.sans.org/sec760
Tested with IDA 6.7

Style Improvements by: Tim Medin (B33f Supreme)

Script to check an PE/COFF or ELF input file to see if it
includes banned functions from MS SDL's banned.h module. If it
does, it lists them out and sets breakpoints on each call.
Some compilers/linker options add an intermediary jmp before
reaching IAT thunk. Code compensates for either case. If you
run the script a second time, it will disable the setting of
all breakpoints it set on the first run.

I have run this against quite a few programs
and fixed a few bugs, and have had
no further issues. If the script crashes, send me back the
output to stephen@deadlisting.com and I will try to fix. 
Global flags are used to deal with issues
around the different ways in which the IAT is hit, as well as
xref types.

e.g. Running against Microsoft's IE11 64-bit MSHTML.DLL from MS14-080.

Running banned_functions.py - One moment...

Found function StrCpyNW in IAT at 0x18169cd88
*** calls to StrCpyNW ***
=> 0x180810274 - Added BP
=> 0x1812f10ce - Added BP
=> 0x1812f1fd1 - Added BP

=> This program calls direct to IAT.
=> The following banned functions were found:

=> StrCpyNW

Finished! Breakpoints added. Run again to delete.
"""
import idaapi, idc, idautils

checked = []
bpflag = 0
codeflag = 0

# Microsoft SDL banned.h list. Feel free to add/remove names.
bannedList = (["_fstrcat", "_fstrcpy", "_fstrncat", "_fstrncpy", "_ftccat", "_ftccpy", 
               "_ftcscat", "_ftcscpy", "_getts", "_gettws", "_getws", "_itoa", "_i64toa", 
               "_i64tow", "_mbccpy", "_mbscpy", "_mbsnbcpy", "_mbsnbcat", "_mbsncat", 
               "_mbsncpy", "_mbstok", "_snprintf", "_sntprintf", "_sntscanf", "_snwprintf", 
               "_splitpath", "_stprintf", "_stscanf", "_tccat", "_tccpy", "_tcscat", 
               "_tcscpy", "_tcsncat", "_tcsncpy", "_tmakepath", "_tscanf", "_tsplitpath", 
               "_ui64toa", "_ui64tow", "_ultoa", "CharToOemA", "CharToOemBuffA", "CharToOemBuffW", 
               "CharToOemW", "OemToCharA", "OemToCharBuffA", "OemToCharBuffW", "OemToCharW", 
               "StrCat", "StrCatA", "StrCatBuff", "StrCatBuffA", "StrCatBuffW", "StrCatChainW", 
               "StrCatN", "StrCatNA", "StrCatNW", "StrCatW", "StrCpy", "StrCpyA", "StrCpyN", 
               "StrCpyNA", "StrCpyNW", "strcpyW", "StrCpyW", "StrNCat", "StrNCatA", "StrNCatW", 
               "StrNCpy", "StrNCpyA", "StrNCpyW", "gets", "lstrcat", "lstrcatA", "lstrcatn", 
               "lstrcatnA", "lstrcatnW", "lstrcatW", "lstrcpy", "lstrcpyA", "lstrcpyn", 
               "lstrcpynA", "lstrcpynW", "lstrcpyW", "lstrlen", "lstrlenA", "lstrlenW", "scanf", 
               "sscanf", "snscanf", "snwscanf", "sprintf", "sprintfA", "sprintfW", "lstrncat", 
               "makepath", "nsprintf", "strcat", "strcatA", "strcatW", "strcpy", "strcpyA", 
               "strncat", "strncpy", "swprintf", "ualstrcpyW", "vsnprintf", "vsprintf", "vswprintf", 
               "wcscat", "wcscpy", "wcsncat", "wcsncpy", "wnsprintf", "wnsprintfA", "wsprintf", 
               "wsprintfA", "wsprintfW", "wmemcpy", "wscanf", "wnsprintfW", "ExAllocatePool", 
               "ExAllocatePoolWithTag", "ExAllocatePoolWithQuota", "ExAllocatePoolWithQuotaTag", 
               "ExAllocatePoolWithTagPriority", "MmMapIoSpace", "MmAllocateContiguousMemorySpecifyCache", 
               "ExInitializeNPagedLookasideList", "MmAllocateContiguousMemorySpecifyCache"])

def iatCallback(addr, name, ord):   # Don't care about ord, but required for enum_import_names
    global bpflag, codeflag, checked, bannedList  # Function got a bit out of hand. Sorry.

    if name in bannedList and name not in checked:
        checked.append(name)
        loopflag = 0
        xref = XrefsTo(addr, 0)
        for checkXrefType in xref:
            if XrefTypeName(checkXrefType.type) == "Code_Near_Call" and loopflag != 1:
                print("\nFound function %s in IAT at 0x%08x" % (name, addr))
                print("*** calls to %s ***" % name)
                loopflag = 1
                codeflag = 1
                xref = CodeRefsTo(addr, 1)      # Ref to IAT should be of type code.
                for lines in xref:
                    if check_bpt(lines) > 0:     # Adding or deleting BP's
                        idaapi.del_bpt(lines)
                        print("=> 0x%08x - Deleted BP" % lines)
                    else:
                        idaapi.add_bpt(lines, 0, BPT_SOFT)
                        enable_bpt(lines, True)
                        checked.append(lines)
                        print("=> 0x%08x - Added BP" % lines)
                        bpflag = 1
            elif XrefTypeName(checkXrefType.type) == "Data_Read" and codeflag == 0:
                print("\nFound function %s in IAT at 0x%08x" % (name, addr))
                print("*** calls to %s ***" % name)
                xref = DataRefsTo(addr)                # Ref to IAT should be of type data.
                for line in xref:
                    xref2 = CodeRefsTo(line, 1)
                    for lines in xref2:
                        if check_bpt(lines) > 0:         # Adding or deleting BP's
                            idaapi.del_bpt(lines)
                            print("=> 0x%08x - Deleted BP" % lines)
                        else:
                            idaapi.add_bpt(lines, 0, BPT_SOFT)
                            enable_bpt(lines, True)
                            checked.append(lines)
                            print("=> 0x%08x - Added BP" % lines)
                            bpflag = 1
            elif XrefTypeName(checkXrefType.type) == "Code_Near_Jump":
                GOT = DataRefsTo(addr)
                for line in GOT:
                    print("\n Found function %s in GOT at 0x%08x" % (name, line))
                    print("*** calls to %s ***" % name)
                    codeflag = 2
                xref = CodeRefsTo(addr, 1)
                for line in xref:
                    xref2 = CodeRefsTo(line, 1)
                    for lines in xref2:
                        if check_bpt(lines) > 0:
                            idaapi.del_bpt(lines)
                            print("=> 0x%08x - Deleted BP" % lines)
                        else:
                            idaapi.add_bpt(lines, 0, BPT_SOFT)
                            enable_bpt(lines, True)
                            checked.append(lines)
                            print("=> 0x%08x = Added BP" % lines)
                            bpflag = 1							
            #elif loopflag != 1:
            #    codeflag = 2
            #	    break
            else:
                continue    #Need to compensate for other xref types.

    return True				#Has to be here for the callback. 

def ToggleBreakpoints():
    global bpflag, codeflag, checked, bannedList 
    
    print("\nRunning banned_functions.py - One moment...")

    for i in range(0, idaapi.get_import_module_qty()):
        name = idaapi.get_import_module_name(i)
        idaapi.enum_import_names(i, iatCallback)

    if codeflag == 0 and checked != []:
        print("\n=> This PE/COFF program uses an intermediary jmp to IAT.")
    elif codeflag == 1 and checked != []:
        print("\n=> This PE/COFF program calls direct to IAT.")
    elif codeflag == 2 and checked != []:
        print("\n=> Looks like an ELF file. CS => PLT => *GOT.")
    else:
        print("")

    print("=> The following banned functions were found:\n ")

    for item in checked:
        if item in bannedList:
            print("=> %s" % item)

    if bpflag == 0 and codeflag == 1:
        print("\nFinished! Breakpoints deleted. Run again to add.")
    elif bpflag == 1 and codeflag <= 1:
        print("\nFinished! Breakpoints added. Run again to delete.")
    elif bpflag == 0 and codeflag == 0:
        if not checked:
            print("\nNo banned functions found!")
    else:
        print("\n")

if __name__ == '__main__':
    ToggleBreakpoints()

