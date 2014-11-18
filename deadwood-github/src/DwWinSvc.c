/* Copyright (c) 2009 Sam Trenholme and Marko Njezic
 *
 * TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * This software is provided 'as is' with no guarantees of correctness or
 * fitness for purpose.
 */

/* This program is a Windows service; I would like to thank Steve Friedl who
   put a public domain simple Windows service on his web site at unixwiz.net;
   his public domain code made it possible for me to write the Win32
   service code.

   After compiling, one needs to install this service:

        Deadwood.exe --install

   Then one can start the service:

        net start Deadwood

   (It can also be started from Control Panel -> Administrative tools ->
    Services; look for the "Deadwood" service)

   To stop the service:

        net stop Deadwood

   (Or from the Services control panel)

   To remove the service:

        Deadwood.exe --remove

   This program has been verified to compile and run in a MinGW-3.1.0-1 +
   MSYS-1.0.10 environment; for details on how to set up this environment in
   Windows, go to this page:

   http://maradns.blogspot.com/2009/03/mingw-310-1-last-real-mingw-release.html

 */

#include <winsock.h>
#include <wininet.h>
#include <stdint.h>
#include <stdio.h>
/* Make -Wall happy */
#include "DwStr.h"
#include "DwSys.h"
#include "version.h"
extern int dw_svc_main(int argc, char **argv);

int run_loop = 1;
static SERVICE_STATUS           sStatus;
static SERVICE_STATUS_HANDLE    hServiceStatus = 0;
#define COUNTOF(x)       (sizeof(x) / sizeof((x)[0]) )

/* Install the service so it's in Windows' list of services */
void svc_install_service() {
        char szPath[512], svcbinary[550];

        GetModuleFileName( NULL, szPath, COUNTOF(szPath) );
        /* Call the program as "{name} service" so it knows to start as
         * a service (this was Marko Njezic's idea) */
        if (strstr(szPath, " ") != NULL) {
                snprintf(svcbinary, COUNTOF(svcbinary), "\"%s\" service",
                        szPath);
        } else {
                snprintf(svcbinary, COUNTOF(svcbinary), "%s service", szPath);
        }

        SC_HANDLE hSCManager = OpenSCManager(NULL, NULL,
                                SC_MANAGER_CREATE_SERVICE);

        SC_HANDLE hService = CreateService(
                        hSCManager,
                        "Deadwood",                   /* name of service */
                        "Deadwood DNS cache http://maradns.org/deadwood",
                        /* name to display */
                        SERVICE_ALL_ACCESS,           /* desired access */
                        SERVICE_WIN32_OWN_PROCESS,    /* service type */
                        SERVICE_AUTO_START,           /* start type */
                        SERVICE_ERROR_NORMAL,         /* error control type */
                        svcbinary,                    /* service's binary */
                        NULL,                         /* no load order grp */
                        NULL,                         /* no tag identifier */
                        "",                           /* dependencies */
                        0,                     /* LocalSystem account */
                        0);                    /* no password */

        if(hService == NULL) {
                printf("Problem creating service\n");
        } else {
                printf(
            "Deadwood service installed; start with: net start Deadwood\n");
        }

        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);

}

/* Remove the service from Windows' list of services; it's probably a good
 * idea to stop the service first */
void svc_remove_service() {
        SC_HANDLE hService = 0;
        SC_HANDLE hSCManager = OpenSCManager(0,0,0);
        hService = OpenService  (hSCManager,"Deadwood",DELETE);
        if(DeleteService(hService) == 0) {
                printf("Problem deleting service\n");
        } else {
                printf("Deadwood service removed\n");
        }
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
}

/* Handle a request to stop the service */
void svc_service_control(DWORD dwControl) {
        switch (dwControl) {
                case SERVICE_CONTROL_SHUTDOWN:
                case SERVICE_CONTROL_STOP:

                sStatus.dwCurrentState  = SERVICE_STOP_PENDING;
                sStatus.dwCheckPoint    = 0;
                sStatus.dwWaitHint      = 2000; /* Two seconds */
                sStatus.dwWin32ExitCode = 0;
                run_loop = 0;

                default:
                        sStatus.dwCheckPoint = 0;
        }
        SetServiceStatus(hServiceStatus, &sStatus);
}

/* This is the code that is invoked when the service is started */
void svc_service_main(int argc, char **argv) {
        char *a = 0, *b = 0, d = 0;
        int c = 0;
        char szPath[512];

        hServiceStatus = RegisterServiceCtrlHandler(argv[0],
                (void *)svc_service_control);
        if(hServiceStatus == 0) {
                return;
        }

        sStatus.dwServiceType                   = SERVICE_WIN32_OWN_PROCESS;
        sStatus.dwCurrentState                  = SERVICE_START_PENDING;
        sStatus.dwControlsAccepted              = SERVICE_ACCEPT_STOP
                                                | SERVICE_ACCEPT_SHUTDOWN;
        sStatus.dwWin32ExitCode                 = 0;
        sStatus.dwServiceSpecificExitCode       = 0;
        sStatus.dwCheckPoint                    = 0;
        sStatus.dwWaitHint                      = 2 * 1000; /* Two seconds */
        sStatus.dwCurrentState = SERVICE_RUNNING;

        SetServiceStatus(hServiceStatus, &sStatus);

        /* Set the CWD to the directory the service runs in */
        GetModuleFileName( NULL, szPath, COUNTOF(szPath) );
        a = szPath;
        while(*a != 0 && c < 250) {
                if(*a == '/' || *a == '\\') {
                        b = a;
                }
                a++;
                c++;
        }
        if(b != 0) {
                d = *b;
                *b = 0; /* Now ARGV[0] is the path to the program */
                chdir(szPath);
                *b = d;
        }

        /* Prepare things for logging */
        dw_log_init();
        /* The actual code the service runs */
        dw_svc_main(argc,argv);
        /* Clean up the log */
        dw_log_close();

        /* Clean up the stopped service; otherwise we get a nasty error in
           Win32 */
        sStatus.dwCurrentState  = SERVICE_STOPPED;
        SetServiceStatus(hServiceStatus, &sStatus);

}

/* Debug version of main in case the service acts up */
int dmain(int argc, char **argv) {
        char *a = 0, *b = 0, d = 0;
        int c = 0;
        /* Set the CWD to the directory the service runs in */
        a = argv[0];
        while(*a != 0 && c < 250) {
                if(*a == '/' || *a == '\\') {
                        b = a;
                }
                a++;
                c++;
        }
        if(b != 0) {
                d = *b;
                *b = 0; /* Now ARGV[0] is the path to the program */
                chdir(argv[0]);
                *b = d;
        }

        /* The actual code the service runs */
        dw_svc_main(argc,argv);
        return 0;
}

/* The main() function that calls the service */
int main(int argc, char **argv) {

        int a=0;
        char *b;
        int action = 0;

        static SERVICE_TABLE_ENTRY      Services[] = {
                { "Deadwood",  (void *)svc_service_main },
                { 0 }
        };
        if(argc > 1) {

                /* Are we started as a service? */
                if (strcmp(argv[1], "service") == 0) {
                        if (!StartServiceCtrlDispatcher(Services)) {
                                printf("Fatal: Can not start service!\n");
                                return 1;
                        }
                        return 0;
                }

                b = argv[1];
                for(a=0;a<5 && *b;a++) {
                        if(*b == 'r') { /* --remove */
                                action = 1;
                        } else if(*b == 'd') { /* --nodaemon */
                                action = 2;
                        }
                        b++;
                }
                if(action == 1) { /* --remove */
                        svc_remove_service();
                } else if(action == 2) { /* --nodaemon */
                        dw_log_init();
                        argv[1] = "-f";
                        dw_svc_main(argc,argv);
                } else { /* --install */
                        svc_install_service();
                }
        } else {
                printf("Deadwood version %s\n\n",VERSION);
                printf("Deadwood is a DNS server that is a Windows service\n\n"
                       "To install this service:\n\n\tDeadwood --install\n\n"
                       "To remove this service:\n\n\tDeadwood --remove\n\n");
        }
        return 0;
}

