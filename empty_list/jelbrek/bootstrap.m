#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/stat.h>

#include <Foundation/Foundation.h>
#include <CoreFoundation/CoreFoundation.h>

#include "jelbrek.h"
#include "shell.h"
#include "libjb.h"

int bootstrap() {
    NSLog(@"Installing bootstrap...");
      
    chdir("/var/containers/Bundle/");
    
    FILE *bootstrap = fopen((char*)[[[[NSBundle mainBundle] bundlePath] stringByAppendingString:@"/iosbinpack.tar"] UTF8String], "r");
    untar(bootstrap, "/var/containers/Bundle/");
    fclose(bootstrap);

    FILE *tweaks = fopen((char*)[[[[NSBundle mainBundle] bundlePath] stringByAppendingString:@"/tweaksupport.tar"] UTF8String], "r");
    untar(tweaks, "/var/containers/Bundle/");
    fclose(tweaks);
    
    if (![[NSFileManager defaultManager] fileExistsAtPath:@"/var/containers/Bundle/tweaksupport"] || ![[NSFileManager defaultManager] fileExistsAtPath:@"/var/containers/Bundle/iosbinpack64"]) return -1;
    return 0;
}

void createSymlinks() {
    NSLog(@"Symlinking stuff...");
    NSString *LIB = @"/var/containers/Bundle/tweaksupport/Library";
    NSString *ulib = @"/var/containers/Bundle/tweaksupport/usr/lib";
    NSString *bin = @"/var/containers/Bundle/tweaksupport/bin";
    NSString *sbin = @"/var/containers/Bundle/tweaksupport/sbin";
    
    symlink((char*)[LIB UTF8String], "/var/LIB");
    symlink((char*)[ulib UTF8String], "/var/ulb");
    symlink((char*)[bin UTF8String], "/var/bin");
    symlink((char*)[sbin UTF8String], "/var/sbin");
}


void uninstall() {
    NSLog(@"Uninstalling...");
    
    NSFileManager *fm = [NSFileManager defaultManager];
    [fm removeItemAtPath:@"/var/LIB" error:nil];
    [fm removeItemAtPath:@"/var/ulb" error:nil];
    [fm removeItemAtPath:@"/var/bin" error:nil];
    [fm removeItemAtPath:@"/var/sbin" error:nil];
    [fm removeItemAtPath:@"/var/profile" error:nil];
    [fm removeItemAtPath:@"/var/motd" error:nil];
    [fm removeItemAtPath:@"/var/dropbear" error:nil];
    [fm removeItemAtPath:@"/var/containers/Bundle/tweaksupport" error:nil];
    [fm removeItemAtPath:@"/var/containers/Bundle/iosbinpack64" error:nil];
    [fm removeItemAtPath:@"/var/containers/Bundle/dylibs" error:nil];
    [fm removeItemAtPath:@"/var/log/testbin.log" error:nil];
    [fm removeItemAtPath:@"/var/log/jailbreakd-stdout.log" error:nil];
    [fm removeItemAtPath:@"/var/log/jailbreakd-stderr.log" error:nil];
}

