#import <Foundation/Foundation.h>
#include <err.h>
#include "kern_utils.h"
#include "patchfinder64.h"
#include "amfi_utils.h"
#include "offsetof.h"
#include "jelbrek.h"
#include <sys/mount.h>
#include "kexecute.h"
#include "osobject.h"
#include "vnode_utils.h"

#include <sys/spawn.h>
#include <sys/mman.h>
#include <IOKitLib.h>
#include <sys/snapshot.h>

//#include "inject_criticald.h"
//#include "unlocknvram.h"
//#include <IOKit/IOKitLib.h>

extern uint64_t kslide;

void init_jelbrek(mach_port_t tfp0, uint64_t kernel_base) {
    init_kernel_utils(tfp0);
    init_kernel(kernel_base, NULL);
    initQiLin(tfp0, kernel_base); //Jonathan Levin: http://newosxbook.com/QiLin/
    init_kexecute();
    setKernelSymbol("_kernproc", find_kernproc()-kslide);
}

int trustbin(const char *path) {
    
    NSMutableArray *paths = [NSMutableArray array];
    
    NSFileManager *fileManager = [NSFileManager defaultManager];
    
    BOOL isDir = NO;
    if (![fileManager fileExistsAtPath:@(path) isDirectory:&isDir]) {
        printf("[-] Path does not exist!\n");
        return -1;
    }
    
    NSURL *directoryURL = [NSURL URLWithString:@(path)];
    NSArray *keys = [NSArray arrayWithObject:NSURLIsDirectoryKey];
    
    if (isDir) {
        NSDirectoryEnumerator *enumerator = [fileManager
                                             enumeratorAtURL:directoryURL
                                             includingPropertiesForKeys:keys
                                             options:0
                                             errorHandler:^(NSURL *url, NSError *error) {
                                                 if (error) printf("[-] %s\n", [[error localizedDescription] UTF8String]);
                                                 return YES;
                                             }];
        
        for (NSURL *url in enumerator) {
            NSError *error;
            NSNumber *isDirectory = nil;
            if (![url getResourceValue:&isDirectory forKey:NSURLIsDirectoryKey error:&error]) {
                if (error) continue;
            }
            else if (![isDirectory boolValue]) {
                
                int rv;
                int fd;
                uint8_t *p;
                off_t sz;
                struct stat st;
                uint8_t buf[16];
                
                char *fpath = strdup([[url path] UTF8String]);
                
                if (strtail(fpath, ".plist") == 0 || strtail(fpath, ".nib") == 0 || strtail(fpath, ".strings") == 0 || strtail(fpath, ".png") == 0) {
                    continue;
                }
                
                rv = lstat(fpath, &st);
                if (rv || !S_ISREG(st.st_mode) || st.st_size < 0x4000) {
                    continue;
                }
                
                fd = open(fpath, O_RDONLY);
                if (fd < 0) {
                    continue;
                }
                
                sz = read(fd, buf, sizeof(buf));
                if (sz != sizeof(buf)) {
                    close(fd);
                    continue;
                }
                if (*(uint32_t *)buf != 0xBEBAFECA && !MACHO(buf)) {
                    close(fd);
                    continue;
                }
                
                p = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
                if (p == MAP_FAILED) {
                    close(fd);
                    continue;
                }
                
                [paths addObject:@(fpath)];
                printf("[*] Will trust %s\n", fpath);
            }
        }
    }
    else {
        printf("[*] Will trust %s\n", path);
        [paths addObject:@(path)];
    }
    
    uint64_t trust_chain = find_trustcache();
    
    printf("[*] trust_chain at 0x%llx\n", trust_chain);
    
    struct trust_chain fake_chain;
    fake_chain.next = kread64(trust_chain);
    *(uint64_t *)&fake_chain.uuid[0] = 0xabadbabeabadbabe;
    *(uint64_t *)&fake_chain.uuid[8] = 0xabadbabeabadbabe;
    
    int cnt = 0;
    uint8_t hash[CC_SHA256_DIGEST_LENGTH];
    hash_t *allhash = malloc(sizeof(hash_t) * [paths count]);
    for (int i = 0; i != [paths count]; ++i) {
        uint8_t *cd = getCodeDirectory((char*)[[paths objectAtIndex:i] UTF8String]);
        if (cd != NULL) {
            getSHA256inplace(cd, hash);
            memmove(allhash[cnt], hash, sizeof(hash_t));
            ++cnt;
        }
        else {
            printf("[-] CD NULL\n");
            continue;
        }
    }
    
    fake_chain.count = cnt;
    
    size_t length = (sizeof(fake_chain) + cnt * sizeof(hash_t) + 0xFFFF) & ~0xFFFF;
    uint64_t kernel_trust = kalloc(length);
    printf("[*] allocated: 0x%zx => 0x%llx\n", length, kernel_trust);
    
    kwrite(kernel_trust, &fake_chain, sizeof(fake_chain));
    kwrite(kernel_trust + sizeof(fake_chain), allhash, cnt * sizeof(hash_t));
    kwrite64(trust_chain, kernel_trust);
    
    return 0;
}



BOOL unsandbox(pid_t pid) {
    uint64_t proc = proc_for_pid(pid);
    uint64_t ucred = kread64(proc + offsetof_p_ucred); //our credentials
    kwrite64(kread64(ucred + 0x78) + 8 + 8, 0x0); //get rid of sandbox by writing 0x0 to it
    
    return (kread64(kread64(ucred + 0x78) + 8 + 8) == 0) ? YES : NO;
}

void setcsflags(pid_t pid) {
    uint64_t proc = proc_for_pid(pid);
    uint32_t csflags = kread32(proc + offsetof_p_csflags);
    csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW | CS_DEBUGGED) & ~(CS_RESTRICT | CS_HARD | CS_KILL);
    kwrite32(proc + offsetof_p_csflags, csflags);
}

BOOL get_root(pid_t pid) {
    uint64_t proc = proc_for_pid(pid);
    uint64_t ucred = kread64(proc + offsetof_p_ucred);
    //make everything 0 without setuid(0), pretty straightforward. 
    kwrite32(proc + offsetof_p_uid, 0);
    kwrite32(proc + offsetof_p_ruid, 0);
    kwrite32(proc + offsetof_p_gid, 0);
    kwrite32(proc + offsetof_p_rgid, 0);
    kwrite32(ucred + offsetof_ucred_cr_uid, 0);
    kwrite32(ucred + offsetof_ucred_cr_ruid, 0);
    kwrite32(ucred + offsetof_ucred_cr_svuid, 0);
    kwrite32(ucred + offsetof_ucred_cr_ngroups, 1);
    kwrite32(ucred + offsetof_ucred_cr_groups, 0);
    kwrite32(ucred + offsetof_ucred_cr_rgid, 0);
    kwrite32(ucred + offsetof_ucred_cr_svgid, 0);
    
    return (geteuid() == 0) ? YES : NO;
}

void platformize(pid_t pid) {
    uint64_t proc = proc_for_pid(pid);
    printf("Platformizing process at address 0x%llx\n", proc);
    uint64_t task = kread64(proc + offsetof_task);
    uint32_t t_flags = kread32(task + offsetof_t_flags);
    t_flags |= 0x400;
    NSLog(@"Flicking on task @0x%llx t->flags to have TF_PLATFORM (0x%x)..\n", task, t_flags);
    kwrite32(task+offsetof_t_flags, t_flags);
    uint32_t csflags = kread32(proc + offsetof_p_csflags);
    kwrite32(proc + offsetof_p_csflags, csflags | 0x24004001u);
}

void entitlePid(pid_t pid, const char *ent1, _Bool val1) {
    uint64_t proc = proc_for_pid(pid);
    uint64_t ucred = kread64(proc+0x100);
    uint64_t entitlements = kread64(kread64(ucred+0x78)+0x8);
    
    if (OSDictionary_GetItem(entitlements, ent1) == 0) {
        printf("[*] Setting Entitlements...\n");
        printf("before: %s is 0x%llx\n", ent1, OSDictionary_GetItem(entitlements, ent1));
        OSDictionary_SetItem(entitlements, ent1, (val1) ? find_OSBoolean_True() : find_OSBoolean_False());
        printf("after: %s is 0x%llx\n", ent1, OSDictionary_GetItem(entitlements, ent1));
    }
}

uint64_t borrowCredsFromPid(pid_t donor) {
    uint64_t selfproc = proc_for_pid(getpid());
    uint64_t donorproc = proc_for_pid(donor);
    uint64_t selfcred = kread64(selfproc + offsetof_p_ucred);
    uint64_t donorcred = kread64(donorproc + offsetof_p_ucred);
    kwrite64(selfproc + offsetof_p_ucred, donorcred);
    return selfcred;
}

void undoCredDonation(uint64_t selfcred) {
    uint64_t selfproc = proc_for_pid(getpid());
    kwrite64(selfproc + offsetof_p_ucred, selfcred);
}

//don't use this yet pls
uint64_t borrowCredsFromDonor(char *binary) {
    pid_t pd;
    const char* args[] = {binary, NULL};
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
    int rv = posix_spawn(&pd, binary, NULL, NULL, (char **)&args, NULL);
    if (rv) {
        printf("Error occured while gaining credentials from donor\n");
        return -1;
    }
    kill(pd, SIGSTOP);
    uint64_t creds = borrowCredsFromPid(pd);
    kill(pd, SIGSEGV);
    return creds;
}

int launchAsPlatform(char *binary, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5, char *arg6, char**env) {
    pid_t pd;
    const char* args[] = {binary, arg1, arg2, arg3, arg4, arg5, arg6,  NULL};
    
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED); //this flag will make the created process stay frozen until we send the CONT signal. This so we can platformize it before it launches.
    
    int rv = posix_spawn(&pd, binary, NULL, &attr, (char **)&args, env);
    
    platformize(pd);
    
    kill(pd, SIGCONT); //continue
    
    if (!rv) {
        int a;
        waitpid(pd, &a, 0);
    }
    
    return rv;
}

int launch(char *binary, char *arg1, char *arg2, char *arg3, char *arg4, char *arg5, char *arg6, char**env) {
    pid_t pd;
    const char* args[] = {binary, arg1, arg2, arg3, arg4, arg5, arg6,  NULL};
    
    int rv = posix_spawn(&pd, binary, NULL, NULL, (char **)&args, env);
    if (!rv) {
        int a;
        waitpid(pd, &a, 0);
    }
    return rv;
}

void remount1126(){
    uint64_t _rootvnode = find_rootvnode();
    uint64_t rootfs_vnode = kread64(_rootvnode);
    printf("\n[*] vnode of /: 0x%llx\n", rootfs_vnode);
    uint64_t v_mount = kread64(rootfs_vnode + offsetof_v_mount);
    uint32_t v_flag = kread32(v_mount + offsetof_mnt_flag);
    printf("[*] Removing RDONLY, NOSUID and ROOTFS flags\n");
    printf("[*] Flags before 0x%x\n", v_flag);
    v_flag &= ~MNT_NOSUID;
    v_flag &= ~MNT_RDONLY;
    printf("[*] Flags now 0x%x\n", v_flag);
    kwrite32(v_mount + offsetof_mnt_flag, v_flag & ~MNT_ROOTFS);
    
    char *nmz = strdup("/dev/disk0s1s1");
    int rv = mount("apfs", "/", MNT_UPDATE, (void *)&nmz);
    printf("[*] Remounting /, return value = %d\n", rv);
    
    v_mount = kread64(rootfs_vnode + offsetof_v_mount);
    kwrite32(v_mount + offsetof_mnt_flag, v_flag);
    
    int fd = open("/RWTEST", O_RDONLY);
    if (fd == -1) {
        fd = creat("/RWTEST", 0777);
    } else {
        printf("File already exists!\n");
    }
    close(fd);
    printf("Did we mount / as read+write? %s\n", [[NSFileManager defaultManager] fileExistsAtPath:@"/RWTEST"] ? "yes" : "no");
}

void createDirAtPath(const char* path) {
    mkdir(path, 0755);
}

struct hfs_mount_args {
    char    *fspec;            /* block special device to mount */
    uid_t    hfs_uid;        /* uid that owns hfs files (standard HFS only) */
    gid_t    hfs_gid;        /* gid that owns hfs files (standard HFS only) */
    mode_t    hfs_mask;        /* mask to be applied for hfs perms  (standard HFS only) */
    u_int32_t hfs_encoding;    /* encoding for this volume (standard HFS only) */
    struct    timezone hfs_timezone;    /* user time zone info (standard HFS only) */
    int        flags;            /* mounting flags, see below */
    int     journal_tbuffer_size;   /* size in bytes of the journal transaction buffer */
    int        journal_flags;          /* flags to pass to journal_open/create */
    int        journal_disable;        /* don't use journaling (potentially dangerous) */
};

int mountDevAtPathAsRW(const char* devpath, const char* path) {
    struct hfs_mount_args mntargs;
    bzero(&mntargs, sizeof(struct hfs_mount_args));
    mntargs.fspec = (char*)devpath;
    mntargs.hfs_mask = 1;
    gettimeofday(NULL, &mntargs.hfs_timezone);
    
    int rvtmp = mount("apfs", path, 0, (void *)&mntargs);
    printf("mounting: %d\n", rvtmp);
    return rvtmp;
}


int list_snapshots(const char *vol)
{
    int dirfd = open(vol, O_RDONLY, 0);
    if (dirfd < 0) {
        perror("get_dirfd");
        return -1;
    }
    
    struct attrlist alist = { 0 };
    char abuf[2048];
    
    alist.commonattr = ATTR_BULK_REQUIRED;
    
    int count = fs_snapshot_list(dirfd, &alist, &abuf[0], sizeof (abuf), 0);
    if (count < 0) {
        perror("fs_snapshot_list");
        return -1;
    }
    
    char *p = &abuf[0];
    for (int i = 0; i < count; i++) {
        char *field = p;
        uint32_t len = *(uint32_t *)field;
        field += sizeof (uint32_t);
        attribute_set_t attrs = *(attribute_set_t *)field;
        field += sizeof (attribute_set_t);
        
        if (attrs.commonattr & ATTR_CMN_NAME) {
            attrreference_t ar = *(attrreference_t *)field;
            char *name = field + ar.attr_dataoffset;
            field += sizeof (attrreference_t);
            (void) printf("%s\n", name);
        }
        
        p += len;
    }
    
    return (0);
}

char *copyBootHash() {
    io_registry_entry_t chosen = IORegistryEntryFromPath(kIOMasterPortDefault, "IODeviceTree:/chosen");
    
    unsigned char buf[1024];
    uint32_t size = 1024;
    char *hash;
    
    if (chosen && chosen != -1) {
        kern_return_t ret = IORegistryEntryGetProperty(chosen, "boot-manifest-hash", (char*)buf, &size);
        IOObjectRelease(chosen);
        
        if (ret) {
            printf("Unable to read boot-manifest-hash\n");
            hash = NULL;
        }
        else {
            char *result = (char*)malloc((2 * size) | 1); // even number | 1 = that number + 1, just because why not
            memset(result, 0, (2 * size) | 1);
            
            int i = 0;
            while (i < size) {
                unsigned char ch = buf[i];
                sprintf(result + 2 * i++, "%02X", ch);
            }
            printf("Hash: %s\n", result);
            hash = strdup(result);
        }
    }
    else {
        printf("Unable to get IODeviceTree:/chosen port\n");
        hash = NULL;
    }
    return hash;
}

char *find_system_snapshot() {
    const char *hash = copyBootHash();
    size_t len = strlen(hash);
    char *str = (char*)malloc(len + 29);
    memset(str, 0, len + 29); //fill it up with zeros?
    if (!hash) return 0;
    sprintf(str, "com.apple.os.update-%s", hash);
    printf("System snapshot: %s\n", str);
    return str;
}

int do_rename(const char *vol, const char *snap, const char *nw) {
    int dirfd = open(vol, O_RDONLY);
    if (dirfd < 0) {
        perror("open");
        return -1;
    }
    
    int ret = fs_snapshot_rename(dirfd, snap, nw, 0);
    close(dirfd);
    if (ret != 0)
        perror("fs_snapshot_rename");
    return (ret);
}

int remount1131(){
    
    int rv = -1, ret;
    
    if (kCFCoreFoundationVersionNumber > 1451.51 && list_snapshots("/")) { //the second check makes it only run once
        if (init_offsets()) {
            
            vfs_current_context = get_vfs_context();
            
            uint64_t devVnode = getVnodeAtPath("/dev/disk0s1s1");
            uint64_t specinfo = kread64(devVnode + offsetof_v_specinfo);
            
            kwrite32(specinfo + offsetof_specflags, 0);
            
            if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/rootfsmnt"])
                rmdir("/var/rootfsmnt");
            
            mkdir("/var/rootfsmnt", 0777);
            chown("/var/rootfsmnt", 0, 0);
            
            printf("Temporarily setting kern ucred\n");
            uint64_t creds = borrowCredsFromPid(0);
            
        
            if (mountDevAtPathAsRW("/dev/disk0s1s1", "/var/rootfsmnt")) {
                printf("Error mounting root at %s\n", "/var/rootfsmnt");
            }
            else {
                printf("Disabling the APFS snapshot mitigations\n");
                char *snap = find_system_snapshot();
                if (snap && !do_rename("/var/rootfsmnt", snap, "orig-fs")) {
                    rv = 0;
                    unmount("/var/rootfsmnt", 0);
                    rmdir("/var/rootfsmnt");
                }
            }
            printf("Restoring our ucred\n");
            undoCredDonation(creds);
            vnode_put(devVnode);
            
            if (rv) {
                printf("Failed to disable the APFS snapshot mitigations\n");
            }
            else {
                printf("Disabled the APFS snapshot mitigations\n");
                printf("Restarting\n");
                sleep(2);
                kill(1, SIGKILL);
            }
            ret = -1;
        }
        else ret = -1;
    }
    else {
        ret = 0;
        remount1126();
    }
    
    return ret;
}
