# beautifully rootless

So, as some of you know after multi_path was released I immediately started working on a dev-only jailbreak with it. Got the first things ready just a few hours later, those included root, a sandbox escape (without stealing credentials, avoiding a huge mess on the kernel) and a codesign patch. (which is done in 2 phases: 1) use QiLin's castrateAmfid function (which uses Ian Beer's technique) to set a crashy value when amfid validates a binary and then set an exception port on our app where amfid will get redirected once it crashes. There we handle the validation ourselves. However, I did not like that patch because it didn't support all binaries properly and works only when our app is running. amfidebilitate could have been used but I thought of a better method: 2) Use Electra's amfid_payload.dylib which will completely replace the validation function with our own. Differently from Electra, I didn't use the trustcache (which Apple is going to probably mitigate sometime in the future), because the provided technique didn't work due to bad patchfinfing and thus had to platformize the jailbreak app, and inject "com.apple.private.skip-library-validation" & "get-task-allow" into amfid (and of course, the opposite of "get-task-allow" into the jailbreak app. This was done with the help of QiLin as normal entitlement injection didn't work for me)

Later on, I decided to see what was working from the Electra patches, and included on my project a nvram unlock, and host_get_special_port 4 to open tfp0 to any process running as root.

HOWEVER, an important piece was missing, what every jailbreak had in order to be called a jailbreak: a rootfs remount...

SparkZheng had released a write-up on this and I decided to implement it. Wrote the getVnodeAtPath() function (which didn't work as is on KTRR devices for some weird reason), found the required offsets and ran the bypass, but I never could get it to work properly. And SSH would just drop the connection after switching mnt_data.

At that point some people would have given up but I didn't. Every time Apple adds a new mitigation people find a way around it, so who cares if there's no r/w? WE CAN DO IT. First let's think why we need r/w normally:

1. /var is sandboxed as hell
2. A lot of binaries and tweaks expect stuff to be in /
3. idk what else

So, for 1) I had the solution: /var/containers/Bundle is a good place where code execution is allowed with the required entitlements and for 2) I did the obvious thing: patched paths using a hex editor. Paths were mostly /usr/lib and /Library in case of some tweaks. The next problem is that /usr/lib and /Library are reasonably shorter in length than the only possible unsandboxed path /var/containers/Bundle, so I used another workaround. Since symlinks get followed, if we symlink the unsandboxed path into a sandboxed path such as /var/LIB it'd still work. So when you see some random symlinks in /var after using this jailbreak, you know why.

The first rootless patch I did was dropbear, I had been using mach_portal's netcat shell for quite a long time but obviously SSH is a way better option. I replaced /etc/dropbear with /var/dropbear and everything worked smoothly. (no need to symlink here. /var/dropbear is just data). Then to keep dropbear alive I had to support LaunchDaemons and for that I needed a working launchctl. To make launchctl work Electra added it to the trustcache, providing automatic platformization, so what I did to avoid using that was making a new launchAsPlatform function (the same as QiLin's spawnAndPlatformize but open source :D). The idea is simple: use posix_spawn to launch the binary normally but add the SUSPENDED flag so the binary gets paused immediately after spawning, giving us unlimited time to patch it. While it was paused I added the TF_PLATFORM flag on it & set the CS_PLATFORM_BINARY flag. Then I simply ran kill(pid, SIGCONT) ("continue signal") to resume execution and it worked perfectly. I got working launch daemons, without r/w.

Next step was providing the user an automatically platformized launchctl so he has control over the launch daemons. To do that a jailbreakd was required, so I quickly wrote one with all the patches from the jailbreak and made a fake launchctl binary which did the same thing as launchAsPlatform() with the original launchctl. (since launchctl isn't open source). The jailbreakd used CPDistributedMessagingCenter to communicate, for ease of access, however that caused some issues with the next part, so I had to temporarily use Electra's one. (the one from beta's before beta 11, so both open-source and stable). I'm not quite good at low-level IPC so until then will continue to use this.

Now, tweaks. Code injection was already achieved so the only thing left for me to do was patching paths. I grabbed the latest copies of Substitute, Tweak Injector and a tweak and successfully injected. But to keep tweaks alive after a respring we need to automatically inject. All previous jailbreaks did this using launchd. It is always pid 1, and never gets killed (kill 1 = panic), and was used to launch all apps and daemons using xpcproxy so was a perfect target for tweak persistence (NOTE: Not after reboot; but after killing the process; people thought this was an untether). So I started working on a launchd payload based on Electra's. But launchd didn't want to send messages through CPDistruibutedMessagingCenter (and saw nothing in the system logs) and CoreFoundation notifications caused a panic. As I said earlier, the only solution was using jailbreakd and the payload from Electra betas. The original jailbreakd made by me can be found on jakeajames/multi_path. After implementing the jailbreakd tweaks started working immediately without issues, except that all sandboxed apps started crashing. First I thought it was because I didn't update the jailbreakd sandbox exceptions but actually I realized sandboxed apps can't load a library from /var unless it's their OWN container. Without having a fix for now, I decided to whitelist what gets tweaked. The whitelist is as follows:

- Messages
- SpringBoard
- Clock
- Home

## Usage notes

- Binaries are located in: /var/containers/Bundle/iosbinpack64
- Launch daemons are located in /var/containers/Bundle/iosbinpack64/LaunchDaemons
- /var/containers/Bundle/tweaksupport contains a fake filesystem where tweaks and stuff get installed
- Symlinks include: /var/LIB, /var/ulb, /var/bin, /var/sbin

All executables must have at least these two entitlements:

    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>platform-application</key>
        <true/>
        <key>com.apple.private.security.container-required</key>
        <false/>
    </dict>
    </plist>


- Tweaks and stuff get installed in: /var/containers/Bundle/tweaksupport the same way you did with Electra betas.
- Tweaks must be patched using the patcher script provided. (Mac and Linux only) or manually
- PreferenceLoader currently is broken
Usage:
    ./patcher /path/to/deb /path/to/output_folder

Credits to: Ian Beer for multi_path and mach_portal, Jonathan Levin for amfid patch, Jonathan Seals for find_kernel_base, Electra Team (especially stek29) and PsychoTea (@iBSparkes)
