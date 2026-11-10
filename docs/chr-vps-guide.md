# Installing MikroTik CHR on an ISO-Only VPS (HostHatch / Debian 13)

Getting RouterOS CHR onto a KVM VPS that only takes ISOs, no custom disk images. The trick:
`dd` the raw CHR image straight over the provider's disk from a minimal single-user shell, then
hard-reboot.

Yes, you're overwriting the disk of the OS you're running. It's fine. Mostly fine. Keep the VNC
console open.

Tested on HostHatch with a Debian 13 base install and console (VNC) access.

---

## Why this works

The provider installs Debian for you. You're destroying it anyway, so overwrite its disk with
the CHR raw image while it's idle and reboot straight into RouterOS. Do it from a **single-user
shell with root mounted read-only**. Then nothing writes to the disk behind your back.

**Use CHR, not x86 RouterOS.** The x86 ISO looks like the obvious fit for an ISO-only host. But
its paid perpetual licenses are tied to the disk. CHR is the VM edition with free and trial
tiers. You want CHR.

---

## Prerequisites

- A KVM VPS (HostHatch) running Debian 13
- Console / VNC access through the provider panel
- Your network details written down **before you start**: IP, gateway, netmask. You're wiping
  the OS that knows them

---

## Step 1 — Download the CHR image (while in normal Debian)

Fetch the image *before* dropping to single-user mode. That mode has no networking.

```bash
cd /root
wget https://download.mikrotik.com/routeros/7.19.4/chr-7.19.4.img.zip
unzip chr-7.19.4.img.zip
lsblk   # confirm your disk name: usually /dev/vda on KVM, sometimes /dev/sda
```

> Check <https://mikrotik.com/download> for the current CHR version and fix the URL.

---

## Step 2 — Force a boot straight into a root shell

GRUB menus on VPSes are usually too fast to catch, or VNC attaches too late to see them. Don't
race the menu. Bake the parameter into the boot config. Deterministic, and you're wiping this
install anyway.

```bash
nano /etc/default/grub
```

Append `init=/bin/bash` to the kernel command line. Keep whatever's already there:

```
GRUB_CMDLINE_LINUX="init=/bin/bash"
```

Apply and reboot:

```bash
update-grub
reboot
```

Every boot now lands in a root bash shell with `/` mounted read-only. No menu, no timing, no
keystrokes.

> **Still booting into normal Debian?** The host does *direct kernel boot*. The hypervisor loads
> the kernel and skips GRUB. Fall back to dd'ing from the running Debian, or attach a rescue ISO
> (SystemRescue, say) and dd from there.

---

## Step 3 — Copy image to RAM, then dd over the disk

Root is read-only and you're about to overwrite the disk the image lives on. Stage it in tmpfs
first. It's only ~128 MB so it fits in RAM on any VPS.

```bash
mount                                    # verify / is read-only
mount -t tmpfs tmpfs /dev/shm 2>/dev/null || (mkdir /dev/shm && mount -t tmpfs tmpfs /dev/shm)
cp /root/chr-7.19.4.img /dev/shm/
dd if=/dev/shm/chr-7.19.4.img of=/dev/vda bs=4M oflag=direct status=progress
sync
```

Adjust `/dev/vda` if `lsblk` showed a different disk.

---

## Step 4 — Hard reboot (no clean shutdown)

No graceful shutdown. You don't want anything writing filesystem data back over what you just
wrote. Reboot immediately via sysrq:

```bash
echo 1 > /proc/sys/kernel/sysrq   # enable sysrq if needed
echo b > /proc/sysrq-trigger
```

(Or just use the panel's force-reset button.)

---

## Step 5 — First boot into RouterOS

Watch VNC for the RouterOS boot. Log in:

- **User:** `admin`
- **Password:** blank (you'll be prompted to set one)

DHCP didn't pick up the address? Set it by hand:

```
/ip address add address=x.x.x.x/24 interface=ether1
/ip route add gateway=x.x.x.1
```

---

## Step 6 — Post-install housekeeping

- **Set a strong admin password** if you weren't prompted.
- **License:** check the trial clock and sort out a license before the 24-hour trial runs out:
  ```
  /system license print
  ```
  A free MikroTik account gets you the free tier (1 Mbps/interface cap). Or pay for more.
- **Grow the partition:** the image only claims ~128 MB. RouterOS 7 can expand into the rest of
  the disk (`/disk` resize, or it auto-grows on newer builds).
- **Firewall / services:** this box sits on a public IP. Tighten the input chain, restrict WinBox
  / SSH / API to your own IPs and turn off unused services under `/ip service`.

---

## Quick reference (the whole flow)

```bash
# --- In normal Debian ---
cd /root
wget https://download.mikrotik.com/routeros/7.19.4/chr-7.19.4.img.zip
unzip chr-7.19.4.img.zip
lsblk

nano /etc/default/grub          # GRUB_CMDLINE_LINUX="init=/bin/bash"
update-grub
reboot

# --- In the init=/bin/bash root shell ---
mount -t tmpfs tmpfs /dev/shm 2>/dev/null || (mkdir /dev/shm && mount -t tmpfs tmpfs /dev/shm)
cp /root/chr-7.19.4.img /dev/shm/
dd if=/dev/shm/chr-7.19.4.img of=/dev/vda bs=4M oflag=direct status=progress
sync
echo 1 > /proc/sys/kernel/sysrq
echo b > /proc/sysrq-trigger

# --- In RouterOS (VNC console) ---
# login admin / blank password, set new password
# /ip address add address=x.x.x.x/24 interface=ether1
# /ip route add gateway=x.x.x.1
# /system license print
```
