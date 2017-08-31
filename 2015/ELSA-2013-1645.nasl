# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-1645.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.com> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://solinor.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
if(description)
 {
script_oid("1.3.6.1.4.1.25623.1.0.123528");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:05:06 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-1645");
script_tag(name: "insight", value: "ELSA-2013-1645
- Oracle Linux 6 kernel update
- [2.6.32-431]
- [md] Disabling of TRIM on RAID5 for RHEL6.5 was too aggressive (Jes Sorensen) [1028426] [2.6.32-430]
- [x86] Revert 'efi: be more paranoid about available space when creating variables' (Rafael Aquini) [1012370 1023173]
- [x86] Revert 'efivars: firmware bug workarounds should be in platform code' (Rafael Aquini) [1012370 1023173]
- [x86] Revert 'efi: Export efi_query_variable_store() for efivars.ko' (Rafael Aquini) [1012370 1023173]
- [x86] Revert 'efi: Check max_size only if it is non-zero' (Rafael Aquini) [1012370 1023173]
- [x86] Revert 'efi: Distinguish between 'remaining space' and actually used space' (Rafael Aquini) [1012370 1023173]
- [x86] Revert 'efi: Implement efi_no_storage_paranoia parameter' (Rafael Aquini) [1012370 1023173]
- [x86] Revert 'Modify UEFI anti-bricking code' (Rafael Aquini) [1012370 1023173]
- [x86] Revert 'efi: Fix dummy variable buffer allocation' (Rafael Aquini) [1012370 1023173] [2.6.32-429]
- [fs] revert xfs: prevent deadlock trying to cover an active log (Eric Sandeen) [1014867] [2.6.32-428]
- [fs] Revert 'vfs: allow umount to handle mountpoints without revalidating them' (Rafael Aquini) [1024607]
- [fs] Revert 'vfs: massage umount_lookup_last() a bit to reduce nesting' (Rafael Aquini) [1024607]
- [fs] Revert 'vfs: rename user_path_umountat() to user_path_mountpoint_at()' (Rafael Aquini) [1024607]
- [fs] Revert 'vfs: introduce kern_path_mountpoint()' (Rafael Aquini) [1024607]
- [fs] Revert 'autofs4: fix device ioctl mount lookup' (Rafael Aquini) [1024607] [2.6.32-427]
- [tools] perf: Add ref-cycles into array of tested events (Jiri Olsa) [968806]
- [pci] Revert 'make SRIOV resources optional' (Myron Stowe) [1022270]
- [pci] Revert 'ability to relocate assigned pci-resources' (Myron Stowe) [1022270]
- [pci] Revert 'honor child buses add_size in hot plug configuration' (Myron Stowe) [1022270]
- [pci] Revert 'make cardbus-bridge resources optional' (Myron Stowe) [1022270]
- [pci] Revert 'code and comments cleanup' (Myron Stowe) [1022270]
- [pci] Revert 'make re-allocation try harder by reassigning ranges higher in the heirarchy' (Myron Stowe) [1022270]
- [pci] Revert 'Calculate right add_size' (Myron Stowe) [1022270] [2.6.32-426]
- [block] loop: unplug_fn only when backing file is attached (Lukas Czerner) [1022997]
- [fs] ext4: Remove warning from ext4_da_update_reserve_space() (Lukas Czerner) [1011876]
- [kernel] async: Revert MAX_THREADS to 256 (Neil Horman) [1021705]
- [net] ipv6: restrict neighbor entry creation to output flow (Jiri Pirko) [997103]
- [net] ipv6: udp packets following an UFO enqueued packet need also be handled by UFO (Jiri Pirko) [1011930] {CVE-2013-4387}
- [net] ipv4: blackhole route should always be recalculated (Herbert Xu) [1010347]
- [net] unix: revert/fix race in stream sockets with SOCK_PASS* flags (Daniel Borkmann) [1019343]
- [net] Loosen constraints for recalculating checksum in skb_segment() (Vlad Yasevich) [1020298]
- [drm] nouveau: fix vblank deadlock (Rob Clark) [1013388]
- [usb] xhci: refactor EHCI/xHCI port switching (Don Zickus) [970715]
- [fs] compat_ioctl: VIDEO_SET_SPU_PALETTE missing error check (Phillip Lougher) [949573] {CVE-2013-1928}
- [fs] vfs: fix d_mountpoint() (Ian Kent) [1011337]
- [fs] autofs4: fix device ioctl mount lookup (Ian Kent) [999708]
- [fs] vfs: introduce kern_path_mountpoint() (Ian Kent) [999708]
- [fs] vfs: rename user_path_umountat() to user_path_mountpoint_at() (Ian Kent) [999708]
- [fs] vfs: massage umount_lookup_last() a bit to reduce nesting (Ian Kent) [999708]
- [fs] vfs: allow umount to handle mountpoints without revalidating them (Ian Kent) [999708]
- [fs] nfs: Remove the 'FIFO' behaviour for nfs41_setup_sequence (Steve Dickson) [1022257]
- [fs] nfs: Record the OPEN create mode used in the nfs4_opendata structure (Steve Dickson) [1019439]
- [fs] nfs: Simulate the change attribute (Steve Dickson) [1018653]
- [scsi] megaraid_sas: Fix synchronization problem between sysPD IO path and AEN path (Tomas Henzl) [1019811] [2.6.32-425]
- [md] dm-snapshot: fix data corruption (Mikulas Patocka) [974481] {CVE-2013-4299}
- [watchdog] iTCO_wdt: add platform driver module alias (Neil Horman) [1019497]
- [hda] alsa: disable 44.1kHz rate for Haswell HDMI/DP audio (Jaroslav Kysela) [831970]
- [x86] Update UV3 hub revision ID (George Beshers) [1018962]
- [fs] xfs: Don't reference the EFI after it is freed (Eric Sandeen) [1018469]
- [security] keys: Fix a race between negating a key and reading the error set (Dave Wysochanski) [890231]
- [fs] nfsv4: Ensure memory ordering between nfs4_ds_connect and nfs4_fl_prepare_ds (Jeff Layton) [1012439]
- [fs] nfsv4: nfs4_fl_prepare_ds
- fix bugs when the connect attempt fails (Jeff Layton) [1012439]
- [md] Disable TRIM on RAID5 for RHEL 6.5 (Jes Sorensen) [837097]
- [md] raid5: BIO_RW_SYNCIO is a bit number, not a bitmask (Jes Sorensen) [837097]
- [virt] hyperv: framebuffer pci stub (Gerd Hoffmann) [1013335]
- [netdrv] bnx2x: add missing enum channel_tlvs definitions (Michal Schmidt) [1015137]
- [netdrv] bnx2x: KR2 disablement fix (Michal Schmidt) [1015137]
- [netdrv] bnx2x: Specific Active-DAC is not detected on 57810 (Michal Schmidt) [1015137]
- [netdrv] bnx2x: Generalize KR work-around (Michal Schmidt) [1015137]
- [usb] usbnet: use ethd name for known ethernet devices (Don Zickus) [1014224]
- [usb] cdc_ether: use ethd name for known ethernet devices (Don Zickus) [1014224]
- [mm] Revert 'Find_early_table_space based on ranges that are actually being mapped' (Rafael Aquini)
- [mm] Revert 'Exclude E820_RESERVED regions and memory holes above 4 GB from direct mapping' (Rafael Aquini)
- [mm] Revert 'Group e820 entries together and add map_individual_e820 boot option' (Rafael Aquini)
- [net] bridge: update mdb expiration timer upon reports (Vlad Yasevich) [1013816]
- [net] veth: Remove NETIF_F_HW_VLAN_RX capability (Thomas Graf) [1018158]
- [net] gre/vxlan: handle 802.1Q inner header properly (Thomas Graf) [997632]
- [net] disable the new NAPI weight error message for RHEL 6.5 (Michal Schmidt) [1012090]
- [scsi] sd: Fix parsing of 'temporary ' cache mode prefix (Ewan Milne) [955441]
- [scsi] sd: fix array cache flushing bug causing performance problems (Ewan Milne) [955441]
- [scsi] bfa: firmware update to 3.2.1.1 (Rob Evers) [1002770]
- [netdrv] bna: firmware update to 3.2.1.1 (Ivan Vecera) [1002771] [2.6.32-424]
- [block] loop: fix crash when using unassigned loop device (Mike Snitzer) [989795]
- [fs] xfs: prevent deadlock trying to cover an active log (Dave Chinner) [1014867]
- [x86] microcode: Fix patch level reporting for AMD family 15h (Prarit Bhargava) [1014401]
- [hda] alsa: enable switcheroo code in the snd-hda-intel driver (Jaroslav Kysela) [1013993]
- [x86] reboot: Fix a warning message triggered by stop_other_cpus() (Jerome Marchand) [840710]
- [kernel] async: Bump up the MAX_THREADS count for the async subsystem (Neil Horman) [1010666]
- [pci] Calculate right add_size (Myron Stowe) [997672]
- [netdrv] iwlwifi: pcie: add SKUs for 6000, 6005 and 6235 series (Stanislaw Gruszka) [1013951]
- [netdrv] iwlwifi: pcie: add new SKUs for 7000 & 3160 NIC series (Stanislaw Gruszka) [1013951]
- [netdrv] iwlwifi: enable shadow registers for 7000 (Stanislaw Gruszka) [1013951]
- [netdrv] iwlwifi: add new 7260 and 3160 series device IDs (Stanislaw Gruszka) [1013951]
- [netdrv] be2net: pass if_id for v1 and V2 versions of TX_CREATE cmd (Ivan Vecera) [1014360]
- [netdrv] be2net: call ENABLE_VF cmd for Skyhawk-R too (Ivan Vecera) [1014360]
- [netdrv] be2net: Fix to prevent Tx stall on SH-R when packet size < 32 (Ivan Vecera) [1014360]
- [scsi] pm8001: Queue rotation logic for inbound and outbound queues (Rich Bono) [1013771]
- [scsi] lpfc: Update lpfc version for 8.3.7.21.4p driver release (Rob Evers) [1004841]
- [scsi] lpfc: Fixed spinlock hang (Rob Evers) [1004841]
- [scsi] lpfc: Fixed spinlock inversion problem (Rob Evers) [1004841]
- [scsi] lpfc: Fixed inconsistent spin lock useage (Rob Evers) [1004841]
- [scsi] qla2xxx: Update version number to 8.05.00.03.06.5-k2 (Chad Dupuis) [912652]
- [scsi] qla2xxx: Fix request queue null dereference (Chad Dupuis) [912652]
- [net] tcp: TSQ can use a dynamic limit (Jiri Pirko) [996802]
- [net] tcp: TSO packets automatic sizing (Jiri Pirko) [996802]
- [net] tcp: Apply device TSO segment limit earlier (Jiri Pirko) [996802]
- [net] Allow driver to limit number of GSO segments per skb (Jiri Pirko) [996802]
- [net] cleanups in RX queue allocation (Ivan Vecera) [1012388]
- [net] Update kernel-doc for netif_set_real_num_rx_queues() (Ivan Vecera) [1012388]
- [net] netif_set_real_num_rx_queues may cap num_rx_queues at init time (Ivan Vecera) [1012388] [2.6.32-423]
- [kvm] pmu: add proper support for fixed counter 2 (Gleb Natapov) [1000956]
- [kvm] vmx: do not check bit 12 of EPT violation exit qualification when undefined (Gleb Natapov) [1006139]
- [kvm] vmx: set 'blocked by NMI' flag if EPT violation happens during IRET from NMI (Gleb Natapov) [1006139]
- [edac] Fix workqueue-related crashes (Aristeu Rozanski) [831127]
- [edac] amd64_edac: Fix driver module removal (Aristeu Rozanski) [831127]
- [md] raid5: BIO flags adjust (Jes Sorensen) [837097]
- [md] Fix skipping recovery for read-only arrays (Jes Sorensen) [1014102]
- [kernel] audit: fix mq_open and mq_unlink to add the MQ root as a hidden parent audit_names record (Richard Guy Briggs) [1009386]
- [kernel] audit: log the audit_names record type (Richard Guy Briggs) [1009386]
- [kernel] audit: add child record before the create to handle case where create fails (Richard Guy Briggs) [1009386]
- [kernel] audit: format user messages to size of MAX_AUDIT_MESSAGE_LENGTH (Richard Guy Briggs) [1007069]
- [netdrv] tg3: Expand led off fix to include 5720 (Ivan Vecera) [991498]
- [netdrv] tg3: Don't turn off led on 5719 serdes port 0 (Ivan Vecera) [991498]
- [netdrv] tg3: Don't turn off led on 5719 serdes port 0 (Ivan Vecera) [991498]
- [netdrv] tg3: Fix UDP fragments treated as RMCP (Ivan Vecera) [991498]
- [netdrv] tg3: Remove incorrect switch to aux power (Ivan Vecera) [991498]
- [i2c] ismt: initialize DMA buffer (Neil Horman) [1014753]
- [scsi] libfcoe: Make fcoe_sysfs optional / fix fnic NULL exception (Neil Horman) [1014864]
- [fs] gfs2: Fix race in iteration of glocks for unfreeze/umount (Abhijith Das) [999909]
- [fs] gfs2: dirty inode correctly in gfs2_write_end (Benjamin Marzinski) [991596]
- [x86] Mark Intel Atom Avoton processor as supported (Prarit Bhargava) [914842]
- [mm] vmscan: fix zone shrinking exit when scan work is done (David Gibson) [985155]
- [block] free bios when failing blk_execute_rq_nowait calls (Jeff Moyer) [1009312]
- [netdrv] be2net: fix disabling TX in be_close() (Ivan Vecera) [951271]
- [crypto] Fix race condition in larval lookup (Herbert Xu) [916361] [2.6.32-422]
- [fs] fuse: drop dentry on failed revalidate (Brian Foster) [924014]
- [fs] fuse: clean up return in fuse_dentry_revalidate() (Brian Foster) [924014]
- [fs] fuse: use d_materialise_unique() (Brian Foster) [924014]
- [mm] Group e820 entries together and add map_individual_e820 boot option (Larry Woodman) [876275]
- [mm] Exclude E820_RESERVED regions and memory holes above 4 GB from direct mapping (Larry Woodman) [876275]
- [mm] Find_early_table_space based on ranges that are actually being mapped (Larry Woodman) [876275]
- [hid] pantherlord: heap overflow flaw (Radomir Vrbovsky) [1000435] {CVE-2013-2892}
- [virt] hv: Correctly support ws2008R2 and earlier (Jason Wang) [1007341]
- [powerpc] iommu: Use GFP_KERNEL instead of GFP_ATOMIC in iommu_init_table() (Steve Best) [1012666]
- [powerpc] Add isync to copy_and_flush (Steve Best) [1014475]
- [block] rsxx: Kernel Panic caused by mapping Discards (Steve Best) [1013728]
- [kernel] audit: avoid soft lockup due to audit_log_start() incorrect loop termination (Richard Guy Briggs) [990806]
- [fs] nfsv4: Remove the BUG_ON() from nfs4_get_lease_time_prepare() (Steve Dickson) [1012688]
- [netdrv] bnx2x: fix loss of VLAN priority information in received TPA-aggregated packets (Michal Schmidt) [1014694]
- [fs] gfs2: garbage quota usage reported due to uninitialized inode during creation (Abhijith Das) [1008947]
- [fs] nfs: fix filelayout_commit_call_ops (Scott Mayhew) [1012479]
- [netdrv] igb: fix driver reload with VF assigned to guest (Stefan Assmann) [985733]
- [md] Fix bio flags for md raid5 (Jes Sorensen) [837097]
- [md] Fix bio flags for md raid10 (Jes Sorensen) [837097]
- [scsi] qla4xxx: 5.03.00.00.06.05-k3 (Chad Dupuis) [1011476]
- [scsi] qla4xxx: Support setting of local CHAP index for flash target entry (Chad Dupuis) [1011476]
- [scsi] qla4xxx: Correct the check for local CHAP entry type (Chad Dupuis) [1011476]
- [scsi] lpfc: Update lpfc version for 8.3.7.21.3p driver release (Rob Evers) [1012961]
- [scsi] lpfc: Fixed function mode field defined too small for not recognizing dual-chute mode (Rob Evers) [1012961]
- [net] Revert 'net: more accurate skb truesize' (Francesco Fusco) [889181]
- [net] fix multiqueue selection (Michal Schmidt) [1011939] [2.6.32-421]
- [scsi] bnx2fc: Bump version from 1.0.14 to 2.4.1 (Tomas Henzl) [1008733]
- [scsi] bnx2fc: hung task timeout warning observed when rmmod bnx2x with active FCoE targets (Tomas Henzl) [1008733]
- [scsi] bnx2fc: Fixed a SCSI CMD cmpl race condition between ABTS and CLEANUP (Tomas Henzl) [1008733]
- [scsi] cnic: Fix crash in, cnic_bnx2x_service_kcq() (Tomas Henzl) [1004554]
- [hid] zeroplus: validate output report details (Frantisek Hrbata) [999906] {CVE-2013-2889}
- [hid] provide a helper for validating hid reports (Frantisek Hrbata) [999906] {CVE-2013-2889}
- [netdrv] sfc: Add SIOCEFX:EFX_MCDI_REQUEST ioctl to workaround MTD limits (Nikolay Aleksandrov) [1008705]
- [netdrv] sfc: deny changing of unsupported flags (Nikolay Aleksandrov) [1010840]
- [kernel] __ptrace_may_access() should not deny sub-threads (Oleg Nesterov) [927360]
- [tools] perf: Make kmem work for non numa machines (Jiri Olsa) [984788]
- [powerpc] Bring all threads online prior to migration/hibernation (Steve Best) [1010528]
- [kvm] introduce guest count uevent (Paolo Bonzini) [1004802]
- [scsi] iscsi_tcp: consider session state in iscsi_sw_sk_state_check (Chris Leech) [840638]
- [crypto] ansi_cprng: Fix off by one error in non-block size request (Neil Horman) [1007694] {CVE-2013-4345}
- [infiniband] cache: don't fill the cache with junk (Doug Ledford) [920306]
- [usb] core: don't try to reset_device() a port that got just disconnected (Don Zickus) [1000944]
- [usb] Fix connected device switch to Inactive state (Don Zickus) [1000944]
- [usb] Don't use EHCI port sempahore for USB 3.0 hubs (Don Zickus) [1000944]
- [netdrv] macvtap: Ignore tap features when VNET_HDR is off (Vlad Yasevich) [987201]
- [netdrv] macvtap: Correctly set tap features when IFF_VNET_HDR is disabled (Vlad Yasevich) [987201]
- [netdrv] macvtap: simplify usage of tap_features (Vlad Yasevich) [987201]
- [infiniband] mlx4: Use default pkey when creating tunnel QPs (Doug Ledford) [993587]
- [infiniband] core: Create QP1 using the pkey index which contains the default pkey (Doug Ledford) [993587]
- [infiniband] ipoib: Make sure child devices use valid/proper pkeys (Doug Ledford) [993587]
- [infiniband] ipoib: Fix pkey change flow for virtualization environments (Doug Ledford) [993587]
- [netdrv] igb: don't deprecate the max_vfs parameter (Stefan Assmann) [1005877]
- [netdrv] igb: Read flow control for i350 from correct EEPROM section (Stefan Assmann) [1005877]
- [netdrv] igb: Add additional get_phy_id call for i354 devices (Stefan Assmann) [1005877]
- [netdrv] igb: Update version number (Stefan Assmann) [1005877]
- [netdrv] igb: Implementation to report advertised/supported link on i354 devices (Stefan Assmann) [1005877]
- [netdrv] igb: Get speed and duplex for 1G non_copper devices (Stefan Assmann) [1005877]
- [netdrv] igb: Support to get 2_5G link status for appropriate media type (Stefan Assmann) [1005877]
- [netdrv] igb: No PHPM support in i354 devices (Stefan Assmann) [1005877]
- [netdrv] igb: M88E1543 PHY downshift implementation (Stefan Assmann) [1005877]
- [netdrv] igb: New PHY_ID for i354 device (Stefan Assmann) [1005877]
- [netdrv] igb: Implementation of 1-sec delay for i210 devices (Stefan Assmann) [1005877]
- [netdrv] igb: Don't look for a PBA in the iNVM when flashless (Stefan Assmann) [1005877]
- [netdrv] igb: Expose RSS indirection table for ethtool (Stefan Assmann) [1005877]
- [netdrv] igb: Add macro for size of RETA indirection table (Stefan Assmann) [1005877]
- [netdrv] igb: Fix get_fw_version function for all parts (Stefan Assmann) [1005877]
- [netdrv] igb: Add device support for flashless SKU of i210 device (Stefan Assmann) [1005877]
- [netdrv] igb: Refactor NVM read functions to accommodate devices with no flash (Stefan Assmann) [1005877]
- [netdrv] igb: Refactor of init_nvm_params (Stefan Assmann) [1005877]
- [netdrv] igb: Update MTU so that it is always at least a standard frame size (Stefan Assmann) [1005877]
- [netdrv] igb: don't allow SR-IOV without MSI-X (Stefan Assmann) [1005877]
- [netdrv] igb: Added rcu_lock to avoid race (Stefan Assmann) [1005877]
- [netdrv] igb: Read register for latch_on without return value (Stefan Assmann) [1005877]
- [netdrv] igb: Reset the link when EEE setting changed (Stefan Assmann) [1005877]
- [netdrv] treewide: relase -> release (Stefan Assmann) [1005877]
- [scsi] iterate over devices individually for /proc/scsi/scsi (David Milburn) [966170]
- [scsi] zfcp: fix lock imbalance by reworking request queue locking (Mikulas Patocka) [803592]
- [kernel] pidns: fix two invalid task_active_pid_ns() usages (Aristeu Rozanski) [984597]
- [netdrv] be2net: implement ethtool set/get_channel hooks (Ivan Vecera) [975885]
- [netdrv] be2net: refactor be_setup() to consolidate queue creation routines (Ivan Vecera) [975885]
- [netdrv] be2net: Fix be_cmd_if_create() to use MBOX if MCCQ is not created (Ivan Vecera) [975885]
- [netdrv] be2net: refactor be_get_resources() code (Ivan Vecera) [975885]
- [netdrv] be2net: don't limit max MAC and VLAN counts (Ivan Vecera) [975885]
- [netdrv] be2net: Fixup profile management routines (Ivan Vecera) [975885]
- [netdrv] be2net: use EQ_CREATEv2 for SH-R (Ivan Vecera) [975885]
- [netdrv] be2net: delete primary MAC address while unloading (Ivan Vecera) [874733]
- [netdrv] be2net: use SET/GET_MAC_LIST for SH-R (Ivan Vecera) [874733]
- [netdrv] be2net: refactor MAC-addr setup code (Ivan Vecera) [874733]
- [netdrv] be2net: fix pmac_id for BE3 VFs (Ivan Vecera) [874733]
- [netdrv] be2net: allow VFs to program MAC and VLAN filters (Ivan Vecera) [874733]
- [netdrv] be2net: fix MAC address modification for VF (Ivan Vecera) [874733]
- [netdrv] be2net: don't use dev_err when AER enabling fails (Ivan Vecera) [986513]
- [netdrv] be2net: Clear any capability flags that driver is not interested in (Ivan Vecera) [998856]
- [net] ethtool: fix RHEL backport of ETHTOOL_RESET (Jiri Benc) [1008678]
- [net] gact: Fix potential panic in tcf_gact() (Jiri Benc) [1003781]
- [net] tcp: fix FIONREAD/SIOCINQ (Francesco Fusco) [1001479]
- [net] vxlan: Avoid creating fdb entry with NULL destination (Amerigo Wang) [923915]
- [net] bridge: sync the definition of struct br_mdb_entry with upstream (Amerigo Wang) [1010251]
- [fs] proc/ns: Fix ABI of proc_inode (Thomas Graf) [1005224]
- [fs] nfs: Fix writeback performance issue on cache invalidation (Scott Mayhew) [1010038]
- [fs] xfs: switch stacks for bmap btree modifications (Dave Chinner) [918359]
- [fs] GFS2: Dont flag consistency error if first mounter is a spectator (Robert S Peterson) [997929]
- [x86] Mark Intel Haswell-EP as supported (Prarit Bhargava) [948339]
- [s390] tx: allow program interruption filtering in user space (Hendrik Brueckner) [1006523]
- [tty] hvc_iucv: Disconnect IUCV connection when lowering DTR (Hendrik Brueckner) [1007570]
- [tty] hvc_console: Add DTR/RTS callback to handle HUPCL control (Hendrik Brueckner) [1007570]
- [netdrv] bonding: fix bond_arp_rcv setting and arp validate desync state (Nikolay Aleksandrov) [1003697]
- [netdrv] bonding: fix store_arp_validate race with mode change (Nikolay Aleksandrov) [1003697]
- [netdrv] bonding: fix set mode race conditions (Nikolay Aleksandrov) [1003697]
- [bluetooth] rfcomm: Fix info leak in RFCOMMGETDEVLIST ioctl() (Radomir Vrbovsky) [922409] {CVE-2012-6545}
- [bluetooth] rfcomm: Fix info leak via getsockname() (Radomir Vrbovsky) [922409] {CVE-2012-6545}
- [mm] mlock: operate on any regions with protection != PROT_NONE (Larry Woodman) [982460]
- [mm] mlock: avoid dirtying pages and triggering writeback (Larry Woodman) [982460]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-1645");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-1645.html");
script_cve_id("CVE-2012-6542","CVE-2013-1929","CVE-2012-6545","CVE-2013-3231","CVE-2013-2164","CVE-2013-2234","CVE-2013-2851","CVE-2013-0343","CVE-2013-4345","CVE-2013-1928","CVE-2013-2888","CVE-2013-2889","CVE-2013-2892","CVE-2013-4387","CVE-2013-4591","CVE-2013-4592");
script_tag(name:"cvss_base", value:"6.2");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_copyright("Eero Volotinen");
script_family("Oracle Linux Local Security Checks");
exit(0);
}
include("revisions-lib.inc");
include("pkg-lib-rpm.inc");
release = get_kb_item("ssh/login/release");
res = "";
if(release == NULL)
{
 exit(0);
}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~431.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~431.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~431.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~431.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~431.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~431.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~431.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~431.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~431.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~431.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

