# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-3012.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123155");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 09:48:35 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-3012");
script_tag(name: "insight", value: "ELSA-2015-3012 - Unbreakable Enterprise kernel security  and bugfix update - kernel-uek[3.8.13-68]- ttusb-dec: buffer overflow in ioctl (Dan Carpenter) [Orabug: 20673373] {CVE-2014-8884}- mm: Fix NULL pointer dereference in madvise(MADV_WILLNEED) support (Kirill A. Shutemov) [Orabug: 20673279] {CVE-2014-8173}- netfilter: conntrack: disable generic tracking for known protocols (Florian Westphal) [Orabug: 20673235] {CVE-2014-8160}[3.8.13-67]- sparc64: Remove deprecated __GFP_NOFAIL from mdesc_kmalloc (Eric Snowberg) [Orabug: 20055909] - x86/xen: allow privcmd hypercalls to be preempted (David Vrabel) [Orabug: 20618880] - sched: Expose preempt_schedule_irq() (Thomas Gleixner) [Orabug: 20618880] - xen-netfront: Fix handling packets on compound pages with skb_linearize (Zoltan Kiss) [Orabug: 19546077] - qla2xxx: Add adapter checks for FAWWN functionality. (Saurav Kashyap) [Orabug: 20474227] - config: enable CONFIG_MODULE_SIG_SHA512 (Guangyu Sun) [Orabug: 20611400] - net: rds: use correct size for max unacked packets and bytes (Sasha Levin) [Orabug: 20585918] - watchdog: w83697hf_wdt: return ENODEV if no device was found (Stanislav Kholmanskikh) [Orabug: 18122938] - NVMe: Disable pci before clearing queue (Keith Busch) [Orabug: 20564650][3.8.13-66]- bnx2fc: upgrade to 2.8.2 (Dan Duval) [Orabug: 20523502] - bnx2i: upgrade to 2.11.0.0 (Dan Duval) [Orabug: 20523502] - bnx2x: upgrade to 1.712.10 (Dan Duval) [Orabug: 20523502] - cnic: upgrade to 2.721.01 (Dan Duval) [Orabug: 20523502] - bnx2: upgrade to 2.712.01 (Dan Duval) [Orabug: 20523502] - Update lpfc version for 10.6.61 (rkennedy) [Orabug: 20539686] - Remove consolidated merge lines from previous patch, they require a 3.19 kernel to build with. (rkennedy) [Orabug: 20539686] - Implement support for wire-only DIF devices (rkennedy) [Orabug: 20539686] - lpfc: Update copyright to 2015 (rkennedy) [Orabug: 20539686] - lpfc: Update Copyright on changed files (James Smart) [Orabug: 20539686] - lpfc: Fix for lun discovery issue with 8Gig adapter. (rkennedy) [Orabug: 20539686] - lpfc: Fix crash in device reset handler. (rkennedy) [Orabug: 20539686] - lpfc: application causes OS crash when running diagnostics (rkennedy) [Orabug: 20539686] - lpfc: Fix internal loopback failure (rkennedy) [Orabug: 20539686] - lpfc: Fix premature release of rpi bit in bitmask (rkennedy) [Orabug: 20539686] - lpfc: Initiator sends wrong BBCredit value for either FLOGI or FLOGI_ACC (rkennedy) [Orabug: 20539686] - lpfc: Fix null ndlp derefernce in target_reset_handler (rkennedy) [Orabug: 20539686] - lpfc: Fix FDMI Fabric support (rkennedy) [Orabug: 20539686] - lpfc: Fix provide host name and OS name in RSNN-NN FC-GS command (rkennedy) [Orabug: 20539686] - lpfc: Parse the new 20G, 25G and 40G link speeds in the lpfc driver (rkennedy) [Orabug: 20539686] - lpfc: lpfc does not support option_rom_version sysfs attribute on newer adapters (rkennedy) [Orabug: 20539686] - lpfc: Fix setting of EQ delay Multiplier (rkennedy) [Orabug: 20539686] - lpfc: Fix host reset escalation killing all IOs. (rkennedy) [Orabug: 20539686] - lpfc: Linux lpfc driver doesnt re-establish the link after a cable pull on LPe12002 (rkennedy) [Orabug: 20539686] - lpfc: Fix to handle PLOGI when already logged in (rkennedy) [Orabug: 20539686] - lpfc: EnableBootCode from hbacmd fails on Lancer (rkennedy) [Orabug: 20539686] - lpfc: Add Lancer Temperature Event support to the lpfc driver (rkennedy) [Orabug: 20539686] - lpfc: Fix the iteration count to match the 30 sec comment (rkennedy) [Orabug: 20539686] - lpfc: fix low priority issues from fortify source code scan (James Smart) [Orabug: 20539686] - lpfc: fix high priority issues from fortify source code scan (James Smart) [Orabug: 20539686] - lpfc: fix for handling unmapped ndlp in target reset handler (James Smart) [Orabug: 20539686] - lpfc: fix crash from page fault caused by use after rport delete (James Smart) [Orabug: 20539686] - lpfc: fix locking issues with abort data paths (James Smart) [Orabug: 20539686] - lpfc: fix race between LOGO/PLOGI handling causing NULL pointer (James Smart) [Orabug: 20539686] - lpfc: fix quarantined XRI recovery qualifier state in link bounce (James Smart) [Orabug: 20539686] - lpfc: fix discovery timeout during nameserver login (James Smart) [Orabug: 20539686] - lpfc: fix IP Reset processing - wait for RDY before proceeding (James Smart) [Orabug: 20539686] - lpfc: Update lpfc version to driver version 10.2.8000.0 (James Smart) [Orabug: 20539686] - net: Check for presence of IFLA_AF_SPEC (Thomas Graf) [Orabug: 20382857] - net: Validate IFLA_BRIDGE_MODE attribute length (Thomas Graf) [Orabug: 20382857] - be2net: fix alignment on line wrap (Kalesh AP) [Orabug: 20382857] - be2net: remove multiple assignments on a single line (Kalesh AP) [Orabug: 20382857] - be2net: remove space after typecasts (Kalesh AP) [Orabug: 20382857] - be2net: remove unnecessary blank lines after an open brace (Kalesh AP) [Orabug: 20382857] - be2net: insert a blank line after function/struct//enum definitions (Kalesh AP) [Orabug: 20382857] - be2net: remove multiple blank lines (Kalesh AP) [Orabug: 20382857] - be2net: add blank line after declarations (Kalesh AP) [Orabug: 20382857] - be2net: remove return statements for void functions (Kalesh AP) [Orabug: 20382857] - be2net: add speed reporting for 20G-KR interface (Vasundhara Volam) [Orabug: 20382857] - be2net: add speed reporting for 40G/KR interface (Kalesh AP) [Orabug: 20382857] - be2net: fix sparse warnings in be_cmd_req_port_type{} (Suresh Reddy) [Orabug: 20382857] - be2net: fix a sparse warning in be_cmd_modify_eqd() (Kalesh AP) [Orabug: 20382857] - enic: fix rx napi poll return value (Govindarajulu Varadarajan) [Orabug: 20342354] - net: rename vlan_tx_* helpers since 'tx' is misleading there (Jiri Pirko) [Orabug: 20342354] - enic: free all rq buffs when allocation fails (Govindarajulu Varadarajan) [Orabug: 20342354] - net: ethernet: cisco: enic: enic_dev: Remove some unused functions (Rickard Strandqvist) [Orabug: 20342354] - enic: add stats for dma mapping error (Govindarajulu Varadarajan) [Orabug: 20342354] - enic: check dma_mapping_error (Govindarajulu Varadarajan) [Orabug: 20342354] - enic: make vnic_wq_buf doubly linked (Govindarajulu Varadarajan) [Orabug: 20342354] - enic: fix rx skb checksum (Govindarajulu Varadarajan) [Orabug: 20342354] - enic: fix work done in tx napi_poll (Govindarajulu Varadarajan) [Orabug: 20342354] - enic: update desc properly in rx_copybreak (Govindarajulu Varadarajan) [Orabug: 20342354] - enic: handle error condition properly in enic_rq_indicate_buf (Govindarajulu Varadarajan) [Orabug: 20342354] - enic: Do not call napi_disable when preemption is disabled. (Govindarajulu Varadarajan) [Orabug: 20342354] - enic: fix possible deadlock in enic_stop/ enic_rfs_flw_tbl_free (Govindarajulu Varadarajan) [Orabug: 20342354] - drivers/net: Convert remaining uses of pr_warning to pr_warn (Joe Perches) [Orabug: 20342354] - enic: implement rx_copybreak (Govindarajulu Varadarajan) [Orabug: 20342354] - PCI: Remove DEFINE_PCI_DEVICE_TABLE macro use (Benoit Taine) [Orabug: 20342354] - enic: add pci_zalloc_consistent to kcompat.h (Govindarajulu Varadarajan) [Orabug: 20342354] - enic: use pci_zalloc_consistent (Joe Perches) [Orabug: 20342354] - enic: Add ethtool support to show classifier filters added by the driver (Govindarajulu Varadarajan) [Orabug: 20342354] - enic: remove #ifdef CONFIG_RFS_ACCEL around filter structures (Govindarajulu Varadarajan) [Orabug: 20342354] - enic: fix return values in enic_set_coalesce (Govindarajulu Varadarajan) [Orabug: 20342354] - enic: fix compile issue when CONFIG_NET_RX_BUSY_POLL is N (Govindarajulu Varadarajan) [Orabug: 20342354] - enic: add kcompat file (Govindarajulu Varadarajan) [Orabug: 20342354] - enic: Make dummy rfs functions inline to fix !CONFIG_RFS_ACCEL build (Geert Uytterhoeven) [Orabug: 20342354] - enic: do tx cleanup in napi poll (Govindarajulu Varadarajan) [Orabug: 20342354] - enic: add low latency socket busy_poll support (Govindarajulu Varadarajan) [Orabug: 20342354] - net: vlan: add protocol argument to packet tagging functions (Patrick McHardy) [Orabug: 20342354] - net: vlan: prepare for 802.1ad VLAN filtering offload (Patrick McHardy) [Orabug: 20342354] - net: vlan: rename NETIF_F_HW_VLAN_* feature flags to NETIF_F_HW_VLAN_CTAG_* (Patrick McHardy) [Orabug: 20342354] - enic: fix lockdep around devcmd_lock (Tony Camuso) [Orabug: 20342354] - enic: Add Accelerated RFS support (Govindarajulu Varadarajan) [Orabug: 20342354] - enic: alloc/free rx_cpu_rmap (Govindarajulu Varadarajan) [Orabug: 20342354] - enic: devcmd for adding IP 5 tuple hardware filters (Govindarajulu Varadarajan) [Orabug: 20342354] - enic: fix return value in _vnic_dev_cmd (Govindarajulu Varadarajan) [Orabug: 20342354] - net: use SPEED_UNKNOWN and DUPLEX_UNKNOWN when appropriate (Jiri Pirko) [Orabug: 20342354] - enic: Fix 64 bit divide on 32bit system (Govindarajulu Varadarajan) [Orabug: 20342354] - enic: Add support for adaptive interrupt coalescing (Sujith Sankar) [Orabug: 20342354] - net: get rid of SET_ETHTOOL_OPS (Wilfried Klaebe) [Orabug: 20342354] - enic: Use pci_enable_msix_range() instead of pci_enable_msix() (Alexander Gordeev) [Orabug: 20342354] - bnx2x: Not use probe_defer (Vaughan Cao) [Orabug: 20405577] - Revert 'nfsd4: fix leak of inode reference on delegation failure' (Dan Duval) [Orabug: 20280060] - ipoib/ib core: set module_unload_allowed = 0 as default (Qing Huang) [Orabug: 20048920] - xfs: fix directory hash ordering bug (Mark Tinguely) [Orabug: 19695297] - xfs: fix node forward in xfs_node_toosmall (Mark Tinguely) [Orabug: 19695297] - XFS: Assertion failed: first b_length), file: fs/xfs/xfs_trans_buf.c, line: 568 (Dave Chinner) [Orabug: 19695297] - mlx4_vnic: Skip fip discover restart if pkey index not changed (Yuval Shaia) [Orabug: 19153757][3.8.13-65]- uek-rpm: ol7: update update-el to 7.1 (Guangyu Sun) [Orabug: 20524699][3.8.13-64]- storvsc: ring buffer failures may result in I/O freeze (Long Li) [Orabug: 20328185] - crypto: add missing crypto module aliases (Mathias Krause) [Orabug: 20429934] {CVE-2013-7421}- crypto: include crypto- module prefix in template (Kees Cook) [Orabug: 20429934] {CVE-2014-9644}- crypto: prefix module autoloading with 'crypto-' (Kees Cook) [Orabug: 20429934] {CVE-2013-7421}- be2iscsi : Bump the driver version (John Soni Jose) [Orabug: 20426078] - be2iscsi : Fix memory leak in the unload path (John Soni Jose) [Orabug: 20426078] - be2iscsi : Fix the PCI request region reserving. (John Soni Jose) [Orabug: 20426078] - be2iscsi : Fix the retry count for boot targets (John Soni Jose) [Orabug: 20426078] - fuse: Ensure request structure is not modified after being reused. (Ashish Samant) [Orabug: 20396380] - x86, apic, kexec: Add disable_cpu_apicid kernel parameter (HATAYAMA Daisuke) [Orabug: 20344754] - nfsd4: zero op arguments beyond the 8th compound op (J. Bruce Fields) [Orabug: 20070817] - ocfs2: implement delayed dropping of last dquot reference (Jan Kara) [Orabug: 19559063] - ib/sdp: fix null dereference of sk->sk_wq in sdp_rx_irq() (Chuck Anderson) [Orabug: 20482741][3.8.13-63]- ext4: protect write with sb_start/end_write in ext4_file_dio_write (Guangyu Sun) [Orabug: 20427284] - fs/pipe.c: skip file_update_time on frozen fs (Dmitry Monakhov) [Orabug: 20427126] - hpsa: remove 'action required' phrasing (Stephen M. Cameron) [Orabug: 20363086] - hpsa: remove spin lock around command allocation (Stephen M. Cameron) [Orabug: 20363086] - hpsa: always call pci_set_master after pci_enable_device (Robert Elliott) [Orabug: 20363086] - hpsa: Convert SCSI LLD ->queuecommand() for host_lock less operation (Nicholas Bellinger) [Orabug: 20363086] - hpsa: do not be so noisy about check conditions (Stephen M. Cameron) [Orabug: 20363086] - hpsa: use atomics for commands_outstanding (Stephen M. Cameron) [Orabug: 20363086] - hpsa: get rid of type/attribute/direction bit field where possible (Stephen M. Cameron) [Orabug: 20363086] - hpsa: fix endianness issue with scatter gather elements (Stephen M. Cameron) [Orabug: 20363086] - hpsa: fix allocation sizes for CISS_REPORT_LUNs commands (Stephen M. Cameron) [Orabug: 20363086] - hpsa: correct off-by-one sizing of chained SG block (Webb Scales) [Orabug: 20363086] - hpsa: fix a couple pci id table mistakes (Stephen M. Cameron) [Orabug: 20363086] - hpsa: remove dev_warn prints from RAID-1ADM (Robert Elliott) [Orabug: 20363086] - hpsa: Clean up warnings from sparse. (Don Brace) [Orabug: 20363086] - hpsa: add missing pci_set_master in kdump path (Tomas Henzl) [Orabug: 20363086] - hpsa: refine the pci enable/disable handling (Tomas Henzl) [Orabug: 20363086] - hpsa: Fallback to MSI rather than to INTx if MSI-X failed (Alexander Gordeev) [Orabug: 20363086] - libata: prevent HSM state change race between ISR and PIO (David Jeffery) [Orabug: 20019302][3.8.13-62]- i40e: Bump i40e version to 1.2.2 and i40evf version to 1.0.6 (Catherine Sullivan) [Orabug: 20199714] - i40e: get pf_id from HW rather than PCI function (Shannon Nelson) [Orabug: 20199714] - i40e: increase ARQ size (Mitch Williams) [Orabug: 20199714] - i40e: Increase reset delay (Kevin Scott) [Orabug: 20199714] - i40evf: make early init sequence even more robust (Mitch Williams) [Orabug: 20199714] - i40e: fix netdev_stat macro definition (Shannon Nelson) [Orabug: 20199714] - i40e: Define and use i40e_is_vf macro (Anjali Singhai Jain) [Orabug: 20199714] - i40e: Add a virtual channel op to config RSS (Anjali Singhai Jain) [Orabug: 20199714] - i40e: dont enable PTP support on more than one PF per port (Jacob Keller) [Orabug: 20199714] - i40e: allow various base numbers in debugfs aq commands (Shannon Nelson) [Orabug: 20199714] - i40e: remove useless debug noise (Shannon Nelson) [Orabug: 20199714] - i40e: Remove unneeded break statement (Shannon Nelson) [Orabug: 20199714] - i40e: trigger SW INT with no ITR wait (Shannon Nelson) [Orabug: 20199714] - i40evf: remove unnecessary else (Mitch Williams) [Orabug: 20199714] - i40evf: make checkpatch happy (Mitch Williams) [Orabug: 20199714] - i40evf: update header comments (Mitch Williams) [Orabug: 20199714] - i40e: dont overload fields (Mitch Williams) [Orabug: 20199714] - i40e: Prevent link flow control settings when PFC is enabled (Neerav Parikh) [Orabug: 20199714] - i40e: Update VEBs enabled_tc after reconfiguration (Neerav Parikh) [Orabug: 20199714] - i40e: Bump version to 1.1.23 (Catherine Sullivan) [Orabug: 20199714] - i40e: re-enable VFLR interrupt sooner (Mitch Williams) [Orabug: 20199714] - i40e: only warn once of PTP nonsupport in 100Mbit speed (Shannon Nelson) [Orabug: 20199714] - i40evf: dont use more queues than CPUs (Mitch Williams) [Orabug: 20199714] - i40evf: make early init processing more robust (Mitch Williams) [Orabug: 20199714] - i40e: clean up throttle rate code (Jesse Brandeburg) [Orabug: 20199714] - i40e: dont do link_status or stats collection on every ARQ (Shannon Nelson) [Orabug: 20199714] - i40e: poll firmware slower (Kamil Krawczyk) [Orabug: 20199714] - i40e: properly parse MDET registers (Mitch Williams) [Orabug: 20199714] - i40e: configure VM ID in qtx_ctl (Mitch Williams) [Orabug: 20199714] - i40e: enable debug earlier (Shannon Nelson) [Orabug: 20199714] - i40e: better wording for resource tracking errors (Shannon Nelson) [Orabug: 20199714] - i40e: scale msix vector use when more cores than vectors (Shannon Nelson) [Orabug: 20199714] - i40e: remove debugfs dump stats (Shannon Nelson) [Orabug: 20199714] - i40e: avoid disable of interrupt when changing ITR (Jesse Brandeburg) [Orabug: 20199714] - i40evf: Add support for 10G base T parts (Paul M Stillwell Jr) [Orabug: 20199714] - i40e: fix link checking logic (Mitch Williams) [Orabug: 20199714] - i40evf: properly handle multiple AQ messages (Mitch Williams) [Orabug: 20199714] - i40e: Add condition to enter fdir flush and reinit (Akeem G Abodunrin) [Orabug: 20199714] - i40e: Bump version (Catherine Sullivan) [Orabug: 20199714] - i40e: Moving variable declaration out of the loops (Akeem G Abodunrin) [Orabug: 20199714] - i40e: Add 10GBaseT support (Mitch Williams) [Orabug: 20199714] - i40e: process link events when setting up switch (Mitch Williams) [Orabug: 20199714]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-3012");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-3012.html");
script_cve_id("CVE-2013-7421","CVE-2014-9644","CVE-2014-3610","CVE-2014-7975","CVE-2014-8134","CVE-2014-8133");
script_tag(name:"cvss_base", value:"4.9");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
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
if(release == "OracleLinux7")
{
  if ((res = isrpmvuln(pkg:"dtrace-modules", rpm:"dtrace-modules~3.8.13~68.el7uek~0.4.3~4.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~68.el7uek", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~68.el7uek", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~68.el7uek", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~68.el7uek", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~68.el7uek", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~68.el7uek", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"dtrace-modules", rpm:"dtrace-modules~3.8.13~68.el6uek~0.4.3~4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~68.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~68.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~68.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~68.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~68.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~68.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

