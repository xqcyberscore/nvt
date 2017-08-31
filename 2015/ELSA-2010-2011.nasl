# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2010-2011.nasl 6555 2017-07-06 11:54:09Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122291");
script_version("$Revision: 6555 $");
script_tag(name:"creation_date", value:"2015-10-06 14:16:07 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:09 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2010-2011");
script_tag(name: "insight", value: "ELSA-2010-2011 - Unbreakable enterprise kernel security and bug fix update - Following Security fixes are included in this unbreakable enterprise kernel errata: CVE-2010-3432 The sctp_packet_config function in net/sctp/output.c in the Linux kernel before 2.6.35.6 performs extraneous initializations of packet data structures, which allows remote attackers to cause a denial of service (panic) via a certain sequence of SCTP traffic. CVE-2010-2962 drivers/gpu/drm/i915/i915_gem.c in the Graphics Execution Manager (GEM) in the Intel i915 driver in the Direct Rendering Manager (DRM) subsystem in the Linux kernel before 2.6.36 does not properly validate pointers to blocks of memory, which allows local users to write to arbitrary kernel memory locations, and consequently gain privileges, via crafted use of the ioctl interface, related to (1) pwrite and (2) pread operations. CVE-2010-2955 The cfg80211_wext_giwessid function in net/wireless/wext-compat.c in the Linux kernel before 2.6.36-rc3-next-20100831 does not properly initialize certain structure members, which allows local users to leverage an off-by-one error in the ioctl_standard_iw_point function in net/wireless/wext-core.c, and obtain potentially sensitive information from kernel heap memory, via vectors involving an SIOCGIWESSID ioctl call that specifies a large buffer size. CVE-2010-3705 The sctp_auth_asoc_get_hmac function in net/sctp/auth.c in the Linux kernel before 2.6.36 does not properly validate the hmac_ids array of an SCTP peer, which allows remote attackers to cause a denial of service (memory corruption and panic) via a crafted value in the last element of this array. CVE-2010-3084 Buffer overflow in the niu_get_ethtool_tcam_all function in drivers/net/niu.c in the Linux kernel before 2.6.36-rc4 allows local users to cause a denial of service or possibly have unspecified other impact via the ETHTOOL_GRXCLSRLALL ethtool command. CVE-2010-3437 Integer signedness error in the pkt_find_dev_from_minor function in drivers/block/pktcdvd.c in the Linux kernel before 2.6.36-rc6 allows local users to obtain sensitive information from kernel memory or cause a denial of service (invalid pointer dereference and system crash) via a crafted index value in a PKT_CTRL_CMD_STATUS ioctl call. CVE-2010-3079 kernel/trace/ftrace.c in the Linux kernel before 2.6.35.5, when debugfs is enabled, does not properly handle interaction between mutex possession and llseek operations, which allows local users to cause a denial of service (NULL pointer dereference and outage of all function tracing files) via an lseek call on a file descriptor associated with the set_ftrace_filter file. CVE-2010-3698 The KVM implementation in the Linux kernel before 2.6.36 does not properly reload the FS and GS segment registers, which allows host OS users to cause a denial of service (host OS crash) via a KVM_RUN ioctl call in conjunction with a modified Local Descriptor Table (LDT). CVE-2010-3442 Multiple integer overflows in the snd_ctl_new function in sound/core/control.c in the Linux kernel before 2.6.36-rc5-next-20100929 allow local users to cause a denial of service (heap memory corruption) or possibly have unspecified other impact via a crafted (1) SNDRV_CTL_IOCTL_ELEM_ADD or (2) SNDRV_CTL_IOCTL_ELEM_REPLACE ioctl call. [2.6.32-100.24.1.el5] - [sctp] Do not reset the packet during sctp_packet_con[CVE-2010-3432] - [drm/i915] Sanity check pread/pwrite [CVE-2010-2962] - [wireless] fix kernel heap content leak [CVE-2010-2955] - [sctp] Fix out-of-bounds reading in sctp_asoc_get_hmac() [CVE-2010-3705] - [niu] Fix kernel buffer overflow for ETHTOOL_GRXCLSRLALL [CVE-2010-3084] - Fix pktcdvd ioctl dev_minor range check [CVE-2010-3437] - Do not allow llseek to set_ftrace_filter [CVE-2010-3079] - [kvm] Fix fs/gs reload oops with invalid ldt [CVE-2010-3698] - [alsa] prevent heap corruption in snd_ctl_new() [CVE-2010-3442] - Fix LACP bonding mode (Tina Yang) - Fix grat arps on bonded interfaces (Tina Yang)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2010-2011");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2010-2011.html");
script_cve_id("CVE-2010-2955","CVE-2010-2962","CVE-2010-3079","CVE-2010-3084","CVE-2010-3432","CVE-2010-3437","CVE-2010-3442","CVE-2010-3698","CVE-2010-3705");
script_tag(name:"cvss_base", value:"8.3");
script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
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
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~100.24.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~100.24.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~100.24.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~100.24.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~100.24.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~100.24.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~100.24.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ofa", rpm:"ofa~2.6.32~100.24.1.el5~1.5.1~4.0.23", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ofa", rpm:"ofa~2.6.32~100.24.1.el5debug~1.5.1~4.0.23", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

