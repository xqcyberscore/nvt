# OpenVAS Vulnerability Test
# $Id: alas-2011-26.nasl 6579 2017-07-06 13:45:14Z cfischer $
 
# Description: Amazon Linux security check 
#  
# Authors: 
# Eero Volotinen <eero.volotinen@iki.fi> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://ping-viini.org 
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
script_oid("1.3.6.1.4.1.25623.1.0.120399");
script_version("$Revision: 6579 $");
script_tag(name:"creation_date", value:"2015-09-08 11:24:42 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:45:14 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2011-26");
script_tag(name: "insight", value: "IPv6 fragment identification value generation could allow a remote attacker to disrupt a target system's networking, preventing legitimate users from accessing its services. (CVE-2011-2699 , Important)A signedness issue was found in the Linux kernel's CIFS (Common Internet File System) implementation. A malicious CIFS server could send a specially-crafted response to a directory read request that would result in a denial of service or privilege escalation on a system that has a CIFS share mounted. (CVE-2011-3191 , Important)A flaw was found in the way the Linux kernel handled fragmented IPv6 UDP datagrams over the bridge with UDP Fragmentation Offload (UFO) functionality on. A remote attacker could use this flaw to cause a denial of service. (CVE-2011-4326 , Important)The way IPv4 and IPv6 protocol sequence numbers and fragment IDs were generated could allow a man-in-the-middle attacker to inject packets and possibly hijack connections. Protocol sequence numbers and fragment IDs are now more random. (CVE-2011-3188 , Moderate)A buffer overflow flaw was found in the Linux kernel's FUSE (Filesystem in Userspace) implementation. A local user in the fuse group who has access to mount a FUSE file system could use this flaw to cause a denial of service. (CVE-2011-3353 , Moderate)A flaw was found in the b43 driver in the Linux kernel. If a system had an active wireless interface that uses the b43 driver, an attacker able to send a specially-crafted frame to that interface could cause a denial of service. (CVE-2011-3359 , Moderate)A flaw was found in the way CIFS shares with DFS referrals at their root were handled. An attacker on the local network who is able to deploy a malicious CIFS server could create a CIFS network share that, when mounted, would cause the client system to crash. (CVE-2011-3363 , Moderate)A flaw was found in the way the Linux kernel handled VLAN 0 frames with the priority tag set. When using certain network drivers, an attacker on the local network could use this flaw to cause a denial of service. (CVE-2011-3593 , Moderate)A flaw in the way memory containing security-related data was handled in tpm_read() could allow a local, unprivileged user to read the results of a previously run TPM command. (CVE-2011-1162 , Low)A heap overflow flaw was found in the Linux kernel's EFI GUID Partition Table (GPT) implementation. A local attacker could use this flaw to cause a denial of service by mounting a disk that contains specially-crafted partition tables. (CVE-2011-1577 , Low)The I/O statistics from the taskstats subsystem could be read without any restrictions. A local, unprivileged user could use this flaw to gather confidential information, such as the length of a password used in a process. (CVE-2011-2494 , Low)It was found that the perf tool, a part of the Linux kernel's Performance Events implementation, could load its configuration file from the current working directory. If a local user with access to the perf tool were tricked into running perf in a directory that contains a specially-crafted configuration file, it could cause perf to overwrite arbitrary files and directories accessible to that user. (CVE-2011-2905 , Low)"); 
script_tag(name : "solution", value : "Run yum update kernel to update your system.  You will need to reboot your system in order for the new kernel to be running.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2011-26.html");
script_cve_id("CVE-2011-3593", "CVE-2011-2699", "CVE-2011-3188", "CVE-2011-2905", "CVE-2011-3363", "CVE-2011-2494", "CVE-2011-4326", "CVE-2011-3353", "CVE-2011-1577", "CVE-2011-4110", "CVE-2011-3359", "CVE-2011-1162", "CVE-2011-3191", "CVE-2011-4132");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name:"summary", value:"Amazon Linux Local Security Checks");
script_copyright("Eero Volotinen");
script_family("Amazon Linux Local Security Checks");
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
if(release == "AMAZON")
{
if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.35.14~106.49.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.35.14~106.49.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.35.14~106.49.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.35.14~106.49.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.35.14~106.49.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.35.14~106.49.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
