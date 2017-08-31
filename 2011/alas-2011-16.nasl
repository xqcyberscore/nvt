# OpenVAS Vulnerability Test
# $Id: alas-2011-16.nasl 6579 2017-07-06 13:45:14Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120275");
script_version("$Revision: 6579 $");
script_tag(name:"creation_date", value:"2015-09-08 11:21:32 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:45:14 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2011-16");
script_tag(name: "insight", value: "The skb_gro_header_slow function in include/linux/netdevice.h in the Linux kernel before 2.6.39.4, when Generic Receive Offload (GRO) is enabled, resets certain fields in incorrect situations, which allows remote attackers to cause a denial of service (system crash) via crafted network traffic. Race condition in the ecryptfs_mount function in fs/ecryptfs/main.c in the eCryptfs subsystem in the Linux kernel before 3.1 allows local users to bypass intended file permissions via a mount.ecryptfs_private mount with a mismatched uid. The (1) IPv4 and (2) IPv6 implementations in the Linux kernel before 3.1 use a modified MD4 algorithm to generate sequence numbers and Fragment Identification values, which makes it easier for remote attackers to cause a denial of service (disrupted networking) or hijack network sessions by predicting these values and sending crafted packets. Integer signedness error in the CIFSFindNext function in fs/cifs/cifssmb.c in the Linux kernel before 3.1 allows remote CIFS servers to cause a denial of service (memory corruption) or possibly have unspecified other impact via a large length value in a response to a read request for a directory. The Performance Events subsystem in the Linux kernel before 3.1 does not properly handle event overflows associated with PERF_COUNT_SW_CPU_CLOCK events, which allows local users to cause a denial of service (system hang) via a crafted application."); 
script_tag(name : "solution", value : "Run yum update kernel to update your system.  You will need to reboot your system in order for the new kernel to be running.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2011-16.html");
script_cve_id("CVE-2011-2723", "CVE-2011-1833", "CVE-2011-3188", "CVE-2011-3191", "CVE-2011-2918");
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
if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.35.14~97.44.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.35.14~97.44.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-i686", rpm:"kernel-debuginfo-common-i686~2.6.35.14~97.44.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.35.14~97.44.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.35.14~97.44.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.35.14~97.44.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
