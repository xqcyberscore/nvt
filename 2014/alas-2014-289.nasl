# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2014-289.nasl 6715 2017-07-13 09:57:40Z teissa $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120008");
script_version("$Revision: 6715 $");
script_tag(name:"creation_date", value:"2015-09-08 13:14:47 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-13 11:57:40 +0200 (Thu, 13 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2014-289");
script_tag(name: "insight", value: "The pn_recvmsg function in net/phonet/datagram.c in the Linux kernel before 3.12.4 updates a certain length value before ensuring that an associated data structure has been initialized, which allows local users to obtain sensitive information from kernel stack memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system call. The security_context_to_sid_core function in security/selinux/ss/services.c in the Linux kernel before 3.13.4 allows local users to cause a denial of service (system crash) by leveraging the CAP_MAC_ADMIN capability to set a zero-length security context. The Linux kernel before 3.12.4 updates certain length values before ensuring that associated data structures have been initialized, which allows local users to obtain sensitive information from kernel stack memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system call, related to net/ipv4/ping.c, net/ipv4/raw.c, net/ipv4/udp.c, net/ipv6/raw.c, and net/ipv6/udp.c. The cifs_iovec_write function in fs/cifs/file.c in the Linux kernel through 3.13.5 does not properly handle uncached write operations that copy fewer than the requested number of bytes, which allows local users to obtain sensitive information from kernel memory, cause a denial of service (memory corruption and system crash), or possibly gain privileges via a writev system call with a crafted pointer."); 
script_tag(name : "solution", value : "Run yum update kernel to update your system.  You will need to reboot your system in order for the new kernel to be running.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2014-289.html");
script_cve_id("CVE-2013-7265", "CVE-2014-1874", "CVE-2013-7263", "CVE-2014-0069");
script_tag(name:"cvss_base", value:"6.2");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
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
if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.4.82~69.112.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-tools-debuginfo", rpm:"kernel-tools-debuginfo~3.4.82~69.112.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.4.82~69.112.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.4.82~69.112.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-i686", rpm:"kernel-debuginfo-common-i686~3.4.82~69.112.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.4.82~69.112.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.4.82~69.112.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
