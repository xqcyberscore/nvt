# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2012-133.nasl 6578 2017-07-06 13:44:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120332");
script_version("$Revision: 6578 $");
script_tag(name:"creation_date", value:"2015-09-08 13:23:45 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:44:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2012-133");
script_tag(name: "insight", value: "An integer overflow flaw was found in the i915_gem_do_execbuffer() function in the Intel i915 driver in the Linux kernel. A local, unprivileged user could use this flaw to cause a denial of service. This issue only affected 32-bit systems. (CVE-2012-2384 , Moderate)A memory leak flaw was found in the way the Linux kernel's memory subsystem handled resource clean up in the mmap() failure path when the MAP_HUGETLB flag was set. A local, unprivileged user could use this flaw to cause a denial of service. (CVE-2012-2390 , Moderate)A race condition was found in the way access to inet->opt ip_options was synchronized in the Linux kernel's TCP/IP protocol suite implementation. Depending on the network facing applications running on the system, a remote attacker could possibly trigger this flaw to cause a denial of service. A local, unprivileged user could use this flaw to cause a denial of service regardless of the applications the system runs. (CVE-2012-3552 , Moderate)A flaw was found in the way the Linux kernel's dl2k driver, used by certain D-Link Gigabit Ethernet adapters, restricted IOCTLs. A local, unprivileged user could use this flaw to issue potentially harmful IOCTLs, which could cause Ethernet adapters using the dl2k driver to malfunction (for example, losing network connectivity). (CVE-2012-2313 , Low)A flaw was found in the way the msg_namelen variable in the rds_recvmsg() function of the Linux kernel's Reliable Datagram Sockets (RDS) protocol implementation was initialized. A local, unprivileged user could use this flaw to leak kernel stack memory to user-space. (CVE-2012-3430 , Low)"); 
script_tag(name : "solution", value : "Run yum update kernel to update your system.  You will need to reboot your system in order for the new kernel to be running.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2012-133.html");
script_cve_id("CVE-2012-2313", "CVE-2012-2384", "CVE-2012-2390", "CVE-2012-3430", "CVE-2012-3552");
script_tag(name:"cvss_base", value:"5.4");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:C");
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
if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.2.30~49.59.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-tools-debuginfo", rpm:"kernel-tools-debuginfo~3.2.30~49.59.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.2.30~49.59.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-i686", rpm:"kernel-debuginfo-common-i686~3.2.30~49.59.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.2.30~49.59.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.2.30~49.59.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.2.30~49.59.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
