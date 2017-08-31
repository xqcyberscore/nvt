# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2014-455.nasl 6750 2017-07-18 09:56:47Z teissa $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120012");
script_version("$Revision: 6750 $");
script_tag(name:"creation_date", value:"2015-09-08 13:14:56 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-18 11:56:47 +0200 (Tue, 18 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2014-455");
script_tag(name: "insight", value: "The sctp_process_param function in net/sctp/sm_make_chunk.c in the SCTP implementation in the Linux kernel before 3.17.4, when ASCONF is used, allows remote attackers to cause a denial of service (NULL pointer dereference and system crash) via a malformed INIT chunk. (CVE-2014-7841 )The pivot_root implementation in fs/namespace.c in the Linux kernel through 3.17 does not properly interact with certain locations of a chroot directory, which allows local users to cause a denial of service (mount-tree loop) via . (dot) values in both arguments to the pivot_root system call. (CVE-2014-7970 )The do_double_fault function in arch/x86/kernel/traps.c in the Linux kernel through 3.17.4 does not properly handle faults associated with the Stack Segment (SS) segment register, which allows local users to cause a denial of service (panic) via a modify_ldt system call, as demonstrated by sigreturn_32 in the linux-clock-tests test suite. (CVE-2014-9090 )A flaw was found in the way the Linux kernel handled GS segment register base switching when recovering from a #SS (stack segment) fault on an erroneous return to user space. A local, unprivileged user could use this flaw to escalate their privileges on the system. (CVE-2014-9322 )"); 
script_tag(name : "solution", value : "Run yum clean all followed by yum update kernel to update your system.  You will need to reboot your system in order for the new kernel to be running.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2014-455.html");
script_cve_id("CVE-2014-7841", "CVE-2014-7970", "CVE-2014-9322", "CVE-2014-9090");
script_tag(name:"cvss_base", value:"7.2");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
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
if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.14.26~24.46.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~3.14.26~24.46.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"perf-debuginfo", rpm:"perf-debuginfo~3.14.26~24.46.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.14.26~24.46.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-tools-devel", rpm:"kernel-tools-devel~3.14.26~24.46.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-i686", rpm:"kernel-debuginfo-common-i686~3.14.26~24.46.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.14.26~24.46.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"perf", rpm:"perf~3.14.26~24.46.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.14.26~24.46.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.14.26~24.46.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
