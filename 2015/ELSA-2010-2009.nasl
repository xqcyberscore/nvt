# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2010-2009.nasl 6555 2017-07-06 11:54:09Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122306");
script_version("$Revision: 6555 $");
script_tag(name:"creation_date", value:"2015-10-06 14:16:23 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:09 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2010-2009");
script_tag(name: "insight", value: "ELSA-2010-2009 -  Oracle Linux 5 Unbreakable Enterprise kernel security fix update - Following security bugs are fixed in this errataCVE-2010-3904When copying data to userspace, the RDS protocol failed to verify that the user-provided address was a validuserspace address. A local unprivileged user could issue specially crafted socket calls to write arbitraryvalues into kernel memory and potentially escalate privileges to root.CVE-2010-3067Integer overflow in the do_io_submit function in fs/aio.c in the Linux kernel before 2.6.36-rc4-next-20100915 allowslocal users to cause a denial of service or possibly have unspecified other impact via crafted use of the io_submitsystem call.CVE-2010-3477The tcf_act_police_dump function in net/sched/act_police.c in the actions implementation in the network queueingfunctionality in the Linux kernel before 2.6.36-rc4 does not properly initialize certain structure members, whichallows local users to obtain potentially sensitive information from kernel memory via vectors involving a dumpoperation. NOTE: this vulnerability exists because of an incomplete fix for CVE-2010-2942.kernel:[2.6.32-100.21.1.el5]- [rds] fix access issue with rds (Chris Mason) {CVE-2010-3904}- [fuse] linux-2.6.32-fuse-return-EGAIN-if-not-connected-bug-10154489.patch- [net] linux-2.6.32-net-sched-fix-kernel-leak-in-act_police.patch- [aio] linux-2.6.32-aio-check-for-multiplication-overflow-in-do_io_subm.patchofa:[1.5.1-4.0.23]- Fix rds permissions checks during copies[1.5.1-4.0.21]- Update to BXOFED 1.5.1-1.3.6-5"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2010-2009");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2010-2009.html");
script_cve_id("CVE-2010-3067","CVE-2010-3477","CVE-2010-3904");
script_tag(name:"cvss_base", value:"7.2");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~100.21.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~100.21.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~100.21.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~100.21.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~100.21.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~100.21.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~100.21.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ofa", rpm:"ofa~2.6.32~100.21.1.el5~1.5.1~4.0.23", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

