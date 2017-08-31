# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-0312.nasl 6600 2017-07-07 09:58:31Z teissa $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123978");
script_version("$Revision: 6600 $");
script_tag(name:"creation_date", value:"2015-10-06 14:11:06 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:58:31 +0200 (Fri, 07 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2012-0312");
script_tag(name: "insight", value: "ELSA-2012-0312 -  initscripts security and bug fix update - [8.45.42-1.0.1.el5]- Update oracle-enterprise.patch to do detection on /etc/oracle-release and /etc/enterprise-release- Patch x86_64 sysctl.conf as well as default sysctl.conf- Patch sysctl.conf to default rp_filter to loose reverse path filtering (has no effect for pre-2.6.32 kernels) [orabug 10286227]- Move hwclock into udev rules- Update oracle-enterprise.patch to fix RedHat references in arch specific sysctl.conf files in source tarball- Add oracle-enterprise.patch and update specfile- Don't attempt to re-enslave already-enslaved devices (#455537) (pknirsch@redhat.com)[8.45.42-1]- changed exchange_mode to 'main, aggressive' (#435274)[8.45.41-1]- fix check for dhcp6c pid (#568896)[8.45.40-1]- exit arping on first response (#744734)[8.45.39-1]- suppress remove error message during boot (#679998)- fix logic error with removing arp_ip_target (#745681)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-0312");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-0312.html");
script_cve_id("CVE-2008-1198");
script_tag(name:"cvss_base", value:"7.1");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:N/A:N");
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
  if ((res = isrpmvuln(pkg:"initscripts", rpm:"initscripts~8.45.42~1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

