# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-1536.nasl 6556 2017-07-06 11:54:54Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122040");
script_version("$Revision: 6556 $");
script_tag(name:"creation_date", value:"2015-10-06 14:12:05 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:54 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-1536");
script_tag(name: "insight", value: "ELSA-2011-1536 -  sos security, bug fix, and enhancement update - [2.2-17.0.1.el6]- Direct traceroute to linux.oracle.com (John Haxby) [orabug 11713272]- Allow '-' in ticket (SR) numbers (John Haxby)- Disable --upload option as it will not work with Oracle support- Check oraclelinux-release instead of redhat-release to get OS version (John Haxby) [bug 11681869]- Remove RH ftp URL and support email- add sos-oracle-enterprise.patch[2.2-17]- Do not collect subscription manager keys in general pluginResolves: bz750607[2.2-16]- Fix execution of RHN hardware.py from hardware pluginResolves: bz736718- Fix hardware plugin to support new lsusb pathResolves: bz691477[2.2-15]- Fix brctl collection when a bridge contains no interfaces Resolves: bz697899- Fix up2dateclient path in hardware plugin Resolves: bz736718[2.2-14]- Collect brctl show and showstp output Resolves: bz697899- Collect nslcd.conf in ldap plugin Resolves: bz682124[2.2-11]- Truncate files that exceed specified size limit Resolves: bz683219- Add support for collecting Red Hat Subscrition Manager configuration Resolves: bz714293- Collect /etc/init on systems using upstart Resolves: bz694813- Don't strip whitespace from output of external programs Resolves: bz713449- Collect ipv6 neighbour table in network module Resolves: bz721163- Collect basic cgroups configuration data Resolves: bz729455[2.2-10]- Fix collection of data from LVM2 reporting tools in devicemapper plugin Resolves: bz704383- Add /proc/vmmemctl collection to vmware plugin Resolves: bz709491[2.2-9]- Collect yum repository list by default Resolves: bz600813- Add basic Infiniband plugin Resolves: bz673244- Add plugin for scsi-target-utils iSCSI target Resolves: bz677124- Fix autofs plugin LC_ALL usage Resolves: bz683404- Fix collection of lsusb and add collection of -t and -v outputs Resolves: bz691477- Extend data collection by qpidd plugin Resolves: bz726360- Add ethtool pause, coalesce and ring (-a, -c, -g) options to network plugin Resolves: bz726427"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-1536");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-1536.html");
script_cve_id("CVE-2011-4083");
script_tag(name:"cvss_base", value:"4.3");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
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
  if ((res = isrpmvuln(pkg:"sos", rpm:"sos~2.2~17.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

