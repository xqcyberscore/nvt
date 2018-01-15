# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-2248.nasl 8419 2018-01-15 07:50:24Z asteins $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122746");
script_version("$Revision: 8419 $");
script_tag(name:"creation_date", value:"2015-11-24 10:17:21 +0200 (Tue, 24 Nov 2015)");
script_tag(name:"last_modification", value:"$Date: 2018-01-15 08:50:24 +0100 (Mon, 15 Jan 2018) $");
script_name("Oracle Linux Local Check: ELSA-2015-2248");
script_tag(name: "insight", value: "ELSA-2015-2248 -  netcf security, bug fix, and enhancement update - [0.2.8-1]- Rebase to netcf-0.2.8 - resolve rhbz#1165965 - CVE-2014-8119 - resolve rhbz#1159000 - support multiple IPv4 addresses in interface config (redhat driver) - resolve rhbz#1113983 - allow static IPv4 config simultaneous with DHCPv4 (redhat driver) - resolve rhbz#1170941 - remove extra quotes from IPV6ADDR_SECONDARIES (redhat+suse drivers) - resolve rhbz#1090011 - limit names of new interfaces to IFNAMSIZ characters - resolve rhbz#761246 - properly parse ifcfg files with comments past column 1"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-2248");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-2248.html");
script_cve_id("CVE-2014-8119");
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
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
  if ((res = isrpmvuln(pkg:"netcf", rpm:"netcf~0.2.8~1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"netcf-devel", rpm:"netcf-devel~0.2.8~1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"netcf-libs", rpm:"netcf-libs~0.2.8~1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

