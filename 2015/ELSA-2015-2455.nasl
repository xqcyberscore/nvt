# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-2455.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122740");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-11-24 10:17:17 +0200 (Tue, 24 Nov 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-2455");
script_tag(name: "insight", value: "ELSA-2015-2455 -  unbound security and bug fix update - [1.4.20-26]- Added Conficts on redhat-release packages without unbound-anchor.timer in presets (Related #1215645)[1.4.20-25]- Resolve ordering loop with nss-lookup.target and ntpdate (#1259806)[1.4.20-24]- Fix CVE-2014-8602 (#1253961)[1.4.20-23]- Removed usage of DLV from the default configuration (#1223339)[1.4.20-22]- unbound.service now Wants unbound-anchor.timer (Related: #1180267)[1.4.20-21]- Fix dependencies and minor scriptlet issues due to systemd timer unit (Related: #1180267)[1.4.20-20]- Install tmpfiles configuration into /usr/lib/tmpfiles.d (#1180995)- Fix root key management to comply to RFC5011 (#1180267)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-2455");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-2455.html");
script_cve_id("CVE-2014-8602");
script_tag(name:"cvss_base", value:"4.3");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
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
  if ((res = isrpmvuln(pkg:"unbound", rpm:"unbound~1.4.20~26.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"unbound-devel", rpm:"unbound-devel~1.4.20~26.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"unbound-libs", rpm:"unbound-libs~1.4.20~26.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"unbound-python", rpm:"unbound-python~1.4.20~26.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

