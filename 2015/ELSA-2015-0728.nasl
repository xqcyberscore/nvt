# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-0728.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123150");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 13:59:59 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-0728");
script_tag(name: "insight", value: "ELSA-2015-0728 -  ipa and slapi-nis security and bug fix update - ipa[4.1.0-18.0.1.el7_1.3]- Replace login-screen-logo.png [20362818]- Drop subscription-manager requires for OL7- Drop redhat-access-plugin-ipa requires for OL7- Blank out header-logo.png product-name.png[4.1.0-18.3]- [ipa-python] ipalib.errors.LDAPError: failed to decode certificate: (SEC_ERROR_INVALID_ARGS) security library: invalid arguments. (#1194312)[4.1.0-18.2]- IPA extdom plugin fails when encountering large groups (#1193759)- CVE-2015-0283 ipa: slapi-nis: infinite loop in getgrnam_r() and getgrgid_r() (#1202997)[4.1.0-18.1]- 'an internal error has occurred' during ipa host-del --updatedns (#1198431)- Renamed patch 1013 to 0114, as it was merged upstream- Fax number not displayed for user-show when kinit'ed as normal user. (#1198430)- Replication agreement with replica not disabled when ipa-restore done without IPA installed (#1199060)- Limit deadlocks between DS plugin DNA and slapi-nis (#1199128)slapi-nis[0.54-3]- Fix CVE-2015-0283- Resolves: #1202995"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-0728");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-0728.html");
script_cve_id("CVE-2015-0283","CVE-2015-1827");
script_tag(name:"cvss_base", value:"7.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
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
  if ((res = isrpmvuln(pkg:"ipa-admintools", rpm:"ipa-admintools~4.1.0~18.0.1.el7_1.3", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ipa-client", rpm:"ipa-client~4.1.0~18.0.1.el7_1.3", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ipa-python", rpm:"ipa-python~4.1.0~18.0.1.el7_1.3", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ipa-server", rpm:"ipa-server~4.1.0~18.0.1.el7_1.3", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ipa-server-trust-ad", rpm:"ipa-server-trust-ad~4.1.0~18.0.1.el7_1.3", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"slapi-nis", rpm:"slapi-nis~0.54~3.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

