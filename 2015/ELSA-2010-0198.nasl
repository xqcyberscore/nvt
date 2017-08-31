# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2010-0198.nasl 6555 2017-07-06 11:54:09Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122377");
script_version("$Revision: 6555 $");
script_tag(name:"creation_date", value:"2015-10-06 14:17:46 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:09 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2010-0198");
script_tag(name: "insight", value: "ELSA-2010-0198 -  openldap security and bug fix update - [2.3.43-12]- updated spec file, so the compat-libs linking patch applies correctly[2.3.43-11]- backported patch to handle null character in TLS certificates (#560912)[2.3.43-10]- updated chase-referral patch to compile cleanly- updated init script (#562714)[2.3.43-9]- updated ldap.sysconf to include SLAPD_LDAP, SLAPD_LDAPS and SLAPD_LDAPI options (#559520)[2.3.43-8]- fixed connection freeze when TLSVerifyClient = allow (#509230)[2.3.43-7]- fixed chasing referrals in libldap (#510522)[2.3.43-6]- fixed possible double free() in rwm overlay (#495628)- updated slapd man page and slapcat usage string (#468206)- updated default config for slapd - deleted syncprov module (#466937)- fixed migration tools autofs generated format (#460331)- fixed migration tools numbers detection in /etc/shadow (#113857)- fixed migration tools base ldif (#104585)[2.3.43-5]- implementation of limit adjustment before starting slapd (#527313)- init script no longer executes script in /tmp (#483356)- slapd not starting with ldap:/// every time (#481003)- delay between TERM and KILL when shutting down slapd (#452064)[2.3.43-4]- fixed compat libs linking (#503734)- activated lightweight dispatcher feature (#507276)- detection of timeout after failed result (#495701"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2010-0198");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2010-0198.html");
script_cve_id("CVE-2009-3767");
script_tag(name:"cvss_base", value:"6.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
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
  if ((res = isrpmvuln(pkg:"compat-openldap", rpm:"compat-openldap~2.3.43_2.2.29~12.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openldap", rpm:"openldap~2.3.43~12.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openldap-clients", rpm:"openldap-clients~2.3.43~12.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openldap-devel", rpm:"openldap-devel~2.3.43~12.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openldap-servers", rpm:"openldap-servers~2.3.43~12.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openldap-servers-overlays", rpm:"openldap-servers-overlays~2.3.43~12.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openldap-servers-sql", rpm:"openldap-servers-sql~2.3.43~12.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

