# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2008-0389.nasl 6553 2017-07-06 11:52:12Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122584");
script_version("$Revision: 6553 $");
script_tag(name:"creation_date", value:"2015-10-08 14:48:38 +0300 (Thu, 08 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:52:12 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2008-0389");
script_tag(name: "insight", value: "ELSA-2008-0389 -  nss_ldap security and bug fix update - [253-12]- rebuild[253-11]- backport changes to group parsing from version 254 to fix heap corruption when parsing nested groups (#444031)[253-10]- remove unnecessary nss_ldap linkage to libnsl (part of #427370)[253-9]- rebuild[253-8]- incorporate Tomas Janouseks fix to prevent re-use of connections across fork() (#252337)[253-7]- add keyutils-libs-devel and libselinux-devel as a buildrequires: in order to static link with newer Kerberos (#427370)[253-6]- suppress password-expired errors encountered during referral chases during modify requests (#335661)- interpret server-supplied policy controls when chasing referrals, so that we dont give up when following a referral for a password change after reset (#335661)- dont attempt to change the password using ldap_modify if the password change mode is 'exop_send_old' (we already didnt for 'exop') (#364501)- dont drop the supplied password if the directory server indicates that the password needs to be changed because its just been reset: we may need it to chase a referral later (#335661)- correctly detect libresolv and build a URI using discovered settings, so that server discovery can work again (#254172)- honor the 'port' setting again by correctly detecting when a URI doesnt already specify one (#326351)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2008-0389");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2008-0389.html");
script_cve_id("CVE-2007-5794");
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
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"nss_ldap", rpm:"nss_ldap~253~12.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

