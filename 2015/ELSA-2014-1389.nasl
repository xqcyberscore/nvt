# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-1389.nasl 6559 2017-07-06 11:57:32Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123290");
script_version("$Revision: 6559 $");
script_tag(name:"creation_date", value:"2015-10-06 14:01:49 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:57:32 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-1389");
script_tag(name: "insight", value: "ELSA-2014-1389 -  krb5 security and bug fix update - [1.10.3-33]- actually apply that last patch[1.10.3-32]- incorporate fix for MITKRB5-SA-2014-001 (CVE-2014-4345, #1128157)[1.10.3-31]- ksu: when evaluating .k5users, don't throw away data from .k5users when we're not passed a command to run, which implicitly means we're attempting to run the target user's shell (#1026721, revised)[1.10.3-30]- ksu: when evaluating .k5users, treat lines with just a principal name as if they contained the principal name followed by '*', and don't throw away data from .k5users when we're not passed a command to run, which implicitly means we're attempting to run the target user's shell (#1026721, revised)[1.10.3-29]- gssapi: pull in upstream fix for a possible NULL dereference in spnego (CVE-2014-4344, #1121510)- gssapi: pull in proposed-and-accepted fix for a double free in initiators (David Woodhouse, CVE-2014-4343, #1121510)[1.10.3-28]- correct a type mistake in the backported fix for CVE-2013-1418/CVE-2013-6800[1.10.3-27]- pull in backported fix for denial of service by injection of malformed GSSAPI tokens (CVE-2014-4341, CVE-2014-4342, #1121510)- incorporate backported patch for remote crash of KDCs which serve multiple realms simultaneously (RT#7756, CVE-2013-1418/CVE-2013-6800, more of[1.10.3-26]- pull in backport of patch to not subsequently always require that responses come from master KDCs if we get one from a master somewhere along the way while chasing referrals (RT#7650, #1113652)[1.10.3-25]- ksu: if the -e flag isn't used, use the target user's shell when checking for authorization via the target user's .k5users file (#1026721)[1.10.3-24]- define _GNU_SOURCE in files where we use EAI_NODATA, to make sure that it's declared (#1059730)[1.10.3-23]- spnego: pull in patch from master to restore preserving the OID of the mechanism the initiator requested when we have multiple OIDs for the same mechanism, so that we reply using the same mechanism OID and the initiator doesn't get confused (#1087068, RT#7858)[1.10.3-22]- add patch from Jatin Nansi to avoid attempting to clear memory at the NULL address if krb5_encrypt_helper() returns an error when called from encrypt_credencpart() (#1055329, pull #158)[1.10.3-21]- drop patch to add additional access() checks to ksu - they shouldn't be resulting in any benefit[1.10.3-20]- apply patch from Nikolai Kondrashov to pass a default realm set in /etc/sysconfig/krb5kdc to the kdb_check_weak helper, so that it doesn't produce an error if there isn't one set in krb5.conf (#1009389)[1.10.3-19]- packaging: don't Obsoletes: older versions of krb5-pkinit-openssl and virtual Provide: krb5-pkinit-openssl on EL6, where we don't need to bother with any of that (#1001961)[1.10.3-18]- pkinit: backport tweaks to avoid trying to call the prompter callback when one isn't set (part of #965721)- pkinit: backport the ability to use a prompter callback to prompt for a password when reading private keys (the rest of #965721)[1.10.3-17]- backport fix to not spin on a short read when reading the length of a response over TCP (RT#7508, #922884)[1.10.3-16]- backport fix for trying all compatible keys when not being strict about acceptor names while reading AP-REQs (RT#7883, #1070244)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-1389");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-1389.html");
script_cve_id("CVE-2013-1418","CVE-2013-6800","CVE-2014-4341","CVE-2014-4344","CVE-2014-4345","CVE-2014-4342","CVE-2014-4343");
script_tag(name:"cvss_base", value:"8.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.10.3~33.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.10.3~33.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"krb5-pkinit-openssl", rpm:"krb5-pkinit-openssl~1.10.3~33.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.10.3~33.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"krb5-server-ldap", rpm:"krb5-server-ldap~1.10.3~33.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.10.3~33.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

