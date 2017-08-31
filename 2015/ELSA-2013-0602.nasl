# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-0602.nasl 6600 2017-07-07 09:58:31Z teissa $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123679");
script_version("$Revision: 6600 $");
script_tag(name:"creation_date", value:"2015-10-06 14:07:08 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:58:31 +0200 (Fri, 07 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-0602");
script_tag(name: "insight", value: "ELSA-2013-0602 -  java-1.7.0-openjdk security update - [1.7.0.9-2.3.8.0.0.1.el6_4]- Update DISTRO_NAME in specfile[1.7.0.9-2.3.8.0el6]- Revert to rhel 6.3 version of spec file- Revert to icedtea7 2.3.8 forest- Resolves: rhbz#917183[1.7.0.11-2.4.0.pre5.el6]- Update to latest snapshot of icedtea7 2.4 forest- Resolves: rhbz#917183[1.7.0.9-2.4.0.pre4.3.el6]- Updated to icedtea 2.4.0.pre4,- Rewritten (again) patch3 java-1.7.0-openjdk-java-access-bridge-security.patch- Resolves: rhbz#911530[1.7.0.9-2.4.0.pre3.3.el6]- Updated to icedtea 2.4.0.pre3, updated!- Rewritten patch3 java-1.7.0-openjdk-java-access-bridge-security.patch- Resolves: rhbz#911530[1.7.0.9-2.4.0.pre2.3.el6]- Removed testing - mauve was outdated and - jtreg was icedtea relict- Updated to icedtea 2.4.0.pre2, updated?- Added java -Xshare:dump to post (see 513605) fo jitarchs- Resolves: rhbz#911530[1.7.0.11-2.4.0.2.el6]- Unapplied but kept (for 2.3revert) patch110, java-1.7.0-openjdk-nss-icedtea-e9c857dcb964.patch- Added and applied patch113: java-1.7.0-openjdk-aes-update_reset.patch- Added and applied patch114: java-1.7.0-openjdk-nss-tck.patch- Added and applied patch115: java-1.7.0-openjdk-nss-split_results.patch- NSS enabled by default - enable_nss set to 1- rewritten patch109 - java-1.7.0-openjdk-nss-config-1.patch- rewritten patch111 - java-1.7.0-openjdk-nss-config-2.patch- Resolves: rhbz#831734[1.7.0.11-2.4.0.1.el6]- Rewritten patch105: java-1.7.0-openjdk-disable-system-lcms.patch- Added jxmd and idlj to alternatives- make executed with DISABLE_INTREE_EC=true and UNLIMITED_CRYPTO=true- Unapplied patch302 and deleted systemtap.patch- buildver increased to 11- icedtea_version set to 2.4.0- Added and applied patch112 java-1.7.openjdk-doNotUseDisabledEcc.patch- removed tmp-patches source tarball- Added /lib/security/US_export_policy.jar and lib/security/local_policy.jar- Disabled nss - enable_nss set to 0- Resolves: rhbz#895034"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-0602");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-0602.html");
script_cve_id("CVE-2013-0809","CVE-2013-1493");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk", rpm:"java-1.7.0-openjdk~1.7.0.9~2.3.8.0.0.1.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-demo", rpm:"java-1.7.0-openjdk-demo~1.7.0.9~2.3.8.0.0.1.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-devel", rpm:"java-1.7.0-openjdk-devel~1.7.0.9~2.3.8.0.0.1.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-javadoc", rpm:"java-1.7.0-openjdk-javadoc~1.7.0.9~2.3.8.0.0.1.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-src", rpm:"java-1.7.0-openjdk-src~1.7.0.9~2.3.8.0.0.1.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

