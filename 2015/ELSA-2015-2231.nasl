# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-2231.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122754");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-11-24 10:17:27 +0200 (Tue, 24 Nov 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-2231");
script_tag(name: "insight", value: "ELSA-2015-2231 -  ntp security, bug fix, and enhancement update - [4.2.6p5-22]- check origin timestamp before accepting KoD RATE packet (CVE-2015-7704)- allow only one step larger than panic threshold with -g (CVE-2015-5300)[4.2.6p5-20]- validate lengths of values in extension fields (CVE-2014-9297)- drop packets with spoofed source address ::1 (CVE-2014-9298)- reject packets without MAC when authentication is enabled (CVE-2015-1798)- protect symmetric associations with symmetric key against DoS attack (CVE-2015-1799)- fix generation of MD5 keys with ntp-keygen on big-endian systems (CVE-2015-3405)- add option to set Differentiated Services Code Point (DSCP) (#1202828)- add nanosecond support to SHM refclock (#1117702)- allow creating all SHM segments with owner-only access (#1122012)- allow different thresholds for forward and backward step (#1193154)- allow symmetric keys up to 32 bytes again (#1191111)- don't step clock for leap second with -x option (#1191122)- don't drop packets with source port below 123 (#1171640)- retry joining multicast groups (#1207014)- increase memlock limit again (#1053569)- warn when monitor can't be disabled due to limited restrict (#1191108)- use larger RSA exponent in ntp-keygen (#1191116)- fix crash in ntpq mreadvar command (#1180721)- move sntp kod database to allow SELinux labeling (#1082934)- fix typos in ntpd man page (#1195211)- improve documentation of restrict command (#1213953)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-2231");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-2231.html");
script_cve_id("CVE-2014-9750","CVE-2014-9751","CVE-2014-9297","CVE-2014-9298","CVE-2015-1798","CVE-2015-1799","CVE-2015-3405");
script_tag(name:"cvss_base", value:"4.3");
script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:N/I:P/A:P");
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
  if ((res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~22.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.6p5~22.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ntp-perl", rpm:"ntp-perl~4.2.6p5~22.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ntpdate", rpm:"ntpdate~4.2.6p5~22.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"sntp", rpm:"sntp~4.2.6p5~22.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

