# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-0304.nasl 6557 2017-07-06 11:55:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123970");
script_version("$Revision: 6557 $");
script_tag(name:"creation_date", value:"2015-10-06 14:10:59 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:55:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2012-0304");
script_tag(name: "insight", value: "ELSA-2012-0304 -  vixie-cron security, bug fix, and enhancement update - [4:4.1-81]- 455664 adoptions of crontab orphans, forgot add buffer for list of orphans- Related: rhbz#455664[4:4.1-80]- 654961 crond process ignores the changes of user's home directory needs bigger changes of code. The fix wasn't applied, detail in comment#11.- Related: rhbz#249512[4:4.1-79]- CVE-2010-0424 vixie-cron, cronie: Race condition by setting timestamp of user's crontab file, when editing the file- Resolves: rhbz#741534[4:4.1-78]- 625016 - crond requires a restart if mcstransd is stopped - Resolves: rhbz#625016[4:4.1-78]- 460070 entries in cronjobs in /etc/cron.d are checked for valid syntax- Resolves: rhbz#460070[4:4.1-78]- 455664 adoptions of crontab orphans- 249512 crontab should verify a user's access to PAM cron service- Resolves: rhbz#455664, rhbz#249512[4:4.1-78]- 699621 and 699620 man page fix- 529632 service crond status return correct status- 480930 set correct pie options in CFLAGS and LDFLAGS- 476972 crontab error with @reboot entry- Resolves: rhbz#699621, rhbz#699620, rhbz#529632, rhbz#480930, rhbz#476972"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-0304");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-0304.html");
script_cve_id("CVE-2010-0424");
script_tag(name:"cvss_base", value:"3.3");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
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
  if ((res = isrpmvuln(pkg:"vixie-cron", rpm:"vixie-cron~4.1~81.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

