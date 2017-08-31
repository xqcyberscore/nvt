# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2016-684.nasl 6574 2017-07-06 13:41:26Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@iki.fi> 
#
# OpenVAS and security consultance available from openvas@solinor.com
# see https://solinor.fi/openvas-en/ for more information
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://ping-viini.org 
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
script_oid("1.3.6.1.4.1.25623.1.0.120674");
script_version("$Revision: 6574 $");
script_tag(name:"creation_date", value:"2016-05-09 14:11:50 +0300 (Mon, 09 May 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:41:26 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: alas-2016-684");
script_tag(name: "insight", value: "wolfSSL (formerly CyaSSL) before 3.6.8 does not properly handle faults associated with the Chinese Remainder Theorem (CRT) process when allowing ephemeral key exchange without low memory optimizations on a server, which makes it easier for remote attackers to obtain private RSA keys by capturing TLS handshakes, also known as a Lenstra attack. (CVE-2015-7744 )Unspecified vulnerability in Oracle MySQL Server 5.6.24 and earlier allows remote authenticated users to affect integrity via unknown vectors related to Server : Security : Privileges. (CVE-2015-4864 )Unspecified vulnerability in Oracle MySQL Server 5.6.23 and earlier allows remote authenticated users to affect availability via unknown vectors related to Server : InnoDB. (CVE-2015-4866 )Unspecified vulnerability in Oracle MySQL Server 5.5.45 and earlier, and 5.6.26 and earlier, allows remote authenticated users to affect availability via unknown vectors related to Server : InnoDB. (CVE-2015-4861 )Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier allows remote authenticated users to affect availability via vectors related to DML. (CVE-2015-4862 )Unspecified vulnerability in Oracle MySQL 5.5.46 and earlier allows remote authenticated users to affect availability via unknown vectors related to Optimizer. (CVE-2016-0616 )Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier allows remote authenticated users to affect availability via unknown vectors related to Server : Memcached. (CVE-2015-4910 )Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier allows remote authenticated users to affect availability via vectors related to Server : DML, a different vulnerability than CVE-2015-4858 . (CVE-2015-4913 )Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows remote authenticated users to affect availability via unknown vectors related to InnoDB. (CVE-2016-0610 )Unspecified vulnerability in Oracle MySQL 5.6.21 and earlier allows remote authenticated users to affect availability via vectors related to DML. (CVE-2016-0594 )Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows remote authenticated users to affect availability via vectors related to DML. (CVE-2016-0595 )Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows remote authenticated users to affect availability via vectors related to DML. (CVE-2016-0596 )Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows remote authenticated users to affect availability via unknown vectors related to Optimizer. (CVE-2016-0597 )Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows remote authenticated users to affect availability via vectors related to DML. (CVE-2016-0598 )Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier allows remote authenticated users to affect availability via unknown vectors related to Server : Partition, a different vulnerability than CVE-2015-4802 . (CVE-2015-4792 )Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier allows remote authenticated users to affect availability via unknown vectors related to Server : Security : Privileges. (CVE-2015-4791 )Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier, when running on Windows, allows remote authenticated users to affect availability via unknown vectors related to Server : Query Cache. (CVE-2015-4807 )Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier, allows remote authenticated users to affect availability via unknown vectors related to Server : Parser. (CVE-2015-4870 )Unspecified vulnerability in Oracle MySQL 5.7.9 allows remote authenticated users to affect availability via unknown vectors related to Optimizer. (CVE-2016-0599 )Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows local users to affect confidentiality, integrity, and availability via unknown vectors related to Client. (CVE-2016-0546 )Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier allows remote authenticated users to affect availability via vectors related to DML, a different vulnerability than CVE-2015-4913 . (CVE-2015-4858 )Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier allows remote authenticated users to affect availability via vectors related to Server : DDL. (CVE-2015-4815 )Unspecified vulnerability in Oracle MySQL Server 5.6.25 and earlier allows remote authenticated users to affect availability via unknown vectors related to Server : Partition. (CVE-2015-4833 )Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier allows remote authenticated users to affect integrity via unknown vectors related to Server : Security : Privileges. (CVE-2015-4830 )Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier allows remote authenticated users to affect availability via unknown vectors related to Server : SP. (CVE-2015-4836 )Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows remote authenticated users to affect availability via vectors related to UDF. (CVE-2016-0608 )Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows remote authenticated users to affect availability via unknown vectors related to privileges. (CVE-2016-0609 )Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows remote authenticated users to affect availability via unknown vectors related to Options. (CVE-2016-0505 )Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows remote authenticated users to affect availability via vectors related to DML, a different vulnerability than CVE-2016-0503 . (CVE-2016-0504 )Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier allows remote authenticated users to affect availability via unknown vectors related to Server : Replication. (CVE-2015-4890 )Unspecified vulnerability in Oracle MySQL 5.7.9 allows remote authenticated users to affect availability via unknown vectors related to Partition. (CVE-2016-0601 )Unspecified vulnerability in Oracle MySQL Server 5.6.25 and earlier allows remote authenticated users to affect availability via unknown vectors related to libmysqld. (CVE-2015-4904 )Unspecified vulnerability in Oracle MySQL Server 5.6.23 and earlier allows remote authenticated users to affect availability via vectors related to Server : DML. (CVE-2015-4905 )Unspecified vulnerability in Oracle MySQL 5.6.26 and earlier allows remote authenticated users to affect availability via unknown vectors. (CVE-2016-0605 )Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows remote authenticated users to affect integrity via unknown vectors related to encryption. (CVE-2016-0606 )Unspecified vulnerability in Oracle MySQL Server 5.6.25 and earlier allows local users to affect availability via unknown vectors related to Server : Security : Firewall. (CVE-2015-4766 )Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows remote authenticated users to affect availability via unknown vectors related to Optimizer. (CVE-2016-0611 )Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows remote authenticated users to affect availability via unknown vectors related to replication. (CVE-2016-0607 )Unspecified vulnerability in Oracle MySQL Server 5.6.25 and earlier allows local users to affect confidentiality, integrity, and availability via unknown vectors related to Client programs. (CVE-2015-4819 )Unspecified vulnerability in Oracle MySQL Server 5.6.25 and earlier allows remote authenticated users to affect confidentiality, integrity, and availability via vectors related to DML. (CVE-2015-4879 )Unspecified vulnerability in Oracle MySQL 5.6.11 and earlier allows remote authenticated users to affect availability via unknown vectors related to Optimizer. (CVE-2016-0502 )Unspecified vulnerability in Oracle MySQL Server 5.6.25 and earlier allows remote authenticated users to affect availability via unknown vectors related to Server : InnoDB. (CVE-2015-4895 )Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows remote authenticated users to affect availability via vectors related to DML, a different vulnerability than CVE-2016-0504 . (CVE-2016-0503 )Unspecified vulnerability in Oracle MySQL 5.6.27 and earlier allows remote authenticated users to affect availability via unknown vectors related to InnoDB. (CVE-2016-0600 )Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier allows remote authenticated users to affect availability via unknown vectors related to Server : Partition, a different vulnerability than CVE-2015-4792 . (CVE-2015-4802 )Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier allows remote authenticated users to affect availability via unknown vectors related to Server : Optimizer. (CVE-2015-4800 )Unspecified vulnerability in Oracle MySQL Server 5.6.26 and earlier allows remote authenticated users to affect confidentiality via unknown vectors related to Server : Types. (CVE-2015-4826 )"); 
script_tag(name : "solution", value : "Run yum update mysql56 to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2016-684.html");
script_cve_id("CVE-2015-4864","CVE-2015-4866","CVE-2015-4861","CVE-2015-4862","CVE-2016-0616","CVE-2015-4910","CVE-2015-4913","CVE-2016-0610","CVE-2016-0594","CVE-2016-0595","CVE-2016-0596","CVE-2016-0597","CVE-2016-0598","CVE-2015-4792","CVE-2015-4791","CVE-2015-4807","CVE-2015-4870","CVE-2016-0599","CVE-2016-0546","CVE-2015-4858","CVE-2015-4815","CVE-2015-4833","CVE-2015-4830","CVE-2015-4836","CVE-2016-0608","CVE-2016-0609","CVE-2016-0505","CVE-2016-0504","CVE-2015-4890","CVE-2016-0601","CVE-2015-4904","CVE-2015-4905","CVE-2016-0605","CVE-2016-0606","CVE-2015-7744","CVE-2015-4766","CVE-2016-0611","CVE-2016-0607","CVE-2015-4819","CVE-2015-4879","CVE-2016-0502","CVE-2015-4895","CVE-2016-0503","CVE-2016-0600","CVE-2015-4802","CVE-2015-4800","CVE-2015-4826");
script_tag(name:"cvss_base", value:"7.2");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name:"summary", value:"Amazon Linux Local Security Checks");
script_copyright("Eero Volotinen");
script_family("Amazon Linux Local Security Checks");
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
if(release == "AMAZON")
{
if ((res = isrpmvuln(pkg:"mysql56-debuginfo", rpm:"mysql56-debuginfo~5.6.29~1.14.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mysql56-common", rpm:"mysql56-common~5.6.29~1.14.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mysql56-test", rpm:"mysql56-test~5.6.29~1.14.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mysql56-errmsg", rpm:"mysql56-errmsg~5.6.29~1.14.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mysql56-server", rpm:"mysql56-server~5.6.29~1.14.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mysql56-devel", rpm:"mysql56-devel~5.6.29~1.14.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mysql56", rpm:"mysql56~5.6.29~1.14.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mysql56-libs", rpm:"mysql56-libs~5.6.29~1.14.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mysql56-bench", rpm:"mysql56-bench~5.6.29~1.14.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mysql56-embedded-devel", rpm:"mysql56-embedded-devel~5.6.29~1.14.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"mysql56-embedded", rpm:"mysql56-embedded~5.6.29~1.14.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
