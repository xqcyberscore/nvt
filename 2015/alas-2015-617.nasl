# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2015-617.nasl 6575 2017-07-06 13:42:08Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@iki.fi> 
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
script_oid("1.3.6.1.4.1.25623.1.0.120607");
script_version("$Revision: 6575 $");
script_tag(name:"creation_date", value:"2015-12-15 02:51:20 +0200 (Tue, 15 Dec 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:42:08 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: alas-2015-617");
script_tag(name: "insight", value: "A buffer overflow flaw was found in the way glibc's gethostbyname_r() and other related functions computed the size of a buffer when passed a misaligned buffer as input. An attacker able to make an application call any of these functions with a misaligned buffer could use this flaw to crash the application or, potentially, execute arbitrary code with the permissions of the user running the application. (CVE-2015-1781 )It was discovered that the nss_files backend for the Name Service Switch in glibc would return incorrect data to applications or corrupt the heap (depending on adjacent heap contents). A local attacker could potentially use this flaw to execute arbitrary code on the system. (CVE-2015-5277 )It was discovered that, under certain circumstances, glibc's getaddrinfo() function would send DNS queries to random file descriptors. An attacker could potentially use this flaw to send DNS queries to unintended recipients, resulting in information disclosure or data loss due to the application encountering corrupted data. (CVE-2013-7423 )A stack overflow flaw was found in glibc's swscanf() function. An attacker able to make an application call the swscanf() function could use this flaw to crash that application or, potentially, execute arbitrary code with the permissions of the user running the application. (CVE-2015-1473 )A heap-based buffer overflow flaw was found in glibc's swscanf() function. An attacker able to make an application call the swscanf() function could use this flaw to crash that application or, potentially, execute arbitrary code with the permissions of the user running the application. (CVE-2015-1472 )"); 
script_tag(name : "solution", value : "Run yum update glibc to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2015-617.html");
script_cve_id("CVE-2015-1781","CVE-2015-5277","CVE-2013-7423","CVE-2015-1473","CVE-2015-1472");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
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
if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.17~106.163.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"glibc-common", rpm:"glibc-common~2.17~106.163.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.17~106.163.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.17~106.163.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.17~106.163.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"glibc-static", rpm:"glibc-static~2.17~106.163.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"glibc-debuginfo", rpm:"glibc-debuginfo~2.17~106.163.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"glibc-headers", rpm:"glibc-headers~2.17~106.163.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"glibc-debuginfo-common", rpm:"glibc-debuginfo-common~2.17~106.163.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
