# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2013-216.nasl 4515 2016-11-15 10:21:35Z cfi $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120433");
script_version("$Revision: 4515 $");
script_tag(name:"creation_date", value:"2015-09-08 13:26:16 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2016-11-15 11:21:35 +0100 (Tue, 15 Nov 2016) $");
script_name("Amazon Linux Local Check: ALAS-2013-216");
script_tag(name: "insight", value: "It was discovered that NSS leaked timing information when decrypting TLS/SSL and DTLS protocol encrypted records when CBC-mode cipher suites were used. A remote attacker could possibly use this flaw to retrieve plain text from the encrypted packets by using a TLS/SSL or DTLS server as a padding oracle. (CVE-2013-1620 )An out-of-bounds memory read flaw was found in the way NSS decoded certain certificates. If an application using NSS decoded a malformed certificate, it could cause the application to crash. (CVE-2013-0791 )"); 
script_tag(name : "solution", value : "Run yum update nspr to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2013-216.html");
script_cve_id("CVE-2013-0791", "CVE-2013-1620");
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("HostDetails/OS/cpe:/o:amazon:linux", "login/SSH/success", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name:"summary", value:"Amazon Linux Local Security Checks");
script_summary("Amazon Linux Local Security Checks ALAS-2013-216");
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
if ((res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.9.5~2.17.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"nspr-devel", rpm:"nspr-devel~4.9.5~2.17.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"nspr-debuginfo", rpm:"nspr-debuginfo~4.9.5~2.17.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
