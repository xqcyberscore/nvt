# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2013-201.nasl 4515 2016-11-15 10:21:35Z cfi $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120028");
script_version("$Revision: 4515 $");
script_tag(name:"creation_date", value:"2015-09-08 13:15:40 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2016-11-15 11:21:35 +0100 (Tue, 15 Nov 2016) $");
script_name("Amazon Linux Local Check: ALAS-2013-201");
script_tag(name: "insight", value: "The openvpn_decrypt function in crypto.c in OpenVPN 2.3.0 and earlier, when running in UDP mode, allows remote attackers to obtain sensitive information via a timing attack involving an HMAC comparison function that does not run in constant time and a padding oracle attack on the CBC mode cipher."); 
script_tag(name : "solution", value : "Run yum update openvpn to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2013-201.html");
script_cve_id("CVE-2013-2061");
script_tag(name:"cvss_base", value:"2.6");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("HostDetails/OS/cpe:/o:amazon:linux", "login/SSH/success", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name:"summary", value:"Amazon Linux Local Security Checks");
script_summary("Amazon Linux Local Security Checks ALAS-2013-201");
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
if ((res = isrpmvuln(pkg:"openvpn", rpm:"openvpn~2.3.1~1.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"openvpn-debuginfo", rpm:"openvpn-debuginfo~2.3.1~1.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
