# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2016-0039.nasl 6562 2017-07-06 12:22:42Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.com> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://www.solinor.com
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
script_oid("1.3.6.1.4.1.25623.1.0.131203");
script_version("$Revision: 6562 $");
script_tag(name:"creation_date", value:"2016-02-02 07:44:19 +0200 (Tue, 02 Feb 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:22:42 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2016-0039");
script_tag(name: "insight", value: "In ntpd before 4.2.8p6, when used with symmetric key encryption, the client would accept packets encrypted with keys for any configured server, allowing a server to impersonate other servers to clients, thus performing a man-in-the-middle attack. A server can be attacked by a client in a similar manner (CVE-2015-7974). A NULL pointer dereference flaw was found in the way ntpd processed 'ntpdc reslist' commands that queried restriction lists with a large amount of entries. A remote attacker could use this flaw to crash the ntpd process (CVE-2015-7977). A stack-based buffer overflow was found in the way ntpd processed 'ntpdc reslist' commands that queried restriction lists with a large amount of entries. A remote attacker could use this flaw to crash the ntpd process (CVE-2015-7978). It was found that when NTP is configured in broadcast mode, an off-path attacker could broadcast packets with bad authentication (wrong key, mismatched key, incorrect MAC, etc) to all clients. The clients, upon receiving the malformed packets, would break the association with the broadcast server. This could cause the time on affected clients to become out of sync over a longer period of time (CVE-2015-7979). A faulty protection against spoofing and replay attacks allows an attacker to disrupt synchronization with kiss-of-death packets, take full control of the clock, or cause ntpd to crash (CVE-2015-8138). A flaw was found in the way the ntpq client certain processed incoming packets in a loop in the getresponse() function. A remote attacker could potentially use this flaw to crash an ntpq client instance (CVE-2015-8158). The ntp package has been patched to fix these issues and a few other bugs. Note that there are still some unfixed issues. Two of those issues, CVE-2015-8139 and CVE-2015-8140, are vulnerabilities to spoofing and replay attacks that can be mitigated by either adding the noquery option to all restrict entries in ntp.conf, configuring ntpd to get time from multiple sources, or using a restriction list to limit who is allowed to issue ntpq and ntpdc queries. Additionally, the other unfixed issues can also be mitigated. CVE-2015-7973, a replay attack issue, can be mitigated by not using broadcast mode, and CVE-2015-7976, a bug that can cause globbing issues on the server, can be mitigated by restricting use of the saveconfig command with the restrict nomodify directive."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2016-0039.html");
script_cve_id("CVE-2015-7974","CVE-2015-7977","CVE-2015-7978","CVE-2015-7979","CVE-2015-8138","CVE-2015-8158");
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2016-0039");
script_copyright("Eero Volotinen");
script_family("Mageia Linux Local Security Checks");
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
if(release == "MAGEIA5")
{
if ((res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~24.4.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
