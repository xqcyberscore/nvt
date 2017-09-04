# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2015-607.nasl 6959 2017-08-18 07:24:59Z asteins $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120597");
script_version("$Revision: 6959 $");
script_tag(name:"creation_date", value:"2015-11-08 13:10:59 +0200 (Sun, 08 Nov 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-08-18 09:24:59 +0200 (Fri, 18 Aug 2017) $");
script_name("Amazon Linux Local Check: alas-2015-607");
script_tag(name: "insight", value: "It was discovered that ntpd as a client did not correctly check timestamps in Kiss-of-Death packets. A remote attacker could use this flaw to send a crafted Kiss-of-Death packet to an ntpd client that would increase the client's polling interval value, and effectively disable synchronization with the server. (CVE-2015-7704 )It was found that ntpd did not correctly implement the threshold limitation for the '-g' option, which is used to set the time without any restrictions. A man-in-the-middle attacker able to intercept NTP traffic between a connecting client and an NTP server could use this flaw to force that client to make multiple steps larger than the panic threshold, effectively changing the time to an arbitrary value. (CVE-2015-5300 )It was found that the fix for CVE-2014-9750  was incomplete: three issues were found in the value length checks in ntp_crypto.c, where a packet with particular autokey operations that contained malicious data was not always being completely validated. Receipt of these packets can cause ntpd to crash. (CVE-2015-7691 , CVE-2015-7692 , CVE-2015-7702 )A potential off by one vulnerability exists in the cookedprint functionality of ntpq. A specially crafted buffer could cause a buffer overflow potentially resulting in null byte being written out of bounds. (CVE-2015-7852 )A memory leak flaw was found in ntpd's CRYPTO_ASSOC. If ntpd is configured to use autokey authentication, an attacker could send packets to ntpd that would, after several days of ongoing attack, cause it to run out of memory. (CVE-2015-7701 )"); 
script_tag(name : "solution", value : "Run yum update ntp to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2015-607.html");
script_cve_id("CVE-2015-7692","CVE-2015-7691","CVE-2015-7852","CVE-2015-7704","CVE-2015-7701","CVE-2015-7702","CVE-2015-5300","CVE-2015-7871","CVE-2014-9750");
script_tag(name:"cvss_base", value:"7.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
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
if ((res = isrpmvuln(pkg:"ntpdate", rpm:"ntpdate~4.2.6p5~34.27.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~34.27.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"ntp-debuginfo", rpm:"ntp-debuginfo~4.2.6p5~34.27.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.6p5~34.27.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"ntp-perl", rpm:"ntp-perl~4.2.6p5~34.27.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
