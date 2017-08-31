# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2016-649.nasl 6574 2017-07-06 13:41:26Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120639");
script_version("$Revision: 6574 $");
script_tag(name:"creation_date", value:"2016-02-11 07:16:47 +0200 (Thu, 11 Feb 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:41:26 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: alas-2016-649");
script_tag(name: "insight", value: "It was discovered that ntpd as a client did not correctly check the originate timestamp in received packets. A remote attacker could use this flaw to send a crafted packet to an ntpd client that would effectively disable synchronization with the server, or push arbitrary offset/delay measurements to modify the time on the client. (CVE-2015-8138 )A NULL pointer dereference flaw was found in the way ntpd processed 'ntpdc reslist' commands that queried restriction lists with a large amount of entries. A remote attacker could use this flaw to crash the ntpd process. (CVE-2015-7977 )It was found that NTP does not verify peer associations of symmetric keys when authenticating packets, which might allow remote attackers to conduct impersonation attacks via an arbitrary trusted key. (CVE-2015-7974 )A stack-based buffer overflow was found in the way ntpd processed 'ntpdc reslist' commands that queried restriction lists with a large amount of entries. A remote attacker could use this flaw to crash the ntpd process. (CVE-2015-7978 )It was found that when NTP is configured in broadcast mode, an off-path attacker could broadcast packets with bad authentication (wrong key, mismatched key, incorrect MAC, etc) to all clients. The clients, upon receiving the malformed packets, would break the association with the broadcast server. This could cause the time on affected clients to become out of sync over a longer period of time. (CVE-2015-7979 )A flaw was found in the way the ntpq client certain processed incoming packets in a loop in the getresponse() function. A remote attacker could potentially use this flaw to crash an ntpq client instance. (CVE-2015-8158 )"); 
script_tag(name : "solution", value : "Run yum update ntp to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2016-649.html");
script_cve_id("CVE-2015-7977","CVE-2015-7974","CVE-2015-7978","CVE-2015-7979","CVE-2015-8158","CVE-2015-8138");
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
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
if ((res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~36.29.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"ntpdate", rpm:"ntpdate~4.2.6p5~36.29.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"ntp-debuginfo", rpm:"ntp-debuginfo~4.2.6p5~36.29.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.6p5~36.29.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"ntp-perl", rpm:"ntp-perl~4.2.6p5~36.29.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
