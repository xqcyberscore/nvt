# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2015-539.nasl 6575 2017-07-06 13:42:08Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120202");
script_version("$Revision: 6575 $");
script_tag(name:"creation_date", value:"2015-09-08 13:20:01 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:42:08 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2015-539");
script_tag(name: "insight", value: "As reported upstream:When NTP or cmdmon access was configured (from chrony.conf or via authenticated cmdmon) with a subnet size that is indivisible by 4 and an address that has nonzero bits in the 4-bit subnet remainder (e.g. 192.168.15.0/22 or f000::/3), the new setting was written to an incorrect location, possibly outside the allocated array.  An attacker that has the command key and is allowed to access cmdmon (only localhost is allowed by default) could exploit this to crash chronyd or possibly execute arbitrary code with the privileges of the chronyd process. (CVE-2015-1821 )When allocating memory to save unacknowledged replies to authenticated command requests, the last next pointer was not initialized to NULL. When all allocated reply slots were used, the next reply could be written to an invalid memory instead of allocating a new slot for it.  An attacker that has the command key and is allowed to access cmdmon (only localhost is allowed by default) could exploit this to crash chronyd or possibly execute arbitrary code with the privileges of the chronyd process. (CVE-2015-1822 )An attacker knowing that NTP hosts A and B are peering with each other (symmetric association) can send a packet with random timestamps to host A with source address of B which will set the NTP state variables on A to the values sent by the attacker. Host A will then send on its next poll to B a packet with originate timestamp that doesn't match the transmit timestamp of B and the packet will be dropped. If the attacker does this periodically for both hosts, they won't be able to synchronize to each other.  Authentication using a symmetric key can fully protect against this attack, but in implementations following the NTPv3 (RFC 1305) or NTPv4 (RFC 5905) specification the state variables were updated even when the authentication check failed and the association was not protected. (CVE-2015-1853 )"); 
script_tag(name : "solution", value : "Run yum update chrony to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2015-539.html");
script_cve_id("CVE-2015-1822", "CVE-2015-1853", "CVE-2015-1821");
script_tag(name:"cvss_base", value:"6.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
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
if ((res = isrpmvuln(pkg:"chrony-debuginfo", rpm:"chrony-debuginfo~1.31.1~1.13.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"chrony", rpm:"chrony~1.31.1~1.13.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
