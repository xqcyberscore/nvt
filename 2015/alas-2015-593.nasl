# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2015-593.nasl 6575 2017-07-06 13:42:08Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120093");
script_version("$Revision: 6575 $");
script_tag(name:"creation_date", value:"2015-09-08 13:17:14 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:42:08 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2015-593");
script_tag(name: "insight", value: "As discussed upstream, a flaw was found in the way ntpd processed certain remote configuration packets.  Note that remote configuration is disabled by default in NTP.  (CVE-2015-5146 )It was found that the :config command can be used to set the pidfile and driftfile paths without any restrictions. A remote attacker could use this flaw to overwrite a file on the file system with a file containing the pid of the ntpd process (immediately) or the current estimated drift of the system clock (in hourly intervals).  (CVE-2015-5196 )It was found that ntpd could crash due to an uninitialized variable when processing malformed logconfig configuration commands.  (CVE-2015-5194 )It was found that ntpd exits with a segmentation fault when a statistics type that was not enabled during compilation (e.g. timingstats) is referenced by the statistics or filegen configuration command.  (CVE-2015-5195 )It was discovered that sntp would hang in an infinite loop when a crafted NTP packet was received, related to the conversion of the precision value in the packet to double.  (CVE-2015-5219 )A flaw was found in the way the ntp-keygen utility generated MD5 symmetric keys on big-endian systems. An attacker could possibly use this flaw to guess generated MD5 keys, which could then be used to spoof an NTP client or server.  (CVE-2015-3405 )"); 
script_tag(name : "solution", value : "Run yum update ntp to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2015-593.html");
script_cve_id("CVE-2015-5146", "CVE-2015-5196", "CVE-2015-5194", "CVE-2015-5195", "CVE-2015-5219", "CVE-2015-3405");
script_tag(name:"cvss_base", value:"4.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
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
if ((res = isrpmvuln(pkg:"ntpdate", rpm:"ntpdate~4.2.6p5~33.26.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"ntp-debuginfo", rpm:"ntp-debuginfo~4.2.6p5~33.26.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.6p5~33.26.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"ntp-perl", rpm:"ntp-perl~4.2.6p5~33.26.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
