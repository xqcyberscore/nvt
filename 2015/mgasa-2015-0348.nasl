# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0348.nasl 6563 2017-07-06 12:23:47Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.130039");
script_version("$Revision: 6563 $");
script_tag(name:"creation_date", value:"2015-10-15 10:41:52 +0300 (Thu, 15 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:23:47 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2015-0348");
script_tag(name: "insight", value: "Updated ntp packages fix security vulnerability: A flaw was found in the way ntpd processed certain remote configuration packets. An attacker could use a specially crafted package to cause ntpd to crash if the attacker had authenticated access to remote ntpd configuration (CVE-2015-5146). It was found that ntpd could crash due to an uninitialized variable when processing malformed logconfig configuration commands, for example, ntpq -c :config logconfig a (CVE-2015-5194). It was found that ntpd exits with a segmentation fault when a statistics type that was not enabled during compilation (e.g. timingstats) is referenced by the statistics or filegen configuration command, for example, ntpq -c ':config statistics timingstats' ntpq -c ':config filegen timingstats' (CVE-2015-5195). It was found that the :config command can be used to set the pidfile and driftfile paths without any restrictions. A remote attacker could use this flaw to overwrite a file on the file system with a file containing the pid of the ntpd process (immediately) or the current estimated drift of the system clock (in hourly intervals). For example, ntpq -c ':config pidfile /tmp/ntp.pid' ntpq -c ':config driftfile /tmp/ntp.drift' (CVE-2015-5196). It was discovered that sntp would hang in an infinite loop when a crafted NTP packet was received, related to the conversion of the precision value in the packet to double (CVE-2015-5219)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0348.html");
script_cve_id("CVE-2015-5146","CVE-2015-5194","CVE-2015-5195","CVE-2015-5196","CVE-2015-5219");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0348");
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
if ((res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~24.1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
