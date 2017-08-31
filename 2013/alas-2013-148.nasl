# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2013-148.nasl 6577 2017-07-06 13:43:46Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120066");
script_version("$Revision: 6577 $");
script_tag(name:"creation_date", value:"2015-09-08 13:16:41 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:43:46 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2013-148");
script_tag(name: "insight", value: "A malicious Network File System version 4 (NFSv4) server could return a crafted reply to a GETACL request, causing a denial of service on the client. (CVE-2012-2375 , Moderate)A divide-by-zero flaw was found in the TCP Illinois congestion control algorithm implementation in the Linux kernel. If the TCP Illinois congestion control algorithm were in use (the sysctl net.ipv4.tcp_congestion_control variable set to illinois), a local, unprivileged user could trigger this flaw and cause a denial of service. (CVE-2012-4565 , Moderate)A NULL pointer dereference flaw was found in the way a new node's hot added memory was propagated to other nodes' zonelists. By utilizing this newly added memory from one of the remaining nodes, a local, unprivileged user could use this flaw to cause a denial of service. (CVE-2012-5517 , Moderate)It was found that a prevoius kernel release did not correctly fix the CVE-2009-4307  issue, a divide-by-zero flaw in the ext4 file system code. A local, unprivileged user with the ability to mount an ext4 file system could use this flaw to cause a denial of service. (CVE-2012-2100 , Low)A flaw was found in the way the Linux kernel's IPv6 implementation handled overlapping, fragmented IPv6 packets. A remote attacker could potentially use this flaw to bypass protection mechanisms (such as a firewall or intrusion detection system (IDS)) when sending network packets to a target system. (CVE-2012-4444 , Low)"); 
script_tag(name : "solution", value : "Run yum update kernel nvidia to update your system.  You will need to reboot your system in order for the new kernel to be running.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2013-148.html");
script_cve_id("CVE-2012-5517", "CVE-2012-2100", "CVE-2012-4444", "CVE-2012-4565", "CVE-2012-2375");
script_tag(name:"cvss_base", value:"7.1");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
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
if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.2.36~1.46.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.2.36~1.46.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-tools-debuginfo", rpm:"kernel-tools-debuginfo~3.2.36~1.46.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.2.36~1.46.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~3.2.36~1.46.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.2.36~1.46.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.2.36~1.46.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
