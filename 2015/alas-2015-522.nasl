# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2015-522.nasl 6575 2017-07-06 13:42:08Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120062");
script_version("$Revision: 6575 $");
script_tag(name:"creation_date", value:"2015-09-08 13:16:33 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:42:08 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2015-522");
script_tag(name: "insight", value: "The file-descriptor passed by libcontainer to the pid-1 process of a container has been found to be opened prior to performing the chroot, allowing insecure open and symlink traversal. This allows malicious container images to trigger a local privilege escalation. (CVE-2015-3627 )Libcontainer version 1.6.0 introduced changes which facilitated a mount namespace breakout upon respawn of a container. This allowed malicious images to write files to the host system and escape containerization. (CVE-2015-3629 )Several paths underneath /proc were writable from containers, allowing global system manipulation and configuration. These paths included /proc/asound, /proc/timer_stats, /proc/latency_stats, and /proc/fs.  By allowing writes to /proc/fs, it has been noted that CIFS volumes could be forced into a protocol downgrade attack by a root user operating inside of a container. Machines having loaded the timer_stats module were vulnerable to having this mechanism enabled and consumed by a container. (CVE-2015-3630 )By allowing volumes to override files of /proc within a mount namespace, a user could specify arbitrary policies for Linux Security Modules, including setting an unconfined policy underneath AppArmor, or a docker_t policy for processes managed by SELinux. In all versions of Docker up until 1.6.1, it is possible for malicious images to configure volume mounts such that files of proc may be overridden. (CVE-2015-3631 )"); 
script_tag(name : "solution", value : "Run yum update docker to update your system.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2015-522.html");
script_cve_id("CVE-2015-3631", "CVE-2015-3630", "CVE-2015-3629", "CVE-2015-3627");
script_tag(name:"cvss_base", value:"7.2");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
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
if ((res = isrpmvuln(pkg:"docker", rpm:"docker~1.6.0~1.3.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"docker", rpm:"docker~1.6.0~1.3.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"docker-pkg-devel", rpm:"docker-pkg-devel~1.6.0~1.3.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"docker-devel", rpm:"docker-devel~1.6.0~1.3.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
