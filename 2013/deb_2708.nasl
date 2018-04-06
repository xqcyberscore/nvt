# OpenVAS Vulnerability Test
# $Id: deb_2708.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2708-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");

tag_affected  = "fail2ban on Debian Linux";
tag_insight   = "Monitors log files (e.g. /var/log/auth.log,
/var/log/apache/access.log) and temporarily or persistently bans
failure-prone addresses by updating existing firewall rules. The
software was completely rewritten at version 0.7.0 and now allows
easy specification of different actions to be taken such as to ban an
IP using iptables or hostsdeny rules, or simply to send a
notification email. Currently, by default, supports ssh/apache/vsftpd
but configuration can be easily extended for monitoring any other ASCII
file. All filters and actions are given in the config files, thus
fail2ban can be adopted to be used with a variety of files and
firewalls.";
tag_solution  = "For the oldstable distribution (squeeze), this problem has been fixed in
version 0.8.4-3+squeeze2.

For the stable distribution (wheezy), this problem has been fixed in
version 0.8.6-3wheezy2.

For the testing distribution (jessie), this problem has been fixed in
version 0.8.10-1.

For the unstable distribution (sid), this problem has been fixed in
version 0.8.10-1.

We recommend that you upgrade your fail2ban packages.";
tag_summary   = "Krzysztof Katowicz-Kowalewski discovered a vulnerability in Fail2ban, a
log monitoring and system which can act on attack by preventing hosts to
connect to specified services using the local firewall.

When using Fail2ban to monitor Apache logs, improper input validation in
log parsing could enable a remote attacker to trigger an IP ban on
arbitrary addresses, thus causing a denial of service.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892708");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-2178");
    script_name("Debian Security Advisory DSA 2708-1 (fail2ban - denial of service)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-06-16 00:00:00 +0200 (Sun, 16 Jun 2013)");
    script_tag(name: "cvss_base", value:"5.0");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2708.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: tag_affected);
    script_tag(name: "insight",   value: tag_insight);
#    script_tag(name: "impact",    value: tag_impact);
    script_tag(name: "solution",  value: tag_solution);
    script_tag(name: "summary",   value: tag_summary);
    script_tag(name: "vuldetect", value: tag_vuldetect);
    script_tag(name:"qod_type", value:"package");
    script_tag(name:"solution_type", value:"VendorFix");

    exit(0);
}

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"fail2ban", ver:"0.8.4-3+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fail2ban", ver:"0.8.6-3wheezy2", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
