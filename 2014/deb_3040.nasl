# OpenVAS Vulnerability Test
# $Id: deb_3040.nasl 9354 2018-04-06 07:15:32Z cfischer $
# Auto-generated from advisory DSA 3040-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net
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


if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.703040");
    script_version("$Revision: 9354 $");
    script_cve_id("CVE-2014-3634");
    script_name("Debian Security Advisory DSA 3040-1 (rsyslog - security update)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2014-09-30 00:00:00 +0200 (Tue, 30 Sep 2014)");
    script_tag(name:"cvss_base", value:"7.5");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2014/dsa-3040.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: "rsyslog on Debian Linux");
        script_tag(name: "insight",   value: "Rsyslog is a multi-threaded implementation of syslogd (a system utility
providing support for message logging), with features that include:

* reliable syslog over TCP, SSL/TLS and RELP
* on-demand disk buffering
* email alerting
* writing to MySQL or PostgreSQL databases (via separate output plugins)
* permitted sender lists
* filtering on any part of the syslog message
* on-the-wire message compression
* fine-grained output format control
* failover to backup destinations
* enterprise-class encrypted syslog relaying");
    script_tag(name: "solution",  value: "For the stable distribution (wheezy), this problem has been fixed in
version 5.8.11-3+deb7u1.

For the unstable distribution (sid), this problem has been fixed in
version 8.4.1-1.

We recommend that you upgrade your rsyslog packages.");
    script_tag(name: "summary",   value: "Rainer Gerhards, the rsyslog project leader, reported a vulnerability in
Rsyslog, a system for log processing. As a consequence of this
vulnerability an attacker can send malformed messages to a server, if
this one accepts data from untrusted sources, and trigger a denial of
service attack.");
    script_tag(name: "vuldetect", value:  "This check tests the installed software version using the apt package manager.");
    script_tag(name:"qod_type", value:"package");
    script_tag(name:"solution_type", value:"VendorFix");
    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"rsyslog", ver:"5.8.11-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rsyslog-doc", ver:"5.8.11-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rsyslog-gnutls", ver:"5.8.11-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rsyslog-gssapi", ver:"5.8.11-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rsyslog-mysql", ver:"5.8.11-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rsyslog-pgsql", ver:"5.8.11-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rsyslog-relp", ver:"5.8.11-3+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rsyslog", ver:"5.8.11-3+deb7u1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rsyslog-doc", ver:"5.8.11-3+deb7u1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rsyslog-gnutls", ver:"5.8.11-3+deb7u1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rsyslog-gssapi", ver:"5.8.11-3+deb7u1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rsyslog-mysql", ver:"5.8.11-3+deb7u1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rsyslog-pgsql", ver:"5.8.11-3+deb7u1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rsyslog-relp", ver:"5.8.11-3+deb7u1", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rsyslog", ver:"5.8.11-3+deb7u1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rsyslog-doc", ver:"5.8.11-3+deb7u1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rsyslog-gnutls", ver:"5.8.11-3+deb7u1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rsyslog-gssapi", ver:"5.8.11-3+deb7u1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rsyslog-mysql", ver:"5.8.11-3+deb7u1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rsyslog-pgsql", ver:"5.8.11-3+deb7u1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rsyslog-relp", ver:"5.8.11-3+deb7u1", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rsyslog", ver:"5.8.11-3+deb7u1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rsyslog-doc", ver:"5.8.11-3+deb7u1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rsyslog-gnutls", ver:"5.8.11-3+deb7u1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rsyslog-gssapi", ver:"5.8.11-3+deb7u1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rsyslog-mysql", ver:"5.8.11-3+deb7u1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rsyslog-pgsql", ver:"5.8.11-3+deb7u1", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rsyslog-relp", ver:"5.8.11-3+deb7u1", rls:"DEB7.3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
