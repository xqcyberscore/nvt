#
#ADV FreeBSD-SA-10:10.openssl.asc
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from ADV FreeBSD-SA-10:10.openssl.asc
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

tag_insight = "FreeBSD includes software from the OpenSSL Project.  The OpenSSL Project is
a collaborative effort to develop a robust, commercial-grade, full-featured
Open Source toolkit implementing the Secure Sockets Layer (SSL v2/v3)
and Transport Layer Security (TLS v1) protocols as well as a full-strength
general purpose cryptography library.

A race condition exists in the OpenSSL TLS server extension code
parsing when used in a multi-threaded application, which uses
OpenSSL's internal caching mechanism.  The race condition can lead to
a buffer overflow. [CVE-2010-3864]

A double free exists in the SSL client ECDH handling code, when
processing specially crafted public keys with invalid prime
numbers. [CVE-2010-2939]";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-10:10.openssl.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-10:10.openssl.asc";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.68704");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-2939");
 script_name("FreeBSD Security Advisory (FreeBSD-SA-10:10.openssl.asc)");



 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"package");

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdpatchlevel", "login/SSH/success");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-bsd.inc");
vuln = 0;
if(patchlevelcmp(rel:"8.1", patchlevel:"2")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"8.0", patchlevel:"6")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"7.3", patchlevel:"4")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"7.1", patchlevel:"16")<0) {
    vuln = 1;
}

if(vuln) {
    security_message(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
