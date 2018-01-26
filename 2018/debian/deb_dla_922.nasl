###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_922.nasl 8532 2018-01-25 11:08:09Z teissa $
#
# Auto-generated from advisory DLA 922-1 using nvtgen 1.0
# Script version:1.0
# #
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.890922");
  script_version("$Revision: 8532 $");
  script_cve_id("CVE-2016-10200", "CVE-2016-2188", "CVE-2016-9604", "CVE-2017-2647", "CVE-2017-2671", "CVE-2017-5967", "CVE-2017-5970", "CVE-2017-6951", "CVE-2017-7184", "CVE-2017-7261", "CVE-2017-7273", "CVE-2017-7294", "CVE-2017-7308", "CVE-2017-7472", "CVE-2017-7616", "CVE-2017-7618");
  script_name("Debian Lts Announce DLA 922-1 ([SECURITY] [DLA 922-1] linux security update)");
  script_tag(name:"last_modification", value:"$Date: 2018-01-25 12:08:09 +0100 (Thu, 25 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-17 00:00:00 +0100 (Wed, 17 Jan 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/04/msg00041.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
  script_tag(name:"affected", value:"linux on Debian Linux");
  script_tag(name:"insight", value:"The Linux kernel is the core of the Linux operating system.");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
3.2.88-1. This version also includes bug fixes from upstream version
3.2.88, and fixes some older security issues in the keyring, packet
socket and cryptographic hash subsystems that do not have CVE IDs.

For Debian 8 'Jessie', most of these problems have been fixed in
version 3.16.43-1 which will be part of the next point release.

We recommend that you upgrade your linux packages.");
  script_tag(name:"summary",  value:"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or have other
impacts.

CVE-2016-2188

Ralf Spenneberg of OpenSource Security reported that the iowarrior
device driver did not sufficiently validate USB descriptors. This
allowed a physically present user with a specially designed USB
device to cause a denial of service (crash).

CVE-2016-9604

It was discovered that the keyring subsystem allowed a process to
set a special internal keyring as its session keyring. The
security impact in this version of the kernel is unknown.

CVE-2016-10200

Baozeng Ding and Andrey Konovalov reported a race condition in the
L2TP implementation which could corrupt its table of bound
sockets. A local user could use this to cause a denial of service
(crash) or possibly for privilege escalation.

CVE-2017-2647 / CVE-2017-6951

idl3r reported that the keyring subsystem would allow a process
to search for 'dead' keys, causing a null pointer dereference.
A local user could use this to cause a denial of service (crash).

CVE-2017-2671

Daniel Jiang discovered a race condition in the ping socket
implementation. A local user with access to ping sockets could
use this to cause a denial of service (crash) or possibly for
privilege escalation. This feature is not accessible to any
users by default.

CVE-2017-5967

Xing Gao reported that the /proc/timer_list file showed
information about all processes, not considering PID namespaces.
If timer debugging was enabled by a privileged user, this leaked
information to processes contained in PID namespaces.

CVE-2017-5970

Andrey Konovalov discovered a denial-of-service flaw in the IPv4
networking code. This can be triggered by a local or remote
attacker if a local UDP or raw socket has the IP_RETOPTS option
enabled.

CVE-2017-7184

Chaitin Security Research Lab discovered that the net xfrm
subsystem did not sufficiently validate replay state parameters,
allowing a heap buffer overflow. This can be used by a local user
with the CAP_NET_ADMIN capability for privilege escalation.

CVE-2017-7261

Vladis Dronov and Murray McAllister reported that the vmwgfx
driver did not sufficiently validate rendering surface parameters.
In a VMware guest, this can be used by a local user to cause a
denial of service (crash).

CVE-2017-7273

Benoit Camredon reported that the hid-cypress driver did not
sufficiently validate HID reports. This possibly allowed a
physically present user with a specially designed USB device to
cause a denial of service (crash).

CVE-2017-7294

Li Qiang reported that the vmwgfx driver did not sufficiently
validate rendering surface parameters. In a VMware guest, this
can be used by a local user to cause a denial of service (crash)
or possibly for privilege escalation.

CVE-2017-7308

Andrey Konovalov reported that the packet socket (AF_PACKET)
implementation did not sufficiently validate buffer parameters.
This can be used by a local user with the CAP_NET_RAW capability
for privilege escalation.

CVE-2017-7472

Eric Biggers reported that the keyring subsystem allowed a thread
to create new thread keyrings repeatedly, causing a memory leak.
This can be used by a local user to cause a denial of service
(memory exhaustion).

CVE-2017-7616

Chris Salls reported an information leak in the 32-bit big-endian
compatibility implementations of set_mempolicy() and mbind().
This does not affect any architecture supported in Debian 7 LTS.

CVE-2017-7618

Sabrina Dubroca reported that the cryptographic hash subsystem
does not correctly handle submission of unaligned data to a
device that is already busy, resulting in infinite recursion.
On some systems this can be used by local users to cause a
denial of service (crash).

For Debian 7 'Wheezy', these problems have been fixed in version
3.2.88-1. This version also includes bug fixes from upstream version
3.2.88, and fixes some older security issues in the keyring, packet
socket and cryptographic hash subsystems that do not have CVE IDs.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"linux-doc-3.2", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-486", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-686-pae", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-amd64", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-armel", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-armhf", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-i386", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-amd64", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-common", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-common-rt", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-iop32x", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-ixp4xx", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-kirkwood", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-mv78xx0", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-mx5", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-omap", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-orion5x", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-rt-686-pae", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-rt-amd64", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-versatile", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-vexpress", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-486", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-686-pae", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-all", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-all-amd64", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-all-armel", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-all-armhf", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-all-i386", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-amd64", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-common", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-common-rt", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-iop32x", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-ixp4xx", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-kirkwood", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-mv78xx0", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-mx5", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-omap", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-orion5x", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-rt-686-pae", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-rt-amd64", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-versatile", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-vexpress", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-486", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-686-pae", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-686-pae-dbg", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-amd64", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-amd64-dbg", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-iop32x", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-ixp4xx", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-kirkwood", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-mv78xx0", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-mx5", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-omap", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-orion5x", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-686-pae", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-686-pae-dbg", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-amd64", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-amd64-dbg", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-versatile", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-vexpress", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-486", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-686-pae", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-686-pae-dbg", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-amd64", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-amd64-dbg", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-iop32x", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-ixp4xx", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-kirkwood", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-mv78xx0", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-mx5", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-omap", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-orion5x", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-rt-686-pae", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-rt-686-pae-dbg", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-rt-amd64", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-rt-amd64-dbg", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-versatile", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-vexpress", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-manual-3.2", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-source-3.2", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-support-3.2.0-4", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-support-3.2.0-5", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-4-686-pae", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-4-amd64", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-5-686-pae", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-5-amd64", ver:"3.2.88-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99); # Not vulnerable.
}
