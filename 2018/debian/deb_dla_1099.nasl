###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1099.nasl 10219 2018-06-15 12:00:55Z cfischer $
#
# Auto-generated from advisory DLA 1099-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891099");
  script_version("$Revision: 10219 $");
  script_cve_id("CVE-2017-1000111", "CVE-2017-1000251", "CVE-2017-1000363", "CVE-2017-1000365", "CVE-2017-1000380", "CVE-2017-10661", "CVE-2017-10911", "CVE-2017-11176", "CVE-2017-11600", "CVE-2017-12134", "CVE-2017-12153", "CVE-2017-12154", "CVE-2017-14106", "CVE-2017-14140", "CVE-2017-14156", "CVE-2017-14340", "CVE-2017-14489", "CVE-2017-7482", "CVE-2017-7542", "CVE-2017-7889");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1099-1] linux security update)");
  script_tag(name:"last_modification", value:"$Date: 2018-06-15 14:00:55 +0200 (Fri, 15 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/09/msg00017.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7\.[0-9]+");
  script_tag(name:"affected", value:"linux on Debian Linux");
  script_tag(name:"insight", value:"The Linux kernel is the core of the Linux operating system.");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
3.2.93-1. This version also includes bug fixes from upstream versions
up to and including 3.2.93.

For Debian 8 'Jessie', these problems have been fixed in version
3.16.43-2+deb8u4 or were fixed in an earlier version.

For Debian 9 'Stretch', these problems have been fixed in version
4.9.30-2+deb9u4 or were fixed in an earlier version.

We recommend that you upgrade your linux packages.");
  script_tag(name:"summary",  value:"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2017-7482

Shi Lei discovered that RxRPC Kerberos 5 ticket handling code does
not properly verify metadata, leading to information disclosure,
denial of service or potentially execution of arbitrary code.

CVE-2017-7542

An integer overflow vulnerability in the ip6_find_1stfragopt()
function was found allowing a local attacker with privileges to open
raw sockets to cause a denial of service.

CVE-2017-7889

Tommi Rantala and Brad Spengler reported that the mm subsystem does
not properly enforce the CONFIG_STRICT_DEVMEM protection mechanism,
allowing a local attacker with access to /dev/mem to obtain
sensitive information or potentially execute arbitrary code.

CVE-2017-10661

Dmitry Vyukov of Google reported that the timerfd facility does
not properly handle certain concurrent operations on a single file
descriptor. This allows a local attacker to cause a denial of
service or potentially to execute arbitrary code.

CVE-2017-10911 / XSA-216

Anthony Perard of Citrix discovered an information leak flaw in Xen
blkif response handling, allowing a malicious unprivileged guest to
obtain sensitive information from the host or other guests.

CVE-2017-11176

It was discovered that the mq_notify() function does not set the
sock pointer to NULL upon entry into the retry logic. An attacker
can take advantage of this flaw during a userspace close of a
Netlink socket to cause a denial of service or potentially cause
other impact.

CVE-2017-11600

bo Zhang reported that the xfrm subsystem does not properly
validate one of the parameters to a netlink message. Local users
with the CAP_NET_ADMIN capability can use this to cause a denial
of service or potentially to execute arbitrary code.

CVE-2017-12134 / #866511 / XSA-229

Jan H. Sch?nherr of Amazon discovered that when Linux is running
in a Xen PV domain on an x86 system, it may incorrectly merge
block I/O requests. A buggy or malicious guest may trigger this
bug in dom0 or a PV driver domain, causing a denial of service or
potentially execution of arbitrary code.

This issue can be mitigated by disabling merges on the underlying
back-end block devices, e.g.:
echo 2 > /sys/block/nvme0n1/queue/nomerges

CVE-2017-12153

bo Zhang reported that the cfg80211 (wifi) subsystem does not
properly validate the parameters to a netlink message. Local users
with the CAP_NET_ADMIN capability on a system with a wifi device
can use this to cause a denial of service.

CVE-2017-12154

Jim Mattson of Google reported that the KVM implementation for
Intel x86 processors did not correctly handle certain nested
hypervisor configurations. A malicious guest (or nested guest in a
suitable L1 hypervisor) could use this for denial of service.

CVE-2017-14106

Andrey Konovalov of Google reported that a specific sequence of
operations on a TCP socket could lead to division by zero. A
local user could use this for denial of service.

CVE-2017-14140

Otto Ebeling reported that the move_pages() system call permitted
users to discover the memory layout of a set-UID process running
under their real user-ID. This made it easier for local users to
exploit vulnerabilities in programs installed with the set-UID
permission bit set.

CVE-2017-14156

'sohu0106' reported an information leak in the atyfb video driver.
A local user with access to a framebuffer device handled by this
driver could use this to obtain sensitive information.

CVE-2017-14340

Richard Wareing discovered that the XFS implementation allows the
creation of files with the 'realtime' flag on a filesystem with no
realtime device, which can result in a crash (oops). A local user
with access to an XFS filesystem that does not have a realtime
device can use this for denial of service.

CVE-2017-14489

ChunYu of Red Hat discovered that the iSCSI subsystem does not
properly validate the length of a netlink message, leading to
memory corruption. A local user with permission to manage iSCSI
devices can use this for denial of service or possibly to
execute arbitrary code.

CVE-2017-1000111

Andrey Konovalov of Google reported that a race condition in the
raw packet (af_packet) feature. Local users with the CAP_NET_RAW
capability can use this to cause a denial of service or possibly to
execute arbitrary code.

CVE-2017-1000251 / #875881

Armis Labs discovered that the Bluetooth subsystem does not
properly validate L2CAP configuration responses, leading to a
stack buffer overflow. This is one of several vulnerabilities
dubbed 'Blueborne'. A nearby attacker can use this to cause a
denial of service or possibly to execute arbitrary code on a
system with Bluetooth enabled.

CVE-2017-1000363

Roee Hay reported that the lp driver does not properly bounds-check
passed arguments. This has no security impact in Debian.

CVE-2017-1000365

It was discovered that argument and environment pointers are not
properly taken into account by the size restrictions on arguments
and environmental strings passed through execve(). A local
attacker can take advantage of this flaw in conjunction with other
flaws to execute arbitrary code.

CVE-2017-1000380

Alexander Potapenko of Google reported a race condition in the ALSA
(sound) timer driver, leading to an information leak. A local user
with permission to access sound devices could use this to obtain
sensitive information.

For Debian 7 'Wheezy', these problems have been fixed in version
3.2.93-1. This version also includes bug fixes from upstream versions
up to and including 3.2.93.

For Debian 8 'Jessie', these problems have been fixed in version
3.16.43-2+deb8u4 or were fixed in an earlier version.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"linux-doc-3.2", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-486", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-686-pae", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-amd64", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-armel", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-armhf", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-i386", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-amd64", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-common", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-common-rt", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-iop32x", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-ixp4xx", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-kirkwood", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-mv78xx0", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-mx5", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-omap", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-orion5x", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-rt-686-pae", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-rt-amd64", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-versatile", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-vexpress", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-486", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-686-pae", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-all", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-all-amd64", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-all-armel", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-all-armhf", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-all-i386", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-amd64", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-common", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-common-rt", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-iop32x", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-ixp4xx", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-kirkwood", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-mv78xx0", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-mx5", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-omap", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-orion5x", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-rt-686-pae", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-rt-amd64", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-versatile", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-vexpress", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-486", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-686-pae", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-686-pae-dbg", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-amd64", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-amd64-dbg", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-iop32x", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-ixp4xx", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-kirkwood", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-mv78xx0", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-mx5", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-omap", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-orion5x", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-686-pae", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-686-pae-dbg", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-amd64", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-amd64-dbg", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-versatile", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-vexpress", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-486", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-686-pae", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-686-pae-dbg", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-amd64", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-amd64-dbg", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-iop32x", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-ixp4xx", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-kirkwood", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-mv78xx0", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-mx5", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-omap", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-orion5x", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-rt-686-pae", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-rt-686-pae-dbg", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-rt-amd64", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-rt-amd64-dbg", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-versatile", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-vexpress", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-manual-3.2", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-source-3.2", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-support-3.2.0-4", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-support-3.2.0-5", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-4-686-pae", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-4-amd64", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-5-686-pae", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-5-amd64", ver:"3.2.93-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
