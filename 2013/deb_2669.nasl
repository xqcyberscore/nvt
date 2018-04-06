# OpenVAS Vulnerability Test
# $Id: deb_2669.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2669-1 using nvtgen 1.0
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

tag_affected  = "linux on Debian Linux";
tag_insight   = "The Linux kernel is the core of the Linux operating system.";
tag_solution  = "For the stable distribution (wheezy), this problem has been fixed in version
3.2.41-2+deb7u1.

Note 
: Updates are currently available for the amd64, i386, ia64, s390, s390x
and sparc architectures. Updates for the remaining architectures will be
released as they become available.

The following matrix lists additional source packages that were rebuilt for
compatibility with or to take advantage of this update:

?Debian 7.0 (wheezy)user-mode-linux3.2-2um-1+deb7u1 
We recommend that you upgrade your linux and user-mode-linux packages.

Note 
: Debian carefully tracks all known security issues across every
linux kernel package in all releases under active security support.
However, given the high frequency at which low-severity security
issues are discovered in the kernel and the resource requirements of
doing an update, updates for lower priority issues will normally not
be released for all kernels at the same time. Rather, they will be
released in a staggered or 'leap-frog' fashion.";
tag_summary   = "Several vulnerabilities have been discovered in the Linux kernel that may lead
to a denial of service, information leak or privilege escalation. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2013-0160 
vladz reported a timing leak with the /dev/ptmx character device. A local
user could use this to determine sensitive information such as password
length.

CVE-2013-1796 
Andrew Honig of Google reported an issue in the KVM subsystem. A user in
a guest operating system could corrupt kernel memory, resulting in a
denial of service.

CVE-2013-1929 
Oded Horovitz and Brad Spengler reported an issue in the device driver for
Broadcom Tigon3 based gigabit Ethernet. Users with the ability to attach
untrusted devices can create an overflow condition, resulting in a denial
of service or elevated privileges.

CVE-2013-1979 
Andy Lutomirski reported an issue in the socket level control message
processing subsystem. Local users may be able to gain eleveated privileges.

CVE-2013-2015 
Theodore Ts'o provided a fix for an issue in the ext4 filesystem. Local
users with the ability to mount a specially crafted filesystem can cause
a denial of service (infinite loop).

CVE-2013-2094 
Tommie Rantala discovered an issue in the perf subsystem. An out-of-bounds
access vulnerability allows local users to gain elevated privileges.

CVE-2013-3076 
Mathias Krause discovered an issue in the userspace interface for hash
algorithms. Local users can gain access to sensitive kernel memory.

CVE-2013-3222 
Mathias Krause discovered an issue in the Asynchronous Transfer Mode (ATM)
protocol support. Local users can gain access to sensitive kernel memory.

CVE-2013-3223 
Mathias Krause discovered an issue in the Amateur Radio AX.25 protocol
support. Local users can gain access to sensitive kernel memory.

CVE-2013-3224 
Mathias Krause discovered an issue in the Bluetooth subsystem. Local users
can gain access to sensitive kernel memory.

CVE-2013-3225 
Mathias Krause discovered an issue in the Bluetooth RFCOMM protocol
support. Local users can gain access to sensitive kernel memory.

CVE-2013-3227 
Mathias Krause discovered an issue in the Communication CPU to Application
CPU Interface (CAIF). Local users can gain access to sensitive kernel
memory.

CVE-2013-3228 
Mathias Krause discovered an issue in the IrDA (infrared) subsystem
support. Local users can gain access to sensitive kernel memory.

CVE-2013-3229 
Mathias Krause discovered an issue in the IUCV support on s390 systems.
Local users can gain access to sensitive kernel memory.

CVE-2013-3231 
Mathias Krause discovered an issue in the ANSI/IEEE 802.2 LLC type 2
protocol support. Local users can gain access to sensitive kernel memory.

CVE-2013-3234 
Mathias Krause discovered an issue in the Amateur Radio X.25 PLP (Rose)
protocol support. Local users can gain access to sensitive kernel memory.

CVE-2013-3235 
Mathias Krause discovered an issue in the Transparent Inter Process
Communication (TIPC) protocol support. Local users can gain access to
sensitive kernel memory.

CVE-2013-3301 
Namhyung Kim reported an issue in the tracing subsystem. A privileged
local user could cause a denial of service (system crash). This
vulnerabililty is not applicable to Debian systems by default.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892669");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-1929", "CVE-2013-3234", "CVE-2013-3224", "CVE-2013-3227", "CVE-2013-3228", "CVE-2013-2015", "CVE-2013-3229", "CVE-2013-3231", "CVE-2013-3223", "CVE-2013-3225", "CVE-2013-3076", "CVE-2013-1796", "CVE-2013-2094", "CVE-2013-0160", "CVE-2013-1979", "CVE-2013-3301", "CVE-2013-3235", "CVE-2013-3222");
    script_name("Debian Security Advisory DSA 2669-1 (linux - privilege escalation/denial of service/information leak)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-05-15 00:00:00 +0200 (Wed, 15 May 2013)");
    script_tag(name: "cvss_base", value:"7.2");
    script_tag(name: "cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2669.html");


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
if ((res = isdpkgvuln(pkg:"acpi-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"acpi-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"acpi-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"affs-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"affs-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-4kc-malta-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-loongson-2f-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-4kc-malta-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-loongson-2f-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"core-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"core-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"core-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"core-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"core-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"core-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"core-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"core-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"core-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"core-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"core-modules-3.2.0-4-s390x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"core-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"core-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"core-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-4kc-malta-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-loongson-2f-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-s390x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-4kc-malta-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-loongson-2f-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-s390x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dasd-extra-modules-3.2.0-4-s390x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dasd-modules-3.2.0-4-s390x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"efi-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"efi-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"efi-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"event-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"event-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"event-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"event-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"event-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"event-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"event-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"event-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"event-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-s390x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-s390x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-s390x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fancontrol-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-4kc-malta-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-loongson-2f-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-s390x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"floppy-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"floppy-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"floppy-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"floppy-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"floppy-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-4kc-malta-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-loongson-2f-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-s390x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hfs-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hfs-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hyperv-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hyperv-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hyperv-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hypervisor-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"i2c-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"i2c-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"i2c-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ide-core-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ide-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"input-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"input-modules-3.2.0-4-4kc-malta-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"input-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"input-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"input-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"input-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"input-modules-3.2.0-4-loongson-2f-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"input-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"input-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"input-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"input-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"input-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"input-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-4kc-malta-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-loongson-2f-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-4kc-malta-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-loongson-2f-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"jffs2-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"jffs2-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-4kc-malta-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-loongson-2f-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-4kc-malta-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-loongson-2f-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-r4k-ip22-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-r5k-cobalt-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-r5k-ip32-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-s390x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-s390x-tape-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"leds-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-doc-3.2", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-486", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-4kc-malta", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-5kc-malta", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-686-pae", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-amd64", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-armel", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-armhf", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-i386", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-ia64", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-mips", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-mipsel", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-powerpc", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-s390", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-s390x", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-sparc", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-amd64", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-common", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-common-rt", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-iop32x", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-itanium", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-ixp4xx", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-kirkwood", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-loongson-2f", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-mckinley", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-mv78xx0", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-mx5", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-octeon", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-omap", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-orion5x", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-powerpc", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-powerpc-smp", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-powerpc64", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-r4k-ip22", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-r5k-cobalt", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-r5k-ip32", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-rt-686-pae", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-rt-amd64", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-s390x", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-sb1-bcm91250a", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-sb1a-bcm91480b", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-sparc64", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-sparc64-smp", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-versatile", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-vexpress", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-486", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-4kc-malta", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-5kc-malta", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-686-pae", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-686-pae-dbg", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-amd64", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-amd64-dbg", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-iop32x", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-itanium", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-ixp4xx", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-kirkwood", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-loongson-2f", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-mckinley", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-mv78xx0", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-mx5", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-octeon", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-omap", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-orion5x", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-powerpc", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-powerpc-smp", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-powerpc64", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-r4k-ip22", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-r5k-cobalt", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-r5k-ip32", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-686-pae", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-686-pae-dbg", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-amd64", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-amd64-dbg", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-s390x", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-s390x-dbg", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-s390x-tape", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-sb1-bcm91250a", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-sb1a-bcm91480b", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-sparc64", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-sparc64-smp", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-versatile", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-vexpress", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-manual-3.2", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-source-3.2", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-support-3.2.0-4", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-4kc-malta-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-loongson-2f-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-4kc-malta-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-loongson-2f-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-s390x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"md-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"minix-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"minix-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"minix-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mmc-core-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mmc-core-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mmc-core-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"mtd-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-4kc-malta-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-loongson-2f-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-s390x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-4kc-malta-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-loongson-2f-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-s390x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nfs-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-extra-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-extra-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-extra-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-extra-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-extra-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-loongson-2f-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-s390x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-loongson-2f-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-loongson-2f-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-wireless-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-wireless-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-wireless-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-wireless-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nic-wireless-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntfs-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntfs-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntfs-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ntfs-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"parport-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"parport-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"parport-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"parport-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"plip-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"plip-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"plip-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"plip-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"plip-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-4kc-malta-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-loongson-2f-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qnx4-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qnx4-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"qnx4-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-4kc-malta-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-loongson-2f-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"rtc-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-4kc-malta-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-loongson-2f-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-s390x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-extra-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-extra-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-extra-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-extra-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-extra-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-s390x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sn-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sound-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sound-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"sound-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"speakup-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"speakup-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"speakup-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-4kc-malta-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-loongson-2f-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-4kc-malta-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-loongson-2f-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-4kc-malta-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-loongson-2f-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-4kc-malta-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-kirkwood-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-loongson-2f-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-mx5-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-vexpress-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-4kc-malta-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-loongson-2f-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-s390x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-4-686-pae", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-4-amd64", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-4kc-malta-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-loongson-2f-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-powerpc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-s390x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-486-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-4kc-malta-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-686-pae-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-amd64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-iop32x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-itanium-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-loongson-2f-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-orion5x-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-powerpc-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-r4k-ip22-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-r5k-cobalt-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-r5k-ip32-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-sb1-bcm91250a-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-sparc64-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-versatile-di", ver:"3.2.41-2+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
