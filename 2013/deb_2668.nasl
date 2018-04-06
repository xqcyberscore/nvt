# OpenVAS Vulnerability Test
# $Id: deb_2668.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2668-1 using nvtgen 1.0
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

tag_affected  = "linux-2.6 on Debian Linux";
tag_insight   = "The Linux kernel is the core of the Linux operating system.";
tag_solution  = "For the oldstable distribution (squeeze), this problem has been fixed in
version 2.6.32-48squeeze3.

The following matrix lists additional source packages that were rebuilt for
compatibility with or to take advantage of this update:

?Debian 6.0 (squeeze)user-mode-linux2.6.32-1um-4+48squeeze3 
We recommend that you upgrade your linux-2.6 and user-mode-linux packages.

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

CVE-2012-2121 
Benjamin Herrenschmidt and Jason Baron discovered issues with the IOMMU
mapping of memory slots used in KVM device assignment. Local users with
the ability to assign devices could cause a denial of service due to a
memory page leak.

CVE-2012-3552 
Hafid Lin reported an issue in the IP networking subsystem. A remote user
can cause a denial of service (system crash) on servers running
applications that set options on sockets which are actively being
processed.

CVE-2012-4461 
Jon Howell reported a denial of service issue in the KVM subsystem.
On systems that do not support the XSAVE feature, local users with
access to the /dev/kvm interface can cause a system crash.

CVE-2012-4508 
Dmitry Monakhov and Theodore Ts'o reported a race condition in the ext4
filesystem. Local users could gain access to sensitive kernel memory.

CVE-2012-6537 
Mathias Krause discovered information leak issues in the Transformation
user configuration interface. Local users with the CAP_NET_ADMIN capability
can gain access to sensitive kernel memory.

CVE-2012-6539 
Mathias Krause discovered an issue in the networking subsystem. Local
users on 64-bit systems can gain access to sensitive kernel memory.

CVE-2012-6540 
Mathias Krause discovered an issue in the Linux virtual server subsystem.
Local users can gain access to sensitive kernel memory. Note: this issue
does not affect Debian provided kernels, but may affect custom kernels
built from Debian's linux-source-2.6.32 package.

CVE-2012-6542 
Mathias Krause discovered an issue in the LLC protocol support code.
Local users can gain access to sensitive kernel memory.

CVE-2012-6544 
Mathias Krause discovered issues in the Bluetooth subsystem.
Local users can gain access to sensitive kernel memory.

CVE-2012-6545 
Mathias Krause discovered issues in the Bluetooth RFCOMM protocol
support. Local users can gain access to sensitive kernel memory.

CVE-2012-6546 
Mathias Krause discovered issues in the ATM networking support. Local
users can gain access to sensitive kernel memory.

CVE-2012-6548 
Mathias Krause discovered an issue in the UDF file system support.
Local users can obtain access to sensitive kernel memory.

CVE-2012-6549 
Mathias Krause discovered an issue in the isofs file system support.
Local users can obtain access to sensitive kernel memory.

CVE-2013-0349 
Anderson Lizardo discovered an issue in the Bluetooth Human Interface
Device Protocol (HIDP) stack. Local users can obtain access to sensitive
kernel memory.

CVE-2013-0914 
Emese Revfy discovered an issue in the signal implementation. Local
users may be able to bypass the address space layout randomization (ASLR)
facility due to a leaking of information to child processes.

CVE-2013-1767 
Greg Thelen reported an issue in the tmpfs virtual memory filesystem.
Local users with sufficient privilege to mount filesystems can cause
a denial of service or possibly elevated privileges due to a use-after free defect.

CVE-2013-1773 
Alan Stern provided a fix for a defect in the UTF8->UTF16 string conversion
facility used by the VFAT filesystem. A local user could cause a buffer
overflow condition, resulting in a denial of service or potentially
elevated privileges.

CVE-2013-1774 
Wolfgang Frisch provided a fix for a NULL-pointer dereference defect
in the driver for some serial USB devices from Inside Out Networks.
Local users with permission to access these devices can create a denial
of service (kernel oops) by causing the device to be removed while it is
in use.

CVE-2013-1792 
Mateusz Guzik of Red Hat EMEA GSS SEG Team discovered a race condition
in the access key retention support in the kernel. A local user could
cause a denial of service (NULL pointer dereference).

CVE-2013-1796 
Andrew Honig of Google reported an issue in the KVM subsystem. A user in
a guest operating system could corrupt kernel memory, resulting in a
denial of service.

CVE-2013-1798 
Andrew Honig of Google reported an issue in the KVM subsystem. A user in
a guest operating system could cause a denial of service due to a use after-free defect.

CVE-2013-1826 
Mathias Krause discovered an issue in the Transformation (XFRM) user
configuration interface of the networking stack. A user with the
CAP_NET_ADMIN capability may be able to gain elevated privileges.

CVE-2013-1860 
Oliver Neukum discovered an issue in the USB CDC WCM Device Management
driver. Local users with the ability to attach devices can cause a
denial of service (kernel crash) or potentially gain elevated privileges.

CVE-2013-1928 
Kees Cook provided a fix for an information leak in the
VIDEO_SET_SPU_PALETTE ioctl for 32-bit applications running on a 64-bit
kernel. Local users can gain access to sensitive kernel memory.

CVE-2013-1929 
Oded Horovitz and Brad Spengler reported an issue in the device driver for
Broadcom Tigon3 based gigabit Ethernet. Users with the ability to attach
untrusted devices can create an overflow condition, resulting in a denial
of service or elevated privileges.

CVE-2013-2015 
Theodore Ts'o provided a fix for an issue in the ext4 filesystem. Local
users with the ability to mount a specially crafted filesystem can cause
a denial of service (infinite loop).

CVE-2013-2634 
Mathias Krause discovered a few issues in the Data Center Bridging (DCB)
netlink interface. Local users can gain access to sensitive kernel memory.

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
sensitive kernel memory.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892668");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-1773", "CVE-2013-1929", "CVE-2013-1792", "CVE-2013-1774", "CVE-2013-3224", "CVE-2012-6548", "CVE-2012-4508", "CVE-2013-2634", "CVE-2013-1928", "CVE-2012-6540", "CVE-2012-6537", "CVE-2012-6539", "CVE-2013-1767", "CVE-2012-2121", "CVE-2013-3229", "CVE-2013-3231", "CVE-2013-1798", "CVE-2012-6545", "CVE-2013-3225", "CVE-2012-4461", "CVE-2013-0914", "CVE-2012-6544", "CVE-2013-3235", "CVE-2012-3552", "CVE-2012-6546", "CVE-2012-6549", "CVE-2012-6542", "CVE-2013-0349", "CVE-2013-3234", "CVE-2013-1826", "CVE-2013-3228", "CVE-2013-2015", "CVE-2013-3223", "CVE-2013-1796", "CVE-2013-1860", "CVE-2013-3222");
    script_name("Debian Security Advisory DSA 2668-1 (linux-2.6 - privilege escalation/denial of service/information leak)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-05-14 00:00:00 +0200 (Tue, 14 May 2013)");
    script_tag(name: "cvss_base", value:"6.9");
    script_tag(name: "cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2668.html");


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
if ((res = isdpkgvuln(pkg:"firmware-linux-free", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-base", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-doc-2.6.32", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-486", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-4kc-malta", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-5kc-malta", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-686", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-686-bigmem", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-amd64", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-armel", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-i386", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-ia64", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-mips", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-mipsel", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-powerpc", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-s390", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-sparc", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-amd64", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-common", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-common-openvz", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-common-vserver", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-common-xen", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-iop32x", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-itanium", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-ixp4xx", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-kirkwood", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-mckinley", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-openvz-686", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-openvz-amd64", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-orion5x", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-powerpc", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-powerpc-smp", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-powerpc64", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-r4k-ip22", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-r5k-cobalt", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-r5k-ip32", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-s390x", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-sb1-bcm91250a", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-sb1a-bcm91480b", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-sparc64", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-sparc64-smp", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-versatile", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-686", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-686-bigmem", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-amd64", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-itanium", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-mckinley", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-powerpc", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-powerpc64", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-s390x", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-sparc64", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-xen-686", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-xen-amd64", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-486", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-4kc-malta", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-5kc-malta", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-686", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-686-bigmem", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-686-bigmem-dbg", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-amd64", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-amd64-dbg", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-iop32x", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-itanium", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-ixp4xx", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-kirkwood", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-mckinley", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-openvz-686", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-openvz-686-dbg", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-openvz-amd64", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-openvz-amd64-dbg", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-orion5x", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-powerpc", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-powerpc-smp", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-powerpc64", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-r4k-ip22", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-r5k-cobalt", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-r5k-ip32", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-s390x", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-s390x-tape", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-sb1-bcm91250a", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-sb1a-bcm91480b", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-sparc64", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-sparc64-smp", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-versatile", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-686", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-686-bigmem", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-686-bigmem-dbg", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-amd64", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-amd64-dbg", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-itanium", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-mckinley", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-powerpc", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-powerpc64", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-s390x", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-sparc64", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-xen-686", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-xen-686-dbg", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-xen-amd64", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-5-xen-amd64-dbg", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-manual-2.6.32", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-patch-debian-2.6.32", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-source-2.6.32", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-support-2.6.32-5", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-tools-2.6.32", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-2.6.32-5-xen-686", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-2.6.32-5-xen-amd64", ver:"2.6.32-48squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
