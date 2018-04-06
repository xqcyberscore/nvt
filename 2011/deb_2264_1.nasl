# OpenVAS Vulnerability Test
# $Id: deb_2264_1.nasl 9351 2018-04-06 07:05:43Z cfischer $
# Description: Auto-generated from advisory DSA 2264-1 (linux-2.6)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
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

include("revisions-lib.inc");
tag_insight = "Several vulnerabilities have been discovered in the Linux kernel that may lead
to a privilege escalation, denial of service or information leak.  The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-2524

David Howells reported an issue in the Common Internet File System (CIFS).
Local users could cause arbitrary CIFS shares to be mounted by introducing
malicious redirects.

CVE-2010-3875

Vasiliy Kulikov discovered an issue in the Linux implementation of the
Amateur Radio AX.25 Level 2 protocol. Local users may obtain access to
sensitive kernel memory.

CVE-2010-4075

Dan Rosenberg reported an issue in the tty layer that may allow local
users to obtain access to sensitive kernel memory.

CVE-2010-4655

Kees Cook discovered several issues in the ethtool interface which may
allow local users with the CAP_NET_ADMIN capability to obtain access to
sensitive kernel memory.

CVE-2011-0695

Jens Kuehnel reported an issue in the InfiniBand stack. Remote attackers can
exploit a race condition to cause a denial of service (kernel panic).

CVE-2011-0710

Al Viro reported an issue in the /proc/<pid>/status interface on the
s390 architecture. Local users could gain access to sensitive memory
in processes they do not own via the task_show_regs entry.

CVE-2011-0711

Dan Rosenberg reported an issue in the XFS filesystem. Local users may
obtain access to sensitive kernel memory.

CVE-2011-0726

Kees Cook reported an issue in the /proc/pid/stat implementation. Local
users could learn the text location of a process, defeating protections
provided by address space layout randomization (ASLR).

CVE-2011-1010

Timo Warns reported an issue in the Linux support for Mac partition tables.
Local users with physical access could cause a denial of service (panic)
by adding a storage device with a malicious map_count value.

CVE-2011-1012

Timo Warns reported an issue in the Linux support for Mac partition tables.
Local users with physical access could cause a denial of service (panic)
by adding a storage device with a malicious map_count value.

CVE-2011-1017

Timo Warns reported an issue in the Linux support for LDM partition tables.
Users with physical access can gain access to sensitive kernel memory or
gain elevated privileges by adding a storage device with a specially
crafted LDM partition.

CVE-2011-1078

Vasiliy Kulikov discovered an issue in the Bluetooth subsystem. Local users
can obtain access to sensitive kernel memory.

CVE-2011-1079

Vasiliy Kulikov discovered an issue in the Bluetooth subsystem. Local users
with the CAP_NET_ADMIN capability can cause a denial of service (kernel
Oops).

CVE-2011-1080

Vasiliy Kulikov discovered an issue in the Netfilter subsystem. Local users
can obtain access to sensitive kernel memory.

CVE-2011-1090

Neil Horman discovered a memory leak in the setacl() call on NFSv4
filesystems. Local users can exploit this to cause a denial of service
(Oops).

CVE-2011-1093

Johan Hovold reported an issue in the Datagram Congestion Control Protocol
(DCCP) implementation. Remote users could cause a denial of service by
sending data after closing a socket.

CVE-2011-1160

Peter Huewe reported an issue in the Linux kernel's support for TPM security
chips. Local users with permission to open the device can gain access to
sensitive kernel memory.

CVE-2011-1163

Timo Warns reported an issue in the kernel support for Alpha OSF format disk
partitions. Users with physical access can gain access to sensitive kernel
memory by adding a storage device with a specially crafted OSF partition.

CVE-2011-1170

Vasiliy Kulikov reported an issue in the Netfilter arp table
implementation. Local users with the CAP_NET_ADMIN capability can gain
access to sensitive kernel memory.

CVE-2011-1171

Vasiliy Kulikov reported an issue in the Netfilter IP table
implementation. Local users with the CAP_NET_ADMIN capability can gain
access to sensitive kernel memory.

CVE-2011-1172

Vasiliy Kulikov reported an issue in the Netfilter IP6 table
implementation. Local users with the CAP_NET_ADMIN capability can gain
access to sensitive kernel memory.

CVE-2011-1173

Vasiliy Kulikov reported an issue in the Acorn Econet protocol
implementation. Local users can obtain access to sensitive kernel memory on
systems that use this rare hardware.

CVE-2011-1180

Dan Rosenberg reported a buffer overflow in the Information Access Service
of the IrDA protocol, used for Infrared devices. Remote attackers within IR
device range can cause a denial of service or possibly gain elevated
privileges.

CVE-2011-1182

Julien Tinnes reported an issue in the rt_sigqueueinfo interface. Local
users can generate signals with falsified source pid and uid information.

CVE-2011-1477

Dan Rosenberg reported issues in the Open Sound System driver for cards that
include a Yamaha FM synthesizer chip. Local users can cause memory
corruption resulting in a denial of service. This issue does not affect
official Debian Linux image packages as they no longer provide support for
OSS.  However, custom kernels built from Debians linux-source-2.6.32 may
have enabled this configuration and would therefore be vulnerable.

CVE-2011-1493

Dan Rosenburg reported two issues in the Linux implementation of the
Amateur Radio X.25 PLP (Rose) protocol. A remote user can cause a denial of
service by providing specially crafted facilities fields.

CVE-2011-1577

Timo Warns reported an issue in the Linux support for GPT partition tables.
Local users with physical access could cause a denial of service (Oops)
by adding a storage device with a malicious partition table header.

CVE-2011-1593

Robert Swiecki reported a signednes issue in the next_pidmap() function,
which can be exploited my local users to cause a denial of service.

CVE-2011-1598

Dave Jones reported an issue in the Broadcast Manager Controller Area
Network (CAN/BCM) protocol that may allow local users to cause a NULL
pointer dereference, resulting in a denial of service.

CVE-2011-1745

Vasiliy Kulikov reported an issue in the Linux support for AGP devices.
Local users can obtain elevated privileges or cause a denial of service due
to missing bounds checking in the AGPIOC_BIND ioctl. On default Debian
installations, this is exploitable only by users in the video group.

CVE-2011-1746

Vasiliy Kulikov reported an issue in the Linux support for AGP devices.
Local users can obtain elevated privileges or cause a denial of service
due to missing bounds checking in the agp_allocate_memory and
agp_create_user_memory. On default Debian installations, this is
exploitable only by users in the video group.

CVE-2011-1748

Oliver Kartkopp reported an issue in the Controller Area Network (CAN) raw
socket implementation which permits ocal users to cause a NULL pointer
dereference, resulting in a denial of service.

CVE-2011-1759

Dan Rosenberg reported an issue in the support for executing old ABI
binaries on ARM processors. Local users can obtain elevated privileges due
to insufficient bounds checking in the semtimedop system call.

CVE-2011-1767

Alexecy Dobriyan reported an issue in the GRE over IP implementation.
Remote users can cause a denial of service by sending a packet during
module initialization.

CVE-2011-1768

Alexecy Dobriyan reported an issue in the IP tunnels implementation.
Remote users can cause a denial of service by sending a packet during
module initialization.

CVE-2011-1776

Timo Warns reported an issue in the Linux implementation for GUID
partitions. Users with physical access can gain access to sensitive kernel
memory by adding a storage device with a specially crafted corrupted
invalid partition table.

CVE-2011-2022

Vasiliy Kulikov reported an issue in the Linux support for AGP devices.
Local users can obtain elevated privileges or cause a denial of service due
to missing bounds checking in the AGPIOC_UNBIND ioctl. On default Debian
installations, this is exploitable only by users in the video group.

CVE-2011-2182

Ben Hutchings reported an issue with the fix for CVE-2011-1017 (see above)
that made it insufficient to resolve the issue.

For the oldstable distribution (lenny), this problem has been fixed in
version 2.6.26-26lenny3. Updates for arm and hppa are not yet available,
but will be released as soon as possible.

The following matrix lists additional source packages that were rebuilt for
compatibility with or to take advantage of this update:

Debian 5.0 (lenny)
user-mode-linux                         2.6.26-1um-2+26lenny3

We recommend that you upgrade your linux-2.6 and user-mode-linux packages.";
tag_summary = "The remote host is missing an update to linux-2.6
announced via advisory DSA 2264-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202264-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.69970");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_cve_id("CVE-2010-2524", "CVE-2010-3875", "CVE-2010-4075", "CVE-2010-4655", "CVE-2011-0695", "CVE-2011-0710", "CVE-2011-0711", "CVE-2011-0726", "CVE-2011-1010", "CVE-2011-1012", "CVE-2011-1017", "CVE-2011-1078", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1090", "CVE-2011-1093", "CVE-2011-1160", "CVE-2011-1163", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-1173", "CVE-2011-1180", "CVE-2011-1182", "CVE-2011-1477", "CVE-2011-1493", "CVE-2011-1577", "CVE-2011-1593", "CVE-2011-1598", "CVE-2011-1745", "CVE-2011-1746", "CVE-2011-1748", "CVE-2011-1759", "CVE-2011-1767", "CVE-2011-1768", "CVE-2011-1776", "CVE-2011-2022", "CVE-2011-2182");
 script_name("Debian Security Advisory DSA 2264-1 (linux-2.6)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"linux-doc-2.6.26", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-486", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-4kc-malta", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-5kc-malta", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-686", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-686-bigmem", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-alpha", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-amd64", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-arm", ver:"2.6.26-26lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-armel", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-hppa", ver:"2.6.26-26lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-i386", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-ia64", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-mips", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-mipsel", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-powerpc", ver:"2.6.26-26lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-s390", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-all-sparc", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-alpha-generic", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-alpha-legacy", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-alpha-smp", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-amd64", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-common", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-common-openvz", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-common-vserver", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-common-xen", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-footbridge", ver:"2.6.26-26lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-iop32x", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-itanium", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-ixp4xx", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-mckinley", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-openvz-686", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-openvz-amd64", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-orion5x", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-parisc", ver:"2.6.26-26lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-parisc-smp", ver:"2.6.26-26lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-parisc64", ver:"2.6.26-26lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-parisc64-smp", ver:"2.6.26-26lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-powerpc", ver:"2.6.26-26lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-powerpc-smp", ver:"2.6.26-26lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-powerpc64", ver:"2.6.26-26lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-r4k-ip22", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-r5k-cobalt", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-r5k-ip32", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-s390", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-s390x", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-sb1-bcm91250a", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-sb1a-bcm91480b", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-sparc64", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-sparc64-smp", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-versatile", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-686", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-686-bigmem", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-amd64", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-itanium", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-mckinley", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-powerpc", ver:"2.6.26-26lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-powerpc64", ver:"2.6.26-26lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-s390x", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-vserver-sparc64", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-xen-686", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-2.6.26-2-xen-amd64", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-486", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-4kc-malta", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-5kc-malta", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-686", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-686-bigmem", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-alpha-generic", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-alpha-legacy", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-alpha-smp", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-amd64", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-footbridge", ver:"2.6.26-26lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-iop32x", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-itanium", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-ixp4xx", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-mckinley", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-openvz-686", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-openvz-amd64", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-orion5x", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-parisc", ver:"2.6.26-26lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-parisc-smp", ver:"2.6.26-26lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-parisc64", ver:"2.6.26-26lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-parisc64-smp", ver:"2.6.26-26lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-powerpc", ver:"2.6.26-26lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-powerpc-smp", ver:"2.6.26-26lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-powerpc64", ver:"2.6.26-26lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-r4k-ip22", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-r5k-cobalt", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-r5k-ip32", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-s390", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-s390-tape", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-s390x", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-sb1-bcm91250a", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-sb1a-bcm91480b", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-sparc64", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-sparc64-smp", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-versatile", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-686", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-686-bigmem", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-amd64", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-itanium", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-mckinley", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-powerpc", ver:"2.6.26-26lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-powerpc64", ver:"2.6.26-26lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-s390x", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-vserver-sparc64", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-xen-686", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-2.6.26-2-xen-amd64", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-manual-2.6.26", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-modules-2.6.26-2-xen-686", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-modules-2.6.26-2-xen-amd64", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-patch-debian-2.6.26", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-source-2.6.26", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-support-2.6.26-2", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-tree-2.6.26", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-2.6.26-2-xen-686", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-2.6.26-2-xen-amd64", ver:"2.6.26-26lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
