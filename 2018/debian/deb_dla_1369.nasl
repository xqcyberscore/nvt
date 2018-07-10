###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1369.nasl 10474 2018-07-10 08:12:26Z cfischer $
#
# Auto-generated from advisory DLA 1369-1 using nvtgen 1.0
# Script version: 1.0
#
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
  script_oid("1.3.6.1.4.1.25623.1.0.891369");
  script_version("$Revision: 10474 $");
  script_cve_id("CVE-2017-0861", "CVE-2017-13166", "CVE-2017-16526", "CVE-2017-16911", "CVE-2017-16912",
                "CVE-2017-16913", "CVE-2017-16914", "CVE-2017-18017", "CVE-2017-18203", "CVE-2017-18216",
                "CVE-2017-5715", "CVE-2017-5753", "CVE-2018-1000004", "CVE-2018-1000199", "CVE-2018-1068",
                "CVE-2018-1092", "CVE-2018-5332", "CVE-2018-5333", "CVE-2018-5750", "CVE-2018-5803",
                "CVE-2018-6927", "CVE-2018-7492", "CVE-2018-7566", "CVE-2018-7740", "CVE-2018-7757",
                "CVE-2018-7995", "CVE-2018-8781", "CVE-2018-8822");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1369-1] linux security update)");
  script_tag(name:"last_modification", value:"$Date: 2018-07-10 10:12:26 +0200 (Tue, 10 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-05-04 00:00:00 +0200 (Fri, 04 May 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/05/msg00000.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7\.[0-9]+");
  script_tag(name:"affected", value:"linux on Debian Linux");
  script_tag(name:"insight", value:"The Linux kernel is the core of the Linux operating system.");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
3.2.101-1. This version also includes bug fixes from upstream versions
up to and including 3.2.101. It also fixes a regression in the
procfs hidepid option in the previous version (Debian bug #887106).

We recommend that you upgrade your linux packages.");
  script_tag(name:"summary",  value:"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2017-0861

Robb Glasser reported a potential use-after-free in the ALSA (sound)
PCM core. We believe this was not possible in practice.

CVE-2017-5715

Multiple researchers have discovered a vulnerability in various
processors supporting speculative execution, enabling an attacker
controlling an unprivileged process to read memory from arbitrary
addresses, including from the kernel and all other processes
running on the system.

This specific attack has been named Spectre variant 2 (branch
target injection) and is mitigated for the x86 architecture (amd64
and i386) by using the 'retpoline' compiler feature which allows
indirect branches to be isolated from speculative execution.

CVE-2017-13166

A bug in the 32-bit compatibility layer of the v4l2 ioctl handling
code has been found. Memory protections ensuring user-provided
buffers always point to userland memory were disabled, allowing
destination addresses to be in kernel space. On a 64-bit kernel
(amd64 flavour) a local user with access to a suitable video
device can exploit this to overwrite kernel memory, leading to
privilege escalation.

CVE-2017-16526

Andrey Konovalov reported that the UWB subsystem may dereference
an invalid pointer in an error case. A local user might be able
to use this for denial of service.

CVE-2017-16911

Secunia Research reported that the USB/IP vhci_hcd driver exposed
kernel heap addresses to local users. This information could aid the
exploitation of other vulnerabilities.

CVE-2017-16912

Secunia Research reported that the USB/IP stub driver failed to
perform a range check on a received packet header field, leading
to an out-of-bounds read. A remote user able to connect to the
USB/IP server could use this for denial of service.

CVE-2017-16913

Secunia Research reported that the USB/IP stub driver failed to
perform a range check on a received packet header field, leading
to excessive memory allocation. A remote user able to connect to
the USB/IP server could use this for denial of service.

CVE-2017-16914

Secunia Research reported that the USB/IP stub driver failed to
check for an invalid combination of fields in a received packet,
leading to a null pointer dereference. A remote user able to
connect to the USB/IP server could use this for denial of service.

CVE-2017-18017

Denys Fedoryshchenko reported that the netfilter xt_TCPMSS module
failed to validate TCP header lengths, potentially leading to a
use-after-free. If this module is loaded, it could be used by a
remote attacker for denial of service or possibly for code
execution.

CVE-2017-18203

Hou Tao reported that there was a race condition in creation and
deletion of device-mapper (DM) devices. A local user could
potentially use this for denial of service.

CVE-2017-18216

Alex Chen reported that the OCFS2 filesystem failed to hold a
necessary lock during nodemanager sysfs file operations,
potentially leading to a null pointer dereference. A local user
could use this for denial of service.

CVE-2018-1068

The syzkaller tool found that the 32-bit compatibility layer of
ebtables did not sufficiently validate offset values. On a 64-bit
kernel (amd64 flavour), a local user with the CAP_NET_ADMIN
capability could use this to overwrite kernel memory, possibly
leading to privilege escalation.

CVE-2018-1092

Wen Xu reported that a crafted ext4 filesystem image would
trigger a null dereference when mounted. A local user able
to mount arbitrary filesystems could use this for denial of
service.

CVE-2018-5332

Mohamed Ghannam reported that the RDS protocol did not
sufficiently validate RDMA requests, leading to an out-of-bounds
write. A local attacker on a system with the rds module loaded
could use this for denial of service or possibly for privilege
escalation.

CVE-2018-5333

Mohamed Ghannam reported that the RDS protocol did not properly
handle an error case, leading to a null pointer dereference. A
local attacker on a system with the rds module loaded could
possibly use this for denial of service.

CVE-2018-5750

Wang Qize reported that the ACPI sbshc driver logged a kernel heap
address. This information could aid the exploitation of other
vulnerabilities.

CVE-2018-5803

Alexey Kodanev reported that the SCTP protocol did not range-check
the length of chunks to be created. A local or remote user could
use this to cause a denial of service.

CVE-2018-6927

Li Jinyue reported that the FUTEX_REQUEUE operation on futexes did
not check for negative parameter values, which might lead to a
denial of service or other security impact.

CVE-2018-7492

The syzkaller tool found that the RDS protocol was lacking a null
pointer check. A local attacker on a system with the rds module
loaded could use this for denial of service.

CVE-2018-7566

Fan LongFei reported a race condition in the ALSA (sound)
sequencer core, between write and ioctl operations. This could
lead to an out-of-bounds access or use-after-free. A local user
with access to a sequencer device could use this for denial of
service or possibly for privilege escalation.

CVE-2018-7740

Nic Losby reported that the hugetlbfs filesystem's mmap operation
did not properly range-check the file offset. A local user with
access to files on a hugetlbfs filesystem could use this to cause
a denial of service.

CVE-2018-7757

Jason Yan reported a memory leak in the SAS (Serial-Attached
SCSI) subsystem. A local user on a system with SAS devices
could use this to cause a denial of service.

CVE-2018-7995

Seunghun Han reported a race condition in the x86 MCE
(Machine Check Exception) driver. This is unlikely to have
any security impact.

CVE-2018-8781

Eyal Itkin reported that the udl (DisplayLink) driver's mmap
operation did not properly range-check the file offset. A local
user with access to a udl framebuffer device could exploit this to
overwrite kernel memory, leading to privilege escalation.

CVE-2018-8822

Dr Silvio Cesare of InfoSect reported that the ncpfs client
implementation did not validate reply lengths from the server. An
ncpfs server could use this to cause a denial of service or
remote code execution in the client.

CVE-2018-1000004

Luo Quan reported a race condition in the ALSA (sound) sequencer
core, between multiple ioctl operations. This could lead to a
deadlock or use-after-free. A local user with access to a
sequencer device could use this for denial of service or possibly
for privilege escalation.

CVE-2018-1000199

Andy Lutomirski discovered that the ptrace subsystem did not
sufficiently validate hardware breakpoint settings. Local users
can use this to cause a denial of service, or possibly for
privilege escalation, on x86 (amd64 and i386) and possibly other
architectures.

Additionally, some mitigations for CVE-2017-5753 are included in this
release:

CVE-2017-5753

Multiple researchers have discovered a vulnerability in various
processors supporting speculative execution, enabling an attacker
controlling an unprivileged process to read memory from arbitrary
addresses, including from the kernel and all other processes
running on the system.

This specific attack has been named Spectre variant 1
(bounds-check bypass) and is mitigated by identifying vulnerable
code sections (array bounds checking followed by array access) and
replacing the array access with the speculation-safe
array_index_nospec() function.

More use sites will be added over time.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"linux-doc-3.2", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-486", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-686-pae", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-amd64", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-armel", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-armhf", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-i386", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-amd64", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-common", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-common-rt", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-iop32x", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-ixp4xx", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-kirkwood", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-mv78xx0", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-mx5", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-omap", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-orion5x", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-rt-686-pae", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-rt-amd64", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-versatile", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-vexpress", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-486", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-686-pae", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-all", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-all-amd64", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-all-armel", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-all-armhf", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-all-i386", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-amd64", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-common", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-common-rt", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-iop32x", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-ixp4xx", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-kirkwood", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-mv78xx0", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-mx5", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-omap", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-orion5x", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-rt-686-pae", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-rt-amd64", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-versatile", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-5-vexpress", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-486", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-686-pae", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-all", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-all-amd64", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-all-armel", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-all-armhf", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-all-i386", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-amd64", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-common", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-common-rt", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-iop32x", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-ixp4xx", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-kirkwood", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-mv78xx0", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-mx5", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-omap", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-orion5x", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-rt-686-pae", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-rt-amd64", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-versatile", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-6-vexpress", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-486", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-686-pae", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-686-pae-dbg", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-amd64", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-amd64-dbg", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-iop32x", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-ixp4xx", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-kirkwood", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-mv78xx0", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-mx5", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-omap", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-orion5x", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-686-pae", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-686-pae-dbg", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-amd64", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-amd64-dbg", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-versatile", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-vexpress", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-486", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-686-pae", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-686-pae-dbg", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-amd64", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-amd64-dbg", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-iop32x", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-ixp4xx", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-kirkwood", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-mv78xx0", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-mx5", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-omap", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-orion5x", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-rt-686-pae", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-rt-686-pae-dbg", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-rt-amd64", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-rt-amd64-dbg", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-versatile", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-5-vexpress", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-486", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-686-pae", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-686-pae-dbg", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-amd64", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-amd64-dbg", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-iop32x", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-ixp4xx", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-kirkwood", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-mv78xx0", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-mx5", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-omap", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-orion5x", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-rt-686-pae", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-rt-686-pae-dbg", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-rt-amd64", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-rt-amd64-dbg", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-versatile", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-6-vexpress", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-manual-3.2", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-source-3.2", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-support-3.2.0-4", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-support-3.2.0-5", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-support-3.2.0-6", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-4-686-pae", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-4-amd64", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-5-686-pae", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-5-amd64", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-6-686-pae", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-6-amd64", ver:"3.2.101-1", rls_regex:"DEB7\.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
