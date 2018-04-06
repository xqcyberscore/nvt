# OpenVAS Vulnerability Test
# $Id: deb_3791.nasl 9356 2018-04-06 07:17:02Z cfischer $
# Auto-generated from advisory DSA 3791-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net
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
    script_oid("1.3.6.1.4.1.25623.1.0.703791");
    script_version("$Revision: 9356 $");
    script_cve_id("CVE-2016-6786", "CVE-2016-6787", "CVE-2016-8405", "CVE-2016-9191", "CVE-2017-2583", "CVE-2017-2584", "CVE-2017-2596", "CVE-2017-2618", "CVE-2017-5549", "CVE-2017-5551", "CVE-2017-5897", "CVE-2017-5970", "CVE-2017-6001", "CVE-2017-6074");
    script_name("Debian Security Advisory DSA 3791-1 (linux - security update)");
    script_tag(name: "last_modification", value: "$Date: 2018-04-06 09:17:02 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value: "2017-02-22 00:00:00 +0100 (Wed, 22 Feb 2017)");
    script_tag(name: "cvss_base", value: "10.0");
    script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C");
    script_tag(name: "solution_type", value: "VendorFix");
    script_tag(name: "qod_type", value: "package");

    script_xref(name: "URL", value: "http://www.debian.org/security/2017/dsa-3791.html");

    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: "linux on Debian Linux");
        script_tag(name: "insight",   value: "The Linux kernel is the core of the Linux operating system.");
    script_tag(name: "solution",  value: "For the stable distribution (jessie), these problems have been fixed in
version 3.16.39-1+deb8u1.

We recommend that you upgrade your linux packages.");
    script_tag(name: "summary",   value: "Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or have other
impacts.

CVE-2016-6786 / CVE-2016-6787It was discovered that the performance events subsystem does not
properly manage locks during certain migrations, allowing a local
attacker to escalate privileges. This can be mitigated by
disabling unprivileged use of performance events:
sysctl kernel.perf_event_paranoid=3CVE-2016-8405 
Peter Pi of Trend Micro discovered that the frame buffer video
subsystem does not properly check bounds while copying color maps to
userspace, causing a heap buffer out-of-bounds read, leading to
information disclosure.

CVE-2016-9191 
CAI Qian discovered that reference counting is not properly handled
within proc_sys_readdir in the sysctl implementation, allowing a
local denial of service (system hang) or possibly privilege
escalation.

CVE-2017-2583 
Xiaohan Zhang reported that KVM for amd64 does not correctly
emulate loading of a null stack selector. This can be used by a
user in a guest VM for denial of service (on an Intel CPU) or to
escalate privileges within the VM (on an AMD CPU).

CVE-2017-2584 
Dmitry Vyukov reported that KVM for x86 does not correctly emulate
memory access by the SGDT and SIDT instructions, which can result
in a use-after-free and information leak.

CVE-2017-2596 
Dmitry Vyukov reported that KVM leaks page references when
emulating a VMON for a nested hypervisor. This can be used by a
privileged user in a guest VM for denial of service or possibly
to gain privileges in the host.

CVE-2017-2618 
It was discovered that an off-by-one in the handling of SELinux
attributes in /proc/pid/attr could result in local denial of
service.

CVE-2017-5549 
It was discovered that the KLSI KL5KUSB105 serial USB device
driver could log the contents of uninitialised kernel memory,
resulting in an information leak.

CVE-2017-5551 
Jan Kara found that changing the POSIX ACL of a file on tmpfs never
cleared its set-group-ID flag, which should be done if the user
changing it is not a member of the group-owner. In some cases, this
would allow the user-owner of an executable to gain the privileges
of the group-owner.

CVE-2017-5897 
Andrey Konovalov discovered an out-of-bounds read flaw in the
ip6gre_err function in the IPv6 networking code.

CVE-2017-5970 
Andrey Konovalov discovered a denial-of-service flaw in the IPv4
networking code. This can be triggered by a local or remote
attacker if a local UDP or raw socket has the IP_RETOPTS option
enabled.

CVE-2017-6001Di Shen discovered a race condition between concurrent calls to
the performance events subsystem, allowing a local attacker to
escalate privileges. This flaw exists because of an incomplete fix
of CVE-2016-6786.
This can be mitigated by disabling unprivileged use of performance
events: sysctl kernel.perf_event_paranoid=3CVE-2017-6074Andrey Konovalov discovered a use-after-free vulnerability in the
DCCP networking code, which could result in denial of service or
local privilege escalation. On systems that do not already have
the dccp module loaded, this can be mitigated by disabling it:
echo>> /etc/modprobe.d/disable-dccp.conf install dccp false");
    script_tag(name: "vuldetect", value: "This check tests the installed software version using the apt package manager.");

    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"linux-compiler-gcc-4.8-arm", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-compiler-gcc-4.8-s390", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-compiler-gcc-4.8-x86", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-doc-3.16", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-4kc-malta", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-586", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-5kc-malta", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-686-pae", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-amd64", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-arm64", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-armel", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-armhf", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-i386", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-mips", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-mipsel", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-powerpc", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-ppc64el", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-s390x", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-amd64", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-arm64", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-armmp", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-armmp-lpae", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-common", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-ixp4xx", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-kirkwood", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-loongson-2e", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-loongson-2f", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-loongson-3", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-octeon", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-orion5x", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-powerpc", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-powerpc-smp", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-powerpc64", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-powerpc64le", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-r4k-ip22", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-r5k-ip32", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-s390x", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-sb1-bcm91250a", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-versatile", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-4kc-malta", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-5kc-malta", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-mips", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-mipsel", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-common", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-loongson-2f", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-octeon", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-r4k-ip22", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-r5k-cobalt", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-r5k-ip32", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-sb1-bcm91250a", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-sb1a-bcm91480b", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-4-4kc-malta", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-4-586", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-4-5kc-malta", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-4-686-pae", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-4-686-pae-dbg", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-4-amd64", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-4-amd64-dbg", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-4-arm64", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-4-arm64-dbg", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-4-armmp", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-4-armmp-lpae", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-4-ixp4xx", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-4-kirkwood", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-4-loongson-2e", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-4-loongson-2f", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-4-loongson-3", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-4-octeon", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-4-orion5x", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-4-powerpc", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-4-powerpc-smp", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-4-powerpc64", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-4-powerpc64le", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-4-r4k-ip22", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-4-r5k-ip32", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-4-s390x", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-4-s390x-dbg", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-4-sb1-bcm91250a", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.16.0-4-versatile", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-4kc-malta", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-5kc-malta", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-loongson-2f", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-octeon", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-r4k-ip22", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-r5k-cobalt", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-r5k-ip32", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-sb1-bcm91250a", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-image-3.2.0-4-sb1a-bcm91480b", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-libc-dev", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-manual-3.16", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-source-3.16", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"linux-support-3.16.0-4", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-linux-system-3.16.0-4-amd64", ver:"3.16.39-1+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
