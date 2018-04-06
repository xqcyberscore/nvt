# OpenVAS Vulnerability Test
# $Id: deb_2582_1.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2582-1 using nvtgen 1.0
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

tag_affected  = "xen on Debian Linux";
tag_insight   = "Xen is a hypervisor providing services that allow multiple computer operating
systems to execute on the same computer hardware concurrently.";
tag_solution  = "For the stable distribution (squeeze), these problems have been fixed in
version 4.0.1-5.5.

For the testing distribution (wheezy), these problems have been fixed in
version 4.1.3-6.

For the unstable distribution (sid), these problems have been fixed in
version 4.1.3-6.

We recommend that you upgrade your xen packages.";
tag_summary   = "Multiple denial of service vulnerabilities have been discovered
in the Xen Hypervisor. One of the issue
(CVE-2012-5513)
could even lead to privilege escalation from guest to host.

Some of the recently published Xen Security Advisories
(XSA 25 and 28)
are not fixed by this update and should be fixed in a future release.

CVE-2011-3131 (XSA 5):
DoS using I/OMMU faults from PCI-passthrough guest
A VM that controls a PCI[E] device directly can cause it to issue DMA
requests to invalid addresses. Although these requests are denied by the
I/OMMU, the hypervisor needs to handle the interrupt and clear the error from
the I/OMMU, and this can be used to live-lock a CPU and potentially hang the
host.

CVE-2012-4535 (XSA 20):
Timer overflow DoS vulnerability
A guest which sets a VCPU with an inappropriate deadline can cause an
infinite loop in Xen, blocking the affected physical CPU indefinitely.

CVE-2012-4537 (XSA 22):
Memory mapping failure DoS vulnerability
When set_p2m_entry fails, Xen's internal data structures (the p2m and m2p
tables) can get out of sync. This failure can be triggered by unusual guest
behaviour exhausting the memory reserved for the p2m table. If it happens,
subsequent guest-invoked memory operations can cause Xen to fail an assertion
and crash.

CVE-2012-4538 (XSA 23):
Unhooking empty PAE entries DoS vulnerability
The HVMOP_pagetable_dying hypercall does not correctly check the
caller's pagetable state, leading to a hypervisor crash.

CVE-2012-4539 (XSA 24):
Grant table hypercall infinite loop DoS vulnerability
Due to inappropriate duplicate use of the same loop control variable,
passing bad arguments to GNTTABOP_get_status_frames can cause an
infinite loop in the compat hypercall handler.

CVE-2012-5510 (XSA 26):
Grant table version switch list corruption vulnerability
Downgrading the grant table version of a guest involves freeing its status
pages. This freeing was incomplete - the page(s) are freed back to the
allocator, but not removed from the domain's tracking list. This would cause
list corruption, eventually leading to a hypervisor crash.

CVE-2012-5513 (XSA 29):
XENMEM_exchange may overwrite hypervisor memory
The handler for XENMEM_exchange accesses guest memory without range checking
the guest provided addresses, thus allowing these accesses to include the
hypervisor reserved range.

A malicious guest administrator can cause Xen to crash. If the out of address
space bounds access does not lead to a crash, a carefully crafted privilege
escalation cannot be excluded, even though the guest doesn't itself control
the values written.

CVE-2012-5514 (XSA 30):
Broken error handling in guest_physmap_mark_populate_on_demand()
guest_physmap_mark_populate_on_demand(), before carrying out its actual
operation, checks that the subject GFNs are not in use. If that check fails,
the code prints a message and bypasses the gfn_unlock() matching the
gfn_lock() carried out before entering the loop.
A malicious guest administrator can then use it to cause Xen to hang.

CVE-2012-5515 (XSA 31):
Several memory hypercall operations allow invalid extent order values
Allowing arbitrary extent_order input values for XENMEM_decrease_reservation,
XENMEM_populate_physmap, and XENMEM_exchange can cause arbitrarily long time
being spent in loops without allowing vital other code to get a chance to
execute. This may also cause inconsistent state resulting at the completion
of these hypercalls.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892582");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2012-5513", "CVE-2012-4538", "CVE-2012-4535", "CVE-2011-3131", "CVE-2012-5515", "CVE-2012-4539", "CVE-2012-5514", "CVE-2012-5510", "CVE-2012-4537");
    script_name("Debian Security Advisory DSA 2582-1 (xen - several vulnerabilities)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name:"creation_date", value:"2013-09-18 11:53:02 +0200 (Wed, 18 Sep 2013)");
    script_tag(name: "cvss_base", value:"6.9");
    script_tag(name: "cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

    script_xref(name: "URL", value: "http://www.debian.org/security/2012/dsa-2582.html");


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
if ((res = isdpkgvuln(pkg:"libxen-dev", ver:"4.0.1-5.5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxenstore3.0", ver:"4.0.1-5.5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-docs-4.0", ver:"4.0.1-5.5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-hypervisor-4.0-amd64", ver:"4.0.1-5.5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-hypervisor-4.0-i386", ver:"4.0.1-5.5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-utils-4.0", ver:"4.0.1-5.5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.0.1-5.5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxen-4.1", ver:"4.1.3-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxen-dev", ver:"4.1.3-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxen-ocaml", ver:"4.1.3-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxen-ocaml-dev", ver:"4.1.3-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxenstore3.0", ver:"4.1.3-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-docs-4.1", ver:"4.1.3-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-hypervisor-4.1-amd64", ver:"4.1.3-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-hypervisor-4.1-i386", ver:"4.1.3-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-system-amd64", ver:"4.1.3-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-system-i386", ver:"4.1.3-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-utils-4.1", ver:"4.1.3-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xen-utils-common", ver:"4.1.3-6", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.1.3-6", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
