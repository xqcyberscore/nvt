###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for qemu-kvm RHSA-2012:1234-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

include("revisions-lib.inc");
tag_insight = "KVM (Kernel-based Virtual Machine) is a full virtualization solution for
  Linux on AMD64 and Intel 64 systems. qemu-kvm is the user-space
  component for running virtual machines using KVM.

  A flaw was found in the way QEMU handled VT100 terminal escape sequences
  when emulating certain character devices. A guest user with privileges to
  write to a character device that is emulated on the host using a virtual
  console back-end could use this flaw to crash the qemu-kvm process on the
  host or, possibly, escalate their privileges on the host. (CVE-2012-3515)

  This flaw did not affect the default use of KVM. Affected configurations
  were:

  * When guests were started from the command line (&quot;/usr/libexec/qemu-kvm&quot;)
  without the &quot;-nodefaults&quot; option, and also without specifying a
  serial or parallel device, or a virtio-console device, that specifically
  does not use a virtual console (vc) back-end. (Note that Red Hat does not
  support invoking &quot;qemu-kvm&quot; from the command line without
  '-nodefaults' on  Red Hat Enterprise Linux 6.)

  * Guests that were managed via libvirt, such as when using Virtual Machine
  Manager (virt-manager), but that have a serial or parallel device, or a
  virtio-console device, that uses a virtual console back-end. By default,
  guests managed via libvirt will not use a virtual console back-end
  for such devices.

  Red Hat would like to thank the Xen project for reporting this issue.
  All users of qemu-kvm should upgrade to these updated packages, which
  resolve this issue. After installing this update, shut down all running
  virtual machines. Once all virtual machines have shut down, start them
  again for this update to take effect.";

tag_affected = "qemu-kvm on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2012-September/msg00006.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870823");
  script_version("$Revision: 9352 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-09-07 11:25:36 +0530 (Fri, 07 Sep 2012)");
  script_cve_id("CVE-2012-3515");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2012:1234-01");
  script_name("RedHat Update for qemu-kvm RHSA-2012:1234-01");

  script_tag(name: "summary" , value: "Check for the Version of qemu-kvm");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~0.12.1.2~2.295.el6_3.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~0.12.1.2~2.295.el6_3.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~0.12.1.2~2.295.el6_3.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-debuginfo", rpm:"qemu-kvm-debuginfo~0.12.1.2~2.295.el6_3.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~0.12.1.2~2.295.el6_3.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
