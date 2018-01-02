###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for libguestfs RHSA-2011:0586-01
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
tag_insight = "libguestfs is a library for accessing and modifying guest disk images.

  libguestfs relied on the format auto-detection in QEMU rather than
  allowing the guest image file format to be specified. A privileged guest
  user could potentially use this flaw to read arbitrary files on the host
  that were accessible to a user on that host who was running a program that
  utilized the libguestfs library. (CVE-2010-3851)

  This erratum upgrades libguestfs to upstream version 1.7.17, which includes
  a number of bug fixes and one enhancement. Documentation for these bug
  fixes and this enhancement is provided in the Technical Notes document,
  linked to in the References section.

  All libguestfs users are advised to upgrade to these updated packages,
  which correct this issue, and fix the bugs and add the enhancement noted
  in the Technical Notes.";

tag_affected = "libguestfs on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2011-May/msg00020.html");
  script_id(870656);
  script_version("$Revision: 8249 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-27 07:29:56 +0100 (Wed, 27 Dec 2017) $");
  script_tag(name:"creation_date", value:"2012-06-06 10:44:07 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2010-3851");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_xref(name: "RHSA", value: "2011:0586-01");
  script_name("RedHat Update for libguestfs RHSA-2011:0586-01");

  script_tag(name: "summary" , value: "Check for the Version of libguestfs");
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

  if ((res = isrpmvuln(pkg:"guestfish", rpm:"guestfish~1.7.17~17.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libguestfs", rpm:"libguestfs~1.7.17~17.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libguestfs-debuginfo", rpm:"libguestfs-debuginfo~1.7.17~17.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libguestfs-java", rpm:"libguestfs-java~1.7.17~17.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libguestfs-mount", rpm:"libguestfs-mount~1.7.17~17.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libguestfs-tools", rpm:"libguestfs-tools~1.7.17~17.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libguestfs-tools-c", rpm:"libguestfs-tools-c~1.7.17~17.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-Sys-Guestfs", rpm:"perl-Sys-Guestfs~1.7.17~17.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
