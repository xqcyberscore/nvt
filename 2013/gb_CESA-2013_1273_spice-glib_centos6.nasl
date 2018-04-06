###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for spice-glib CESA-2013:1273 centos6 
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "The spice-gtk packages provide a GIMP Toolkit (GTK+) widget for SPICE
(Simple Protocol for Independent Computing Environments) clients. Both
Virtual Machine Manager and Virtual Machine Viewer can make use of this
widget to access virtual machines using the SPICE protocol.

spice-gtk communicated with PolicyKit for authorization via an API that is
vulnerable to a race condition. This could lead to intended PolicyKit
authorizations being bypassed. This update modifies spice-gtk to
communicate with PolicyKit via a different API that is not vulnerable to
the race condition. (CVE-2013-4324)

All users of spice-gtk are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue.";


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881797");
  script_version("$Revision: 9353 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-09-24 11:45:25 +0530 (Tue, 24 Sep 2013)");
  script_cve_id("CVE-2013-4324");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for spice-glib CESA-2013:1273 centos6 ");


  tag_affected = "spice-glib on CentOS 6";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "CESA", value: "2013:1273");
  script_xref(name: "URL" , value: "http://lists.centos.org/pipermail/centos-announce/2013-September/019950.html");
  script_tag(name: "summary" , value: "Check for the Version of spice-glib");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"spice-glib", rpm:"spice-glib~0.14~7.el6_4.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"spice-glib-devel", rpm:"spice-glib-devel~0.14~7.el6_4.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"spice-gtk", rpm:"spice-gtk~0.14~7.el6_4.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"spice-gtk-devel", rpm:"spice-gtk-devel~0.14~7.el6_4.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"spice-gtk-python", rpm:"spice-gtk-python~0.14~7.el6_4.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"spice-gtk-tools", rpm:"spice-gtk-tools~0.14~7.el6_4.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
