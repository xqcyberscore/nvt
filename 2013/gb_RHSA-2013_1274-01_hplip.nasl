###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for hplip RHSA-2013:1274-01
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871040");
  script_version("$Revision: 9353 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-09-24 11:44:30 +0530 (Tue, 24 Sep 2013)");
  script_cve_id("CVE-2013-4325");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("RedHat Update for hplip RHSA-2013:1274-01");

  tag_insight = "The hplip packages contain the Hewlett-Packard Linux Imaging and Printing
Project (HPLIP), which provides drivers for Hewlett-Packard printers and
multi-function peripherals.

HPLIP communicated with PolicyKit for authorization via a D-Bus API that is
vulnerable to a race condition. This could lead to intended PolicyKit
authorizations being bypassed. This update modifies HPLIP to communicate
with PolicyKit via a different API that is not vulnerable to the race
condition. (CVE-2013-4325)

All users of hplip are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue.
";

  tag_affected = "hplip on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "RHSA", value: "2013:1274-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2013-September/msg00033.html");
  script_tag(name: "summary" , value: "Check for the Version of hplip");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
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

  if ((res = isrpmvuln(pkg:"hpijs", rpm:"hpijs~3.12.4~4.el6_4.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hplip", rpm:"hplip~3.12.4~4.el6_4.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hplip-common", rpm:"hplip-common~3.12.4~4.el6_4.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hplip-debuginfo", rpm:"hplip-debuginfo~3.12.4~4.el6_4.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hplip-gui", rpm:"hplip-gui~3.12.4~4.el6_4.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hplip-libs", rpm:"hplip-libs~3.12.4~4.el6_4.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsane-hpaio", rpm:"libsane-hpaio~3.12.4~4.el6_4.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
