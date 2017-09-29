###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2017_2788-01_augeas.nasl 7318 2017-09-29 05:31:27Z asteins $
#
# RedHat Update for augeas RHSA-2017:2788-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811792");
  script_version("$Revision: 7318 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-29 07:31:27 +0200 (Fri, 29 Sep 2017) $");
  script_tag(name:"creation_date", value:"2017-09-24 09:58:59 +0200 (Sun, 24 Sep 2017)");
  script_cve_id("CVE-2017-7555");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for augeas RHSA-2017:2788-01");
  script_tag(name: "summary", value: "Check the version of augeas");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Augeas is a configuration editing tool. It
parses configuration files in their native formats and transforms them into a tree.
Configuration changes are made by manipulating this tree and saving it back into
native config files.

Security Fix(es):

* A vulnerability was discovered in augeas affecting the handling of
escaped strings. An attacker could send crafted strings that would cause
the application using augeas to copy past the end of a buffer, leading to a
crash or possible code execution. (CVE-2017-7555)

This issue was discovered by Han Han (Red Hat).
");
  script_tag(name: "affected", value: "augeas on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "RHSA", value: "2017:2788-01");
  script_xref(name: "URL" , value: "https://www.redhat.com/archives/rhsa-announce/2017-September/msg00049.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"augeas", rpm:"augeas~1.4.0~2.el7_4.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"augeas-debuginfo", rpm:"augeas-debuginfo~1.4.0~2.el7_4.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"augeas-libs", rpm:"augeas-libs~1.4.0~2.el7_4.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
