###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for puppet openSUSE-SU-2013:1370-1 (puppet)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_id(850554);
  script_version("$Revision: 2925 $");
  script_tag(name:"last_modification", value:"$Date: 2016-03-23 12:31:37 +0100 (Wed, 23 Mar 2016) $");
  script_tag(name:"creation_date", value:"2013-12-10 13:21:28 +0530 (Tue, 10 Dec 2013)");
  script_cve_id("CVE-2013-3567");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("SuSE Update for puppet openSUSE-SU-2013:1370-1 (puppet)");

  tag_insight = "
  A potential remote code execution via YAML was fixed in
  puppet. (CVE-2013-3567)";

  tag_affected = "puppet on openSUSE 12.3";

  tag_solution = "Please Install the Updated Packages.";


  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name: "openSUSE-SU", value: "2013:1370_1");
  script_xref(name: "URL" , value: "http://lists.opensuse.org/opensuse-security-announce/2013-08/msg00019.html");
  script_summary("Check for the Version of puppet");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:novell:opensuse", "login/SSH/success", "ssh/login/release");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "openSUSE12.3")
{

  if ((res = isrpmvuln(pkg:"puppet", rpm:"puppet~3.0.2~2.9.1", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"puppet-server", rpm:"puppet-server~3.0.2~2.9.1", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
