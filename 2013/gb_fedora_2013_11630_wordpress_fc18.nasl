###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for wordpress FEDORA-2013-11630
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

tag_affected = "wordpress on Fedora 18";
tag_insight = "Wordpress is an online publishing / weblog package that makes it very easy,
  almost trivial, to get information out to people on the web.";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_id(866044);
  script_version("$Revision: 2917 $");
  script_tag(name:"last_modification", value:"$Date: 2016-03-23 12:10:43 +0100 (Wed, 23 Mar 2016) $");
  script_tag(name:"creation_date", value:"2013-07-05 12:56:37 +0530 (Fri, 05 Jul 2013)");
  script_cve_id("CVE-2013-2173", "CVE-2013-2199", "CVE-2013-2200", "CVE-2013-2201",
                "CVE-2013-2202", "CVE-2013-2203", "CVE-2013-2204", "CVE-2013-0235",
                                 "CVE-2013-0236", "CVE-2013-0237", "CVE-2013-2205");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name("Fedora Update for wordpress FEDORA-2013-11630");

  script_xref(name: "FEDORA", value: "2013-11630");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2013-July/110564.html");
  script_summary("Check for the Version of wordpress");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:fedoraproject:fedora", "login/SSH/success", "ssh/login/release");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
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

if(release == "FC18")
{

  if ((res = isrpmvuln(pkg:"wordpress", rpm:"wordpress~3.5.2~1.fc18", rls:"FC18")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
