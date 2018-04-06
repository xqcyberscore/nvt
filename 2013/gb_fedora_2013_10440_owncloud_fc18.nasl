###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for owncloud FEDORA-2013-10440
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

tag_solution = "Please Install the Updated Packages.";
tag_insight = "ownCloud gives you universal access to your files through a web interface or
  WebDAV. It also provides a platform to easily view &amp; sync your contacts,
  calendars and bookmarks across all your devices and enables basic editing right
  on the web. ownCloud is extendable via a simple but powerful API for
  applications and plugins.";
tag_affected = "owncloud on Fedora 18";


if(description)
{
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_oid("1.3.6.1.4.1.25623.1.0.866022");
  script_version("$Revision: 9353 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-06-24 14:50:29 +0530 (Mon, 24 Jun 2013)");
  script_cve_id("CVE-2013-2149", "CVE-2013-2039", "CVE-2013-2040", "CVE-2013-2042",
                                                 "CVE-2013-2043", "CVE-2013-2046");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Fedora Update for owncloud FEDORA-2013-10440");

  script_xref(name: "FEDORA", value: "2013-10440");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2013-June/109723.html");
  script_tag(name: "summary" , value: "Check for the Version of owncloud");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
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

  if ((res = isrpmvuln(pkg:"owncloud", rpm:"owncloud~4.5.12~1.fc18", rls:"FC18")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
