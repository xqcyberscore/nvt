###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for proftpd FEDORA-2013-0483
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
tag_insight = "ProFTPD is an enhanced FTP server with a focus toward simplicity, security,
  and ease of configuration. It features a very Apache-like configuration
  syntax, and a highly customizable server infrastructure, including support for
  multiple 'virtual' FTP servers, anonymous FTP, and permission-based directory
  visibility.

  This package defaults to the standalone behavior of ProFTPD, but all the
  needed scripts to have it run by xinetd instead are included.";


tag_affected = "proftpd on Fedora 17";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2013-January/097832.html");
  script_id(865258);
  script_version("$Revision: 8672 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-05 17:39:18 +0100 (Mon, 05 Feb 2018) $");
  script_tag(name:"creation_date", value:"2013-01-31 09:24:31 +0530 (Thu, 31 Jan 2013)");
  script_cve_id("CVE-2012-6095");
  script_tag(name:"cvss_base", value:"1.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:P/A:N");
  script_xref(name: "FEDORA", value: "2013-0483");
  script_name("Fedora Update for proftpd FEDORA-2013-0483");

  script_tag(name: "summary" , value: "Check for the Version of proftpd");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
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

if(release == "FC17")
{

  if ((res = isrpmvuln(pkg:"proftpd", rpm:"proftpd~1.3.4b~5.fc17", rls:"FC17")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
