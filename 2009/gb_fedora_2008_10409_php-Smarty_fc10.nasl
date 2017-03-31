###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for php-Smarty FEDORA-2008-10409
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_affected = "php-Smarty on Fedora 10";
tag_insight = "Although Smarty is known as a &quot;Template Engine&quot;, it would be more accurately
  described as a &quot;Template/Presentation Framework.&quot; That is, it provides the
  programmer and template designer with a wealth of tools to automate tasks
  commonly dealt with at the presentation layer of an application. I stress the
  word Framework because Smarty is not a simple tag-replacing template engine.
  Although it can be used for such a simple purpose, its focus is on quick and
  painless development and deployment of your application, while maintaining
  high-performance, scalability, security and future growth.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2008-November/msg00940.html");
  script_id(860875);
  script_version("$Revision: 3216 $");
  script_tag(name:"last_modification", value:"$Date: 2016-05-03 15:18:38 +0200 (Tue, 03 May 2016) $");
  script_tag(name:"creation_date", value:"2009-02-16 14:16:57 +0100 (Mon, 16 Feb 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "FEDORA", value: "2008-10409");
  script_cve_id("CVE-2008-4811");
  script_name( "Fedora Update for php-Smarty FEDORA-2008-10409");

  script_summary("Check for the Version of php-Smarty");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

if(release == "FC10")
{

  if ((res = isrpmvuln(pkg:"php-Smarty", rpm:"php-Smarty~2.6.20~2.fc10", rls:"FC10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}