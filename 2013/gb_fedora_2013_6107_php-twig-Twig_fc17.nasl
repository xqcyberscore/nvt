###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for php-twig-Twig FEDORA-2013-6107
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
tag_insight = "The flexible, fast, and secure template engine for PHP.

  * Fast: Twig compiles templates down to plain optimized PHP code. The
    overhead compared to regular PHP code was reduced to the very minimum.

  * Secure: Twig has a sandbox mode to evaluate untrusted template code. This
    allows Twig to be used as a template language for applications where users
    may modify the template design.

  * Flexible: Twig is powered by a flexible lexer and parser. This allows the
    developer to define its own custom tags and filters, and create its own
    DSL.

  Optional dependency: Xdebug (php-pecl-xdebug)";


tag_affected = "php-twig-Twig on Fedora 17";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.865595");
  script_version("$Revision: 9353 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-05-03 09:55:06 +0530 (Fri, 03 May 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Update for php-twig-Twig FEDORA-2013-6107");

  script_xref(name: "FEDORA", value: "2013-6107");
  script_xref(name: "URL" , value: "http://lists.fedoraproject.org/pipermail/package-announce/2013-April/103923.html");
  script_tag(name: "summary" , value: "Check for the Version of php-twig-Twig");
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

  if ((res = isrpmvuln(pkg:"php-twig-Twig", rpm:"php-twig-Twig~1.12.3~1.fc17", rls:"FC17")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
