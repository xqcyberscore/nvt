###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for perl FEDORA-2011-4610
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Perl is a high-level programming language with roots in C, sed, awk
  and shell scripting.  Perl is good at handling processes and files,
  and is especially good at handling text.  Perl's hallmarks are
  practicality and efficiency.  While it is used to do a lot of
  different things, Perl's most common applications are system
  administration utilities and web programming.  A large proportion of
  the CGI scripts on the web are written in Perl.  You need the perl
  package installed on your system so that your system can handle Perl
  scripts.

  Install this package if you want to program in Perl or enable your
  system to handle Perl scripts.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "perl on Fedora 14";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2011-April/057891.html");
  script_oid("1.3.6.1.4.1.25623.1.0.862981");
  script_cve_id("CVE-2011-1487");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_version("$Revision: 9371 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:55:06 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-04-19 07:58:39 +0200 (Tue, 19 Apr 2011)");
  script_xref(name: "FEDORA", value: "2011-4610");
  script_name("Fedora Update for perl FEDORA-2011-4610");

  script_tag(name:"summary", value:"Check for the Version of perl");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
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

if(release == "FC14")
{

  if ((res = isrpmvuln(pkg:"perl", rpm:"perl~5.12.3~143.fc14", rls:"FC14")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
