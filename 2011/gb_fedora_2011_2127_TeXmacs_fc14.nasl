###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for TeXmacs FEDORA-2011-2127
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
tag_insight = "GNU TeXmacs is a free scientific text editor, which was both inspired
  by TeX and GNU Emacs. The editor allows you to write structured
  documents via a WYSIWYG (what-you-see-is-what-you-get) and user
  friendly interface.  New styles may be created by the user. The
  program implements high-quality typesetting algorithms and TeX fonts,
  which help you to produce professionally looking documents.

  The high typesetting quality still goes through for automatically
  generated formulas, which makes TeXmacs suitable as an interface for
  computer algebra systems. TeXmacs also supports the Guile/Scheme
  extension language, so that you may customize the interface and write
  your own extensions to the editor.
  
  In the future, TeXmacs is planned to evolve towards a complete
  scientific office suite, with spreadsheet capacities, a technical
  drawing editor and a presentation mode.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "TeXmacs on Fedora 14";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2011-March/055054.html");
  script_oid("1.3.6.1.4.1.25623.1.0.862885");
  script_version("$Revision: 9371 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:55:06 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-03-08 14:34:13 +0100 (Tue, 08 Mar 2011)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2011-2127");
  script_cve_id("CVE-2010-3394");
  script_name("Fedora Update for TeXmacs FEDORA-2011-2127");

  script_tag(name:"summary", value:"Check for the Version of TeXmacs");
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

  if ((res = isrpmvuln(pkg:"TeXmacs", rpm:"TeXmacs~1.0.7.9~2.fc14", rls:"FC14")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
