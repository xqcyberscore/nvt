###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_28447b6f2e_ghostscript_fc27.nasl 12193 2018-11-02 03:47:13Z ckuersteiner $
#
# Fedora Update for ghostscript FEDORA-2018-28447b6f2e
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.875044");
  script_version("$Revision: 12193 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-02 04:47:13 +0100 (Fri, 02 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-09-08 07:29:00 +0200 (Sat, 08 Sep 2018)");
  script_cve_id("CVE-2018-10194", "CVE-2018-15909", "CVE-2018-16541",
                "CVE-2018-16540", "CVE-2018-16539", "CVE-2018-15911", "CVE-2018-16542");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for ghostscript FEDORA-2018-28447b6f2e");
  script_tag(name:"summary", value:"Check the version of ghostscript");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");
  script_tag(name:"insight", value:"Ghostscript is a set of software that provides
  a PostScript interpreter, a set of C procedures (the Ghostscript library, which
  implements the graphics capabilities in the PostScript language) and an interpreter
  for Portable Document Format (PDF) files. Ghostscript translates PostScript code
  into many common, bitmapped formats, like those understood by your printer or screen.
  Ghostscript is normally used to display PostScript files and to print PostScript
  files to non-PostScript printers.

If you need to display PostScript files or print them to
non-PostScript printers, you should install ghostscript. If you
install ghostscript, you also need to install the urw-base35-fonts
package.
");
  script_tag(name:"affected", value:"ghostscript on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-28447b6f2e");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XCUEPMWEHXY26URUPAWY7TL5DUC4SSCT");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC27")
{

  if ((res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~9.22~5.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
