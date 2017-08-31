
 ###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for boomaga FEDORA-2017-5d0871e3fd
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
  script_oid("1.3.6.1.4.1.25623.1.0.872300");
  script_version("$Revision: 6634 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 09:32:24 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2017-01-25 05:51:17 +0100 (Wed, 25 Jan 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for boomaga FEDORA-2017-5d0871e3fd");
  script_tag(name: "summary", value: "Check the version of boomaga");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
  of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Boomaga (BOOklet MAnager) is a virtual printer for viewing a document
before printing it out using the physical printer.
The program is very simple to work with.
Running any program, click 'print' and select 'Boomaga' to see in
several
seconds (CUPS takes some time to respond) the Boomaga window open.
If you print out one more document,
it gets added to the previous one, and you can also print them out as one,
and you can also print them out as one.
Regardless of whether your printer supports duplex printing or not,
you would be able to easily print on both sides of the sheet.
If your printer does not support duplex printing,
point this out in the settings, and Booklet would ask you to turn
over the pages half way through printing your document.

The program can also help you get your documents prepared a bit
before printing. At this stage Boomaga makes it possible to:

 * Paste several documents together.
 * Print several pages on one sheet.
 * 1, 2, 4, 8 pages per sheet
 * Booklet. Folding the sheets in two, you&#39 ll get a book.
");
  script_tag(name: "affected", value: "boomaga on Fedora 24");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-5d0871e3fd");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RRW5X7MPDZYS4DWNSOJPFA72J2JWLI3J");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(release == "FC24")
{

  if ((res = isrpmvuln(pkg:"boomaga", rpm:"boomaga~0.8.0~6.git97f52c1.fc24", rls:"FC24")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
