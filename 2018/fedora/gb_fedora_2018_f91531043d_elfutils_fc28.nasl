###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_f91531043d_elfutils_fc28.nasl 10204 2018-06-15 02:21:57Z ckuersteiner $
#
# Fedora Update for elfutils FEDORA-2018-f91531043d
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
  script_oid("1.3.6.1.4.1.25623.1.0.874661");
  script_version("$Revision: 10204 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-15 04:21:57 +0200 (Fri, 15 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-09 06:01:36 +0200 (Sat, 09 Jun 2018)");
  script_cve_id("CVE-2018-8769");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for elfutils FEDORA-2018-f91531043d");
  script_tag(name:"summary", value:"Check the version of elfutils");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"Elfutils is a collection of utilities, 
including stack (to show backtraces), nm (for listing symbols from object files), 
size (for listing the section sizes of an object or archive file), 
strip (for discarding symbols), readelf (to see the raw ELF file structures), 
elflint (to check for well-formed ELF files) and elfcompress (to compress or 
decompress ELF sections).
");
  script_tag(name:"affected", value:"elfutils on Fedora 28");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-f91531043d");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/EP43TAFBHQYHEVFEGFYOXUFAUCL3CQVB");
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

if(release == "FC28")
{

  if ((res = isrpmvuln(pkg:"elfutils", rpm:"elfutils~0.171~1.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
