###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_d0ebfab3f3_rsync_fc27.nasl 8714 2018-02-08 08:05:41Z santu $
#
# Fedora Update for rsync FEDORA-2018-d0ebfab3f3
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
  script_oid("1.3.6.1.4.1.25623.1.0.874093");
  script_version("$Revision: 8714 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-08 09:05:41 +0100 (Thu, 08 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-02-07 08:07:23 +0100 (Wed, 07 Feb 2018)");
  script_cve_id("CVE-2018-5764");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for rsync FEDORA-2018-d0ebfab3f3");
  script_tag(name: "summary", value: "Check the version of rsync");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Rsync uses a reliable algorithm to bring 
remote and host files into sync very quickly. Rsync is fast because it just sends 
the differences in the files over the network instead of sending the complete
files. Rsync is often used as a very powerful mirroring process or just as a more 
capable replacement for the rcp command. A technical report which describes the 
rsync algorithm is included in this package.
");
  script_tag(name: "affected", value: "rsync on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-d0ebfab3f3");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/IGFYN7FHWTIJWFVEE2IJDNOWRDHY3H7D");
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

  if ((res = isrpmvuln(pkg:"rsync", rpm:"rsync~3.1.3~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
