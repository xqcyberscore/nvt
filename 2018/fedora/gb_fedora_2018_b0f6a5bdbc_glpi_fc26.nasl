###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_b0f6a5bdbc_glpi_fc26.nasl 9488 2018-04-16 05:42:12Z cfischer $
#
# Fedora Update for glpi FEDORA-2018-b0f6a5bdbc
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
  script_oid("1.3.6.1.4.1.25623.1.0.874294");
  script_version("$Revision: 9488 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-16 07:42:12 +0200 (Mon, 16 Apr 2018) $");
  script_tag(name:"creation_date", value:"2018-03-28 08:59:59 +0200 (Wed, 28 Mar 2018)");
  script_cve_id("CVE-2018-7563");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for glpi FEDORA-2018-b0f6a5bdbc");
  script_tag(name: "summary", value: "Check the version of glpi");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "GLPI is the Information Resource-Manager 
with an additional Administration-Interface. You can use it to build up a database 
with an inventory for your company (computer, software, printers...). It has 
enhanced functions to make the daily life for the administrators easier, like a 
job-tracking-system with mail-notification and methods to build a database with 
basic information about your network-topology.
");
  script_tag(name: "affected", value: "glpi on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-b0f6a5bdbc");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KE5FYMOMQ6AQ7WFOBN2NSJNUVDXPY2WE");
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

if(release == "FC26")
{

  if ((res = isrpmvuln(pkg:"glpi", rpm:"glpi~9.1.7.1~2.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
