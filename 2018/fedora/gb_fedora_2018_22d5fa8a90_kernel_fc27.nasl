###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_22d5fa8a90_kernel_fc27.nasl 8323 2018-01-08 14:50:05Z gveerendra $
#
# Fedora Update for kernel FEDORA-2018-22d5fa8a90
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
  script_oid("1.3.6.1.4.1.25623.1.0.873968");
  script_version("$Revision: 8323 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-08 15:50:05 +0100 (Mon, 08 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-05 23:58:52 +0100 (Fri, 05 Jan 2018)");
  script_cve_id("CVE-2017-17857", "CVE-2017-17856", "CVE-2017-17855", "CVE-2017-17854", 
                "CVE-2017-17853", "CVE-2017-17852", "CVE-2017-17862", "CVE-2017-17863", 
                "CVE-2017-17864");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for kernel FEDORA-2018-22d5fa8a90");
  script_tag(name: "summary", value: "Check the version of kernel");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "The kernel meta package
");
  script_tag(name: "affected", value: "kernel on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-22d5fa8a90");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CFRT6EBC2HJ4XLWLZZ7MATZ2EWPTADAH");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.14.11~300.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
