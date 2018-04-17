###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_1b3a73b45f_libofx_fc27.nasl 9499 2018-04-17 03:38:12Z ckuersteiner $
#
# Fedora Update for libofx FEDORA-2018-1b3a73b45f
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
  script_oid("1.3.6.1.4.1.25623.1.0.874360");
  script_version("$Revision: 9499 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-17 05:38:12 +0200 (Tue, 17 Apr 2018) $");
  script_tag(name:"creation_date", value:"2018-04-13 08:06:52 +0200 (Fri, 13 Apr 2018)");
  script_cve_id("CVE-2017-14731", "CVE-2017-2816", "CVE-2017-2920");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for libofx FEDORA-2018-1b3a73b45f");
  script_tag(name: "summary", value: "Check the version of libofx");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "This is the LibOFX library. It is a API 
designed to allow applications to very easily support OFX command responses, 
usually provided by financial institutions.  See 'http://www.ofx.net/ofx/default.asp'
for details and specification.
");
  script_tag(name: "affected", value: "libofx on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-1b3a73b45f");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TFLNASWJ5OH55HY7Q334GN3FP45VNRMW");
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

  if ((res = isrpmvuln(pkg:"libofx", rpm:"libofx~0.9.10~5.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
