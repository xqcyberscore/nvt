###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_944e86b623_yara_fc24.nasl 6873 2017-08-08 12:35:26Z teissa $
#
# Fedora Update for yara FEDORA-2017-944e86b623
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
  script_oid("1.3.6.1.4.1.25623.1.0.872909");
  script_version("$Revision: 6873 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-08 14:35:26 +0200 (Tue, 08 Aug 2017) $");
  script_tag(name:"creation_date", value:"2017-07-25 07:40:01 +0200 (Tue, 25 Jul 2017)");
  script_cve_id("CVE-2017-11328");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for yara FEDORA-2017-944e86b623");
  script_tag(name: "summary", value: "Check the version of yara");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "YARA is a tool aimed at (but not limited to) 
helping malware researchers to identify and classify malware samples. With YARA 
you can create descriptions of malware families (or whatever you want to describe) 
based on textual or binary patterns. Each description, a.k.a rule, consists of 
a set of strings and a Boolean expression which determine its logic.");
  script_tag(name: "affected", value: "yara on Fedora 24");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-944e86b623");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/M6AOVM3TUQVE5NMYDSK5URM4L7LTSZSM");
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

  if ((res = isrpmvuln(pkg:"yara", rpm:"yara~3.6.3~1.fc24", rls:"FC24")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
