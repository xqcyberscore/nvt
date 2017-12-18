###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_41957e0f90_krb5_fc26.nasl 8149 2017-12-15 14:58:09Z cfischer $
#
# Fedora Update for krb5 FEDORA-2017-41957e0f90
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
  script_oid("1.3.6.1.4.1.25623.1.0.873779");
  script_version("$Revision: 8149 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 15:58:09 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-11-23 08:15:27 +0100 (Thu, 23 Nov 2017)");
  script_cve_id("CVE-2017-15088");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for krb5 FEDORA-2017-41957e0f90");
  script_tag(name: "summary", value: "Check the version of krb5");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Kerberos V5 is a trusted-third-party 
network authentication system, which can improve your network&#39 s security by 
eliminating the insecure practice of sending passwords over the network in 
unencrypted form.");
  script_tag(name: "affected", value: "krb5 on Fedora 26");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-41957e0f90");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TVZFC5OOIFWA7Z3W2LHIBMXGCC5WHTH3");
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

if(release == "FC26")
{

  if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.15.2~4.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
