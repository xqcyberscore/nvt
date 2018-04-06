###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for krb5 FEDORA-2013-8219
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_affected = "krb5 on Fedora 17";
tag_insight = "Kerberos V5 is a trusted-third-party network authentication system,
  which can improve your network's security by eliminating the insecure
  practice of sending passwords over the network in unencrypted form.";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.865642");
  script_version("$Revision: 9353 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-05-27 11:51:43 +0530 (Mon, 27 May 2013)");
  script_cve_id("CVE-2002-2443", "CVE-2013-1416", "CVE-2012-1016", "CVE-2013-1415",
                                 "CVE-2012-1014", "CVE-2012-1015", "CVE-2012-1012");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Update for krb5 FEDORA-2013-8219");

  script_xref(name: "FEDORA", value: "2013-8219");
  script_xref(name: "URL" , value: "http://lists.fedoraproject.org/pipermail/package-announce/2013-May/105978.html");
  script_tag(name: "summary" , value: "Check for the Version of krb5");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

if(release == "FC17")
{

  if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.10.2~12.fc17", rls:"FC17")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
