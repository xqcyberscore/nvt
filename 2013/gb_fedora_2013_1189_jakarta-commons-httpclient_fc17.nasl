###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for jakarta-commons-httpclient FEDORA-2013-1189
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

tag_affected = "jakarta-commons-httpclient on Fedora 17";
tag_insight = "The Hyper-Text Transfer Protocol (HTTP) is perhaps the most significant
  protocol used on the Internet today. Web services, network-enabled
  appliances and the growth of network computing continue to expand the
  role of the HTTP protocol beyond user-driven web browsers, and increase
  the number of applications that may require HTTP support.
  Although the java.net package provides basic support for accessing
  resources via HTTP, it doesn't provide the full flexibility or
  functionality needed by many applications. The Jakarta Commons HTTP
  Client component seeks to fill this void by providing an efficient,
  up-to-date, and feature-rich package implementing the client side of the
  most recent HTTP standards and recommendations.
  Designed for extension while providing robust support for the base HTTP
  protocol, the HTTP Client component may be of interest to anyone
  building HTTP-aware client applications such as web browsers, web
  service clients, or systems that leverage or extend the HTTP protocol
  for distributed communication.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2013-February/097885.html");
  script_id(865280);
  script_version("$Revision: 8542 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-26 07:57:28 +0100 (Fri, 26 Jan 2018) $");
  script_tag(name:"creation_date", value:"2013-02-04 09:50:33 +0530 (Mon, 04 Feb 2013)");
  script_cve_id("CVE-2012-5783");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_xref(name: "FEDORA", value: "2013-1189");
  script_name("Fedora Update for jakarta-commons-httpclient FEDORA-2013-1189");

  script_tag(name: "summary" , value: "Check for the Version of jakarta-commons-httpclient");
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

  if ((res = isrpmvuln(pkg:"jakarta-commons-httpclient", rpm:"jakarta-commons-httpclient~3.1~12.fc17", rls:"FC17")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
