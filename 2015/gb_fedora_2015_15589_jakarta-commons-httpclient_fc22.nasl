###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for jakarta-commons-httpclient FEDORA-2015-15589
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.869974");
  script_version("$Revision: 6630 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:34:32 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2015-10-02 07:09:18 +0200 (Fri, 02 Oct 2015)");
  script_cve_id("CVE-2015-5262");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for jakarta-commons-httpclient FEDORA-2015-15589");
  script_tag(name: "summary", value: "Check the version of jakarta-commons-httpclient");
  script_tag(name: "vuldetect", value: "Get the installed version with the help
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "The Hyper-Text Transfer Protocol (HTTP)
is perhaps the most significant protocol used on the Internet today. Web
services, network-enabled appliances and the growth of network computing
continue to expand the role of the HTTP protocol beyond user-driven web browsers,
and increase the number of applications that may require HTTP support. Although
the java.net package provides basic support for accessing resources via HTTP,
it doesn't provide the full flexibility or functionality needed by many
applications. The Jakarta Commons HTTP Client component seeks to fill this void
by providing an efficient, up-to-date, and feature-rich package implementing
the client side of the most recent HTTP standards and recommendations. Designed
for extension while providing robust support for the base HTTP protocol, the
HTTP Client component may be of interest to anyone building HTTP-aware client
applications such as web browsers, web service clients, or systems that
leverage or extend the HTTP protocol for distributed communication.
");
  script_tag(name: "affected", value: "jakarta-commons-httpclient on Fedora 22");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");
  script_xref(name: "FEDORA", value: "2015-15589");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2015-October/167999.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

if(release == "FC22")
{

  if ((res = isrpmvuln(pkg:"jakarta-commons-httpclient", rpm:"jakarta-commons-httpclient~3.1~23.fc22", rls:"FC22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
