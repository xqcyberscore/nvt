###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_7b1517bc6e_tomcat-native_fc27.nasl 9023 2018-03-05 07:08:45Z cfischer $
#
# Fedora Update for tomcat-native FEDORA-2018-7b1517bc6e
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
  script_oid("1.3.6.1.4.1.25623.1.0.874111");
  script_version("$Revision: 9023 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-05 08:08:45 +0100 (Mon, 05 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-02-10 07:57:08 +0100 (Sat, 10 Feb 2018)");
  script_cve_id("CVE-2017-15698");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for tomcat-native FEDORA-2018-7b1517bc6e");
  script_tag(name: "summary", value: "Check the version of tomcat-native");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "Tomcat can use the Apache Portable Runtime 
to provide superior scalability, performance, and better integration with native 
server technologies.  The Apache Portable Runtime is a highly portable library
that is at the heart of Apache HTTP Server 2.x.  APR has many uses, including 
access to advanced IO functionality (such as sendfile, epoll and OpenSSL), OS 
level functionality (random number generation, system status, etc), and native 
process handling (shared memory, NT pipes and Unix sockets).  This package 
contains the Tomcat native library which provides support for using APR in Tomcat.
");
  script_tag(name: "affected", value: "tomcat-native on Fedora 27");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2018-7b1517bc6e");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/J3AMZRPNW5L27APAWB4IW3SRJQR6HL4G");
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

  if ((res = isrpmvuln(pkg:"tomcat-native", rpm:"tomcat-native~1.2.16~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
