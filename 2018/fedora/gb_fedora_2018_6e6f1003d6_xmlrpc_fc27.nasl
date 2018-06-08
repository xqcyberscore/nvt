###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2018_6e6f1003d6_xmlrpc_fc27.nasl 10127 2018-06-08 02:54:24Z ckuersteiner $
#
# Fedora Update for xmlrpc FEDORA-2018-6e6f1003d6
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
  script_oid("1.3.6.1.4.1.25623.1.0.874641");
  script_version("$Revision: 10127 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-08 04:54:24 +0200 (Fri, 08 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-03 05:51:32 +0200 (Sun, 03 Jun 2018)");
  script_cve_id("CVE-2016-5003", "CVE-2016-5002");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for xmlrpc FEDORA-2018-6e6f1003d6");
  script_tag(name:"summary", value:"Check the version of xmlrpc");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present 
on the target host.");
  script_tag(name:"insight", value:"Apache XML-RPC is a Java implementation of 
XML-RPC, a popular protocol that uses XML over HTTP to implement remote procedure 
calls. Apache XML-RPC was previously known as Helma XML-RPC. If you have code
using the Helma library, all you should have to do is change the import 
statements in your code from helma.xmlrpc.* to org.apache.xmlrpc.*.
");
  script_tag(name:"affected", value:"xmlrpc on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-6e6f1003d6");
  script_xref(name:"URL" , value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/MB2KL7W5G3BJY65ISPO5YSV4IGBNWSMD");
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

  if ((res = isrpmvuln(pkg:"xmlrpc", rpm:"xmlrpc~3.1.3~20.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
