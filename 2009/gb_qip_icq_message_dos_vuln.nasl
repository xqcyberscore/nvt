###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qip_icq_message_dos_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Qip ICQ Message Denial Of Service Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Attackers may exploit this issue to crash the application.
  Impact Level: Application";
tag_affected = "QIP version 2005 build 8082 and prior on Windows";
tag_insight = "Issue generated due to an error in handling Rich Text Format ICQ messages.";
tag_solution = "Upgrade to latest version
  http://qip.ru/ru/pages/download_qip_ru/";
tag_summary = "This host is installed with QIP and is prone to denial of
  service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800541");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-03-18 14:25:01 +0100 (Wed, 18 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-0769");
  script_bugtraq_id(33609);
  script_name("Qip ICQ Message Denial Of Service Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33851");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/500656/100/0/threaded");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_qip_detect.nasl");
  script_require_keys("QIP/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

qipVer = get_kb_item("QIP/Version");
if(!qipVer){
  exit(0);
}

if(version_is_less_equal(version:qipVer, test_version:"8.0.8.2")){
  security_message(0);
}
