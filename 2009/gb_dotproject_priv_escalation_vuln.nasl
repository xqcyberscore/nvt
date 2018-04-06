###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dotproject_priv_escalation_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# dotProject Privilege Escalation Vulnerability.
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

tag_impact = "Attackers can exploit this issue via specially crafted HTTP request to
  certain administrative pages to gain administrative privileges on the
  affected system.
  Impact Level: Application";
tag_affected = "dotProject version prior to 2.1.2";
tag_insight = "The flaw is due to improper restrictions on access to certain
  administrative pages.";
tag_solution = "Upgrade to version 2.1.2
  http://www.dotproject.net";
tag_summary = "The host is installed with dotProject and is prone to Privilege
  Escalation vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800565");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-05-07 14:39:04 +0200 (Thu, 07 May 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-6747");
  script_bugtraq_id(29679);
  script_name("dotProject Privilege Escalation Vulnerability");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/378282.php");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/43019");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_dotproject_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

appPort = get_http_port(default:80);
if(!appPort){
  exit(0);
}

dotVer = get_kb_item("www/" + appPort + "/dotProject");
dotVer = eregmatch(pattern:"^(.+) under (/.*)$", string:dotVer);
if(dotVer[1] == NULL){
  exit(0);
}

if(version_is_less(version:dotVer[1], test_version:"2.1.2")){
  security_message(appPort);
}
